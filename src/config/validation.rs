//! STEP 3 — Strict config + genesis validation at boot.
//!
//! Node MUST NOT start if any of these fail:
//! - Bootnodes invalid (malformed multiaddr, missing peer ID)
//! - Chain ID mismatch (config vs genesis)
//! - Stake config invalid (zero, negative, or exceeding maximum)
//! - simple_producer conflict (follower/RPC running as producer)
//! - Genesis mismatch (hash differs from expected)
//! - Genesis hash check at boot
//! - Duplicate validator seeds in genesis
//! - Empty validator set
//! - Invalid listen address/port
//!
//! All failures are **fatal** — not warnings.

use std::collections::BTreeSet;
use std::path::Path;

/// Maximum allowed stake per validator (1 billion units).
const MAX_STAKE: u64 = 1_000_000_000;

/// A fatal validation error that prevents node startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FATAL config error [{}]: {}", self.field, self.message)
    }
}

/// Result of config validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            write!(f, "Config validation: PASS")
        } else {
            writeln!(f, "Config validation: FAIL ({} errors)", self.errors.len())?;
            for e in &self.errors {
                writeln!(f, "  {e}")?;
            }
            Ok(())
        }
    }
}

/// Validate a bootnode multiaddr string.
/// Valid formats: /ip4/X.X.X.X/tcp/PORT/p2p/PEERID or /dns4/HOST/tcp/PORT/p2p/PEERID
/// The peer ID is mandatory for bootnodes.
fn validate_bootnode(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty bootnode address".into());
    }

    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() < 7 {
        // Minimum: /ip4/1.2.3.4/tcp/7001/p2p/PEERID (7 părți)
        return Err(format!("malformed multiaddr (too few parts, missing peer ID?): {addr}"));
    }

    // First part should be empty (leading /).
    if !parts[0].is_empty() {
        return Err(format!("multiaddr must start with /: {addr}"));
    }

    // Check protocol prefix.
    match parts[1] {
        "ip4" => {
            // Validate IP.
            let ip = parts[2];
            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Err(format!("invalid IPv4 address: {ip}"));
            }
            for octet in &octets {
                if octet.parse::<u8>().is_err() {
                    return Err(format!("invalid IPv4 octet: {octet}"));
                }
            }
        }
        "dns4" | "dns6" => {
            // DNS hostname — just check it's not empty.
            if parts[2].is_empty() {
                return Err("empty DNS hostname".into());
            }
        }
        "ip6" => { /* Accept IPv6, we don't validate further */ }
        other => {
            return Err(format!("unsupported multiaddr protocol: {other}"));
        }
    }

    // Check for /tcp/PORT.
    if parts.len() >= 5 && parts[3] == "tcp" {
        if parts[4].parse::<u16>().is_err() {
            return Err(format!("invalid TCP port: {}", parts[4]));
        }
    } else {
        return Err(format!("missing /tcp/ portion: {addr}"));
    }

    // Check for /p2p/ and peer ID.
    if parts.len() >= 7 && parts[5] == "p2p" {
        if parts[6].is_empty() {
            return Err("empty peer ID".into());
        }
        // Optionally validate peer ID format (e.g., base58-check, length) here.
    } else {
        return Err(format!("bootnode missing /p2p/ peer ID: {addr}"));
    }

    Ok(())
}

/// Validate the full node configuration. Returns fatal errors.
///
/// This is called at boot: `config.validate() -> fatal if errors`.
pub fn validate_config(
    chain_id_config: u64,
    chain_id_genesis: Option<u64>,
    bootnodes: &[String],
    stake_each: u64,
    simple_producer: bool,
    rpc_enabled: bool,                     // new parameter
    node_seed: u64,
    genesis_validator_seeds: &[u64],
    listen_addr: &str,
) -> ValidationResult {
    let mut errors = Vec::new();

    // 1. Validate bootnodes.
    for (i, bn) in bootnodes.iter().enumerate() {
        if let Err(e) = validate_bootnode(bn) {
            errors.push(ValidationError {
                field: format!("network.bootnodes[{i}]"),
                message: e,
            });
        }
    }

    // 2. Check for self-bootstrap (node's own address in bootnodes).
    // Simple heuristic: check if any bootnode contains the listen port and a known local address.
    let listen_port = listen_addr.rsplit(':').next().unwrap_or("")
        .chars().filter(|c| c.is_ascii_digit()).collect::<String>();
    let self_indicators = ["127.0.0.1", "0.0.0.0", "localhost"];
    for bn in bootnodes {
        if !listen_port.is_empty() {
            for indicator in &self_indicators {
                if bn.contains(indicator) && bn.contains(&listen_port) {
                    errors.push(ValidationError {
                        field: "network.bootnodes".into(),
                        message: format!("node appears to bootstrap from itself: {bn} (contains local address {indicator} and port {listen_port})"),
                    });
                    break;
                }
            }
        }
    }

    // 3. Chain ID mismatch.
    if let Some(genesis_chain_id) = chain_id_genesis {
        if chain_id_config != genesis_chain_id {
            errors.push(ValidationError {
                field: "node.chain_id".into(),
                message: format!(
                    "config chain_id={chain_id_config} does not match genesis chain_id={genesis_chain_id}"
                ),
            });
        }
    }

    // 4. Stake config invalid.
    if stake_each == 0 {
        errors.push(ValidationError {
            field: "consensus.stake_each".into(),
            message: "stake_each must be > 0".into(),
        });
    }
    if stake_each > MAX_STAKE {
        errors.push(ValidationError {
            field: "consensus.stake_each".into(),
            message: format!("stake_each={stake_each} exceeds maximum allowed ({MAX_STAKE})"),
        });
    }

    // 5. Genesis validator set must not be empty.
    if genesis_validator_seeds.is_empty() {
        errors.push(ValidationError {
            field: "genesis.validators".into(),
            message: "genesis must have at least one validator".into(),
        });
    }

    // 6. Duplicate validator seeds in genesis.
    let unique_seeds: BTreeSet<&u64> = genesis_validator_seeds.iter().collect();
    if unique_seeds.len() < genesis_validator_seeds.len() {
        errors.push(ValidationError {
            field: "genesis.validators".into(),
            message: "duplicate validator seeds detected".into(),
        });
    }

    // 7. simple_producer conflict with validator set and RPC.
    if simple_producer {
        // Producer must be a validator.
        if !genesis_validator_seeds.contains(&node_seed) {
            errors.push(ValidationError {
                field: "consensus.simple_producer".into(),
                message: format!(
                    "simple_producer=true but node seed={node_seed} is not in validator set {:?}",
                    genesis_validator_seeds
                ),
            });
        }
        // Producer cannot have RPC enabled (follower/RPC conflict).
        if rpc_enabled {
            errors.push(ValidationError {
                field: "consensus.simple_producer".into(),
                message: "simple_producer=true and rpc_enabled=true are mutually exclusive".into(),
            });
        }
    } else {
        // If not producer, we could still allow RPC; no conflict.
    }

    // 8. Duplicate bootnode check.
    let unique_bootnodes: BTreeSet<&str> = bootnodes.iter().map(|s| s.as_str()).collect();
    if unique_bootnodes.len() < bootnodes.len() {
        errors.push(ValidationError {
            field: "network.bootnodes".into(),
            message: "duplicate bootnode entries detected".into(),
        });
    }

    // 9. Listen address validation.
    if listen_addr.is_empty() {
        errors.push(ValidationError {
            field: "rpc.listen".into(),
            message: "listen address cannot be empty".into(),
        });
    } else {
        // Validate port number.
        if let Some(port_str) = listen_addr.split(':').last() {
            if port_str.parse::<u16>().is_err() {
                errors.push(ValidationError {
                    field: "rpc.listen".into(),
                    message: format!("invalid port number in listen address: {port_str}"),
                });
            }
        } else {
            errors.push(ValidationError {
                field: "rpc.listen".into(),
                message: format!("listen address missing port: {listen_addr}"),
            });
        }
    }

    ValidationResult { errors }
}

/// Compute a genesis hash for integrity checking.
/// Uses SHA-256 of the canonical JSON representation (normalized to avoid formatting differences).
pub fn genesis_hash(genesis_json: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    // Normalize JSON to ensure deterministic hashing regardless of whitespace.
    let parsed: serde_json::Value = serde_json::from_str(genesis_json)
        .expect("genesis JSON must be valid");
    let canonical = serde_json::to_string(&parsed)
        .expect("canonical serialization failed");

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verify genesis file integrity.
/// Compares the hash of the genesis file against an expected hash.
pub fn verify_genesis_integrity(
    genesis_path: impl AsRef<Path>,
    expected_hash: Option<&[u8; 32]>,
) -> Result<[u8; 32], String> {
    let content = std::fs::read_to_string(genesis_path.as_ref())
        .map_err(|e| format!("cannot read genesis: {e}"))?;

    let hash = genesis_hash(&content);

    if let Some(expected) = expected_hash {
        if hash != *expected {
            return Err(format!(
                "genesis hash mismatch: expected 0x{}, got 0x{}",
                hex::encode(expected),
                hex::encode(hash),
            ));
        }
    }

    Ok(hash)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bootnode_valid() {
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW").is_ok());
        assert!(validate_bootnode("/ip4/192.168.1.1/tcp/30333/p2p/12D3KooW").is_ok());
        assert!(validate_bootnode("/dns4/node.example.com/tcp/7001/p2p/12D3KooW").is_ok());
    }

    #[test]
    fn test_validate_bootnode_invalid() {
        assert!(validate_bootnode("").is_err());
        assert!(validate_bootnode("not-a-multiaddr").is_err());
        assert!(validate_bootnode("/ip4/999.999.999.999/tcp/7001/p2p/id").is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/99999/p2p/id").is_err());
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001").is_err()); // missing /p2p/
        assert!(validate_bootnode("/ip4/1.2.3.4/tcp/7001/p2p/").is_err()); // empty peer ID
        assert!(validate_bootnode("/dns4//tcp/7001/p2p/id").is_err()); // empty hostname
    }

    #[test]
    fn test_config_valid() {
        let result = validate_config(
            6126151,
            Some(6126151),
            &["/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW".into()],
            1000,
            true,   // producer
            false,  // rpc_enabled = false (producer)
            2,      // Seed 2 is in validator set.
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(result.is_ok(), "{result}");
    }

    #[test]
    fn test_chain_id_mismatch() {
        let result = validate_config(
            6126151,
            Some(9999), // Different!
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field == "node.chain_id"));
    }

    #[test]
    fn test_invalid_bootnode() {
        let result = validate_config(
            6126151,
            None,
            &["not-valid".into()],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("bootnodes")));
    }

    #[test]
    fn test_zero_stake() {
        let result = validate_config(
            6126151,
            None,
            &[],
            0, // Invalid!
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("stake_each")));
    }

    #[test]
    fn test_stake_exceeds_max() {
        let result = validate_config(
            6126151,
            None,
            &[],
            MAX_STAKE + 1,
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("exceeds maximum")));
    }

    #[test]
    fn test_simple_producer_conflict_not_validator() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,    // Producer enabled...
            false,
            1,       // ...but seed 1 is NOT a validator.
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("simple_producer")));
    }

    #[test]
    fn test_simple_producer_conflict_rpc_enabled() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            true,   // Producer enabled
            true,   // RPC also enabled -> conflict
            2,
            &[2, 3, 4],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("mutually exclusive")));
    }

    #[test]
    fn test_duplicate_bootnodes() {
        let result = validate_config(
            6126151,
            None,
            &[
                "/ip4/1.2.3.4/tcp/7001/p2p/id".into(),
                "/ip4/1.2.3.4/tcp/7001/p2p/id".into(), // Duplicate!
            ],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn test_empty_listen_addr() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            "", // Empty!
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.field.contains("listen")));
    }

    #[test]
    fn test_invalid_listen_port() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 3],
            "0.0.0.0:99999", // Invalid port
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("invalid port")));
    }

    #[test]
    fn test_empty_validator_set() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[], // Empty validator set!
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("at least one validator")));
    }

    #[test]
    fn test_duplicate_validator_seeds() {
        let result = validate_config(
            6126151,
            None,
            &[],
            1000,
            false,
            false,
            1,
            &[1, 2, 2, 3], // Duplicate seed 2
            "0.0.0.0:9001",
        );
        assert!(!result.is_ok());
        assert!(result.errors.iter().any(|e| e.message.contains("duplicate validator seeds")));
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let json1 = r#"{"chain_id":6126151,"validators":[{"seed":2}]}"#;
        let json2 = r#"
        {
            "chain_id": 6126151,
            "validators": [{"seed": 2}]
        }
        "#;
        let h1 = genesis_hash(json1);
        let h2 = genesis_hash(json2);
        assert_eq!(h1, h2, "Hashes should be equal despite different formatting");
    }

    #[test]
    fn test_genesis_hash_different() {
        let json1 = r#"{"chain_id":6126151}"#;
        let json2 = r#"{"chain_id":9999}"#;
        assert_ne!(genesis_hash(json1), genesis_hash(json2));
    }

    #[test]
    fn test_verify_genesis_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");
        let content = r#"{"chain_id":6126151,"validators":[]}"#;
        std::fs::write(&path, content).unwrap();

        // Without expected hash — just compute.
        let hash = verify_genesis_integrity(&path, None).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // With correct expected hash.
        let result = verify_genesis_integrity(&path, Some(&hash));
        assert!(result.is_ok());

        // With wrong expected hash.
        let bad = [0xFFu8; 32];
        let result = verify_genesis_integrity(&path, Some(&bad));
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_result_display() {
        let result = ValidationResult {
            errors: vec![
                ValidationError { field: "test".into(), message: "bad".into() },
            ],
        };
        let s = format!("{result}");
        assert!(s.contains("FAIL"));
        assert!(s.contains("1 errors"));
    }

    #[test]
    fn test_validation_result_ok_display() {
        let result = ValidationResult { errors: vec![] };
        let s = format!("{result}");
        assert!(s.contains("PASS"));
    }

    #[test]
    fn test_validation_into_result() {
        let ok = ValidationResult { errors: vec![] };
        assert!(ok.into_result().is_ok());

        let fail = ValidationResult {
            errors: vec![ValidationError { field: "x".into(), message: "y".into() }],
        };
        assert!(fail.into_result().is_err());
    }
}
