//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Provides a trait-based abstraction for signing operations that can be
//! backed by different key storage mechanisms:
//! - Local keystore (default)
//! - Remote signer
//! - PKCS#11 HSM
//! - Cloud KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS
//!
//! At the moment, only Local and Remote are fully implemented in this file.
//! The PKCS#11 / AWS / Azure / GCP backends are preserved in configuration
//! and return a clear runtime error until a matching SDK integration is added.

use crate::crypto::Signer;
use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Configuration for key management backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyBackendConfig {
    /// Local encrypted keystore (default).
    Local {
        /// Path to keystore file.
        path: String,
        /// Environment variable holding the password.
        password_env: String,
    },

    /// Remote signer HTTP service.
    Remote { url: String, timeout_s: u64 },

    /// PKCS#11 HSM (e.g. YubiHSM, Thales Luna).
    Pkcs11 {
        /// Path to PKCS#11 shared library.
        library_path: String,
        /// Slot ID.
        slot: u64,
        /// Key label in the HSM.
        key_label: String,
        /// PIN environment variable name.
        pin_env: String,
    },

    /// AWS KMS.
    AwsKms {
        /// KMS key ARN or alias.
        key_id: String,
        /// AWS region.
        region: String,
        /// Optional endpoint override.
        #[serde(default)]
        endpoint: Option<String>,
    },

    /// Azure Key Vault.
    AzureKeyVault {
        /// Key Vault URL.
        vault_url: String,
        /// Key name in the vault.
        key_name: String,
        /// Optional key version.
        #[serde(default)]
        key_version: Option<String>,
    },

    /// GCP Cloud KMS.
    GcpKms {
        /// Full resource name.
        resource_name: String,
    },
}

impl Default for KeyBackendConfig {
    fn default() -> Self {
        Self::Local {
            path: "keys.enc".into(),
            password_env: "IONA_KEYSTORE_PASSWORD".into(),
        }
    }
}

/// Trait for signer backends.
pub trait HsmSigner: Send + Sync {
    /// Return the public key bytes.
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError>;

    /// Sign a message.
    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError>;

    /// Backend name used in logs / diagnostics.
    fn backend_name(&self) -> &str;

    /// Check whether the signer is healthy / reachable.
    fn health_check(&self) -> Result<(), CryptoError>;
}

/// Local keystore signer.
pub struct LocalSigner {
    inner: crate::crypto::ed25519::Ed25519Keypair,
}

impl LocalSigner {
    pub fn new(keypair: crate::crypto::ed25519::Ed25519Keypair) -> Self {
        Self { inner: keypair }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: crate::crypto::ed25519::Ed25519Keypair::from_seed(*seed),
        }
    }

    /// Generate a new random keypair and persist it to the encrypted keystore.
    fn generate_and_save(path: &str, password: &str) -> Result<Self, CryptoError> {
        use crate::crypto::ed25519::Ed25519Keypair;
        use crate::crypto::keystore::encrypt_seed32_to_file;

        let keypair = Ed25519Keypair::random();
        let seed = keypair.to_seed();

        encrypt_seed32_to_file(std::path::Path::new(path), seed, password)
            .map_err(|e| CryptoError::Key(format!("failed to save keystore: {e}")))?;

        Ok(Self::new(keypair))
    }
}

impl HsmSigner for LocalSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.inner.public_key())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Ok(self.inner.sign(msg))
    }

    fn backend_name(&self) -> &str {
        "local"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Adapter over the existing remote signer implementation.
pub struct RemoteSignerAdapter {
    inner: crate::crypto::remote_signer::RemoteSigner,
}

impl RemoteSignerAdapter {
    pub fn new(signer: crate::crypto::remote_signer::RemoteSigner) -> Self {
        Self { inner: signer }
    }
}

impl HsmSigner for RemoteSignerAdapter {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.inner.public_key())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Ok(self.inner.sign(msg))
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        if self.inner.is_healthy() {
            Ok(())
        } else {
            Err(CryptoError::Key("remote signer unhealthy".into()))
        }
    }
}

fn disabled_backend(name: &str) -> Result<Box<dyn HsmSigner>, CryptoError> {
    Err(CryptoError::Key(format!(
        "{name} support temporarily disabled for this build"
    )))
}

/// Create a signer from backend configuration.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    match config {
        KeyBackendConfig::Local { path, password_env } => {
            let password = std::env::var(password_env).unwrap_or_default();
            let path_ref = std::path::Path::new(path);

            if !password.is_empty() && path_ref.exists() {
                match crate::crypto::keystore::decrypt_seed32_from_file(path_ref, &password) {
                    Ok(seed) => {
                        let signer = LocalSigner::from_seed(&seed);
                        info!(backend = "local", "using existing keystore");
                        Ok(Box::new(signer))
                    }
                    Err(e) => {
                        error!(error = %e, "failed to decrypt keystore");
                        Err(CryptoError::Key(format!("keystore decrypt failed: {e}")))
                    }
                }
            } else if path_ref.exists() {
                Err(CryptoError::Key(
                    "keystore exists but no password provided".into(),
                ))
            } else {
                info!(path, "keystore not found, generating new key");
                let signer = LocalSigner::generate_and_save(path, &password)?;
                Ok(Box::new(signer))
            }
        }

        KeyBackendConfig::Remote { url, timeout_s } => {
            use crate::crypto::remote_signer::RemoteSigner;

            let remote =
                RemoteSigner::connect(url.clone(), std::time::Duration::from_secs(*timeout_s))
                    .map_err(|e| CryptoError::Key(format!("remote signer connect: {e}")))?;

            let adapter = RemoteSignerAdapter::new(remote);
            info!(url, "using remote signer");
            Ok(Box::new(adapter))
        }

        KeyBackendConfig::Pkcs11 { .. } => disabled_backend("PKCS#11 HSM"),
        KeyBackendConfig::AwsKms { .. } => disabled_backend("AWS KMS"),
        KeyBackendConfig::AzureKeyVault { .. } => disabled_backend("Azure Key Vault"),
        KeyBackendConfig::GcpKms { .. } => disabled_backend("GCP Cloud KMS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_local_signer() {
        let seed = [42u8; 32];
        let signer = LocalSigner::from_seed(&seed);

        assert_eq!(signer.backend_name(), "local");
        assert!(signer.health_check().is_ok());

        let pk = signer.public_key().unwrap();
        assert!(!pk.0.is_empty());

        let sig = signer.sign(b"test message").unwrap();
        assert!(!sig.0.is_empty());
    }

    #[test]
    fn test_local_signer_deterministic() {
        let seed = [42u8; 32];
        let s1 = LocalSigner::from_seed(&seed);
        let s2 = LocalSigner::from_seed(&seed);

        let sig1 = s1.sign(b"hello").unwrap();
        let sig2 = s2.sign(b"hello").unwrap();

        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_config_default() {
        let config = KeyBackendConfig::default();

        match config {
            KeyBackendConfig::Local { path, password_env } => {
                assert_eq!(path, "keys.enc");
                assert_eq!(password_env, "IONA_KEYSTORE_PASSWORD");
            }
            _ => panic!("default should be Local"),
        }
    }

    #[test]
    fn test_config_serialization() {
        let configs = vec![
            KeyBackendConfig::Local {
                path: "keys.enc".into(),
                password_env: "PW".into(),
            },
            KeyBackendConfig::Remote {
                url: "http://127.0.0.1:8080".into(),
                timeout_s: 5,
            },
            KeyBackendConfig::Pkcs11 {
                library_path: "/usr/lib/pkcs11.so".into(),
                slot: 0,
                key_label: "validator".into(),
                pin_env: "PIN".into(),
            },
            KeyBackendConfig::AwsKms {
                key_id: "arn:aws:kms:us-east-1:123:key/abc".into(),
                region: "us-east-1".into(),
                endpoint: None,
            },
            KeyBackendConfig::AzureKeyVault {
                vault_url: "https://vault.vault.azure.net/".into(),
                key_name: "validator-key".into(),
                key_version: None,
            },
            KeyBackendConfig::GcpKms {
                resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
                    .into(),
            },
        ];

        for cfg in &configs {
            let json = serde_json::to_string(cfg).unwrap();
            let roundtrip: KeyBackendConfig = serde_json::from_str(&json).unwrap();

            match (cfg, roundtrip) {
                (KeyBackendConfig::Local { .. }, KeyBackendConfig::Local { .. }) => {}
                (KeyBackendConfig::Remote { .. }, KeyBackendConfig::Remote { .. }) => {}
                (KeyBackendConfig::Pkcs11 { .. }, KeyBackendConfig::Pkcs11 { .. }) => {}
                (KeyBackendConfig::AwsKms { .. }, KeyBackendConfig::AwsKms { .. }) => {}
                (
                    KeyBackendConfig::AzureKeyVault { .. },
                    KeyBackendConfig::AzureKeyVault { .. },
                ) => {}
                (KeyBackendConfig::GcpKms { .. }, KeyBackendConfig::GcpKms { .. }) => {}
                _ => panic!("roundtrip mismatch"),
            }
        }
    }

    #[test]
    fn test_local_signer_generate_new() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.enc");
        let path_str = path.to_str().unwrap().to_string();

        std::env::set_var("TEST_PW", "testpass");

        let config = KeyBackendConfig::Local {
            path: path_str.clone(),
            password_env: "TEST_PW".into(),
        };

        let signer = create_signer(&config).unwrap();
        assert_eq!(signer.backend_name(), "local");
        assert!(std::path::Path::new(&path_str).exists());

        let signer2 = create_signer(&config).unwrap();
        let pk1 = signer.public_key().unwrap();
        let pk2 = signer2.public_key().unwrap();
        assert_eq!(pk1.0, pk2.0);

        std::env::remove_var("TEST_PW");
    }

    #[test]
    fn test_unimplemented_backends_return_error() {
        let pkcs11 = KeyBackendConfig::Pkcs11 {
            library_path: "dummy".into(),
            slot: 0,
            key_label: "k".into(),
            pin_env: "PIN".into(),
        };
        assert!(create_signer(&pkcs11).is_err());

        let aws = KeyBackendConfig::AwsKms {
            key_id: "key".into(),
            region: "us-east-1".into(),
            endpoint: None,
        };
        assert!(create_signer(&aws).is_err());

        let azure = KeyBackendConfig::AzureKeyVault {
            vault_url: "https://example.vault.azure.net".into(),
            key_name: "key".into(),
            key_version: None,
        };
        assert!(create_signer(&azure).is_err());

        let gcp = KeyBackendConfig::GcpKms {
            resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
                .into(),
        };
        assert!(create_signer(&gcp).is_err());
    }
}
