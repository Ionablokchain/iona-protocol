//! Keystore for managing cryptographic keys.
//!
//! Supports:
//! - Plaintext keystore (keys.json)
//! - Encrypted keystore (keys.enc) using AES-256-GCM
//! - Password derivation via Argon2id
//! - Atomic writes with temporary files

use crate::crypto::ed25519::Ed25519Signer;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Key type stored in the keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum KeyEntry {
    /// Ed25519 key pair, stored as seed (32 bytes).
    Ed25519(#[serde(with = "serde_bytes")] Vec<u8>),
    // Future: other key types (e.g., secp256k1) can be added here.
}

impl KeyEntry {
    /// Create an Ed25519 key entry from a signer.
    pub fn from_ed25519(signer: &Ed25519Signer) -> Self {
        KeyEntry::Ed25519(signer.to_seed().to_vec())
    }

    /// Convert into an Ed25519 signer (if applicable).
    pub fn into_ed25519(self) -> Option<Ed25519Signer> {
        match self {
            KeyEntry::Ed25519(seed) => {
                let mut seed_arr = [0u8; 32];
                seed_arr.copy_from_slice(&seed);
                Some(Ed25519Signer::from_seed(seed_arr))
            }
        }
    }
}

/// The keystore structure that is serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreContent {
    version: u32,
    keys: Vec<KeyEntry>,
}

const KEYSTORE_VERSION: u32 = 1;

/// A keystore that can be persisted to disk, with optional encryption.
pub struct Keystore {
    path: PathBuf,
    encrypted: bool,
    keys: Vec<KeyEntry>,
}

impl Keystore {
    /// Open or create a keystore at the given path.
    ///
    /// If `encrypted` is true, the keystore will be encrypted on disk.
    /// You must provide a password (via `set_password` or environment) when reading/writing.
    pub fn new(path: impl AsRef<Path>, encrypted: bool) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            encrypted,
            keys: Vec::new(),
        }
    }

    /// Load the keystore from disk, using the provided password if encrypted.
    pub fn load(&mut self, password: Option<&str>) -> Result<(), String> {
        if !self.path.exists() {
            // No file yet – start empty.
            self.keys = Vec::new();
            return Ok(());
        }

        let data = fs::read(&self.path).map_err(|e| format!("failed to read keystore: {e}"))?;

        let content: KeystoreContent = if self.encrypted {
            let password = password.ok_or("password required for encrypted keystore")?;
            let decrypted = Self::decrypt(&data, password)?;
            serde_json::from_slice(&decrypted)
                .map_err(|e| format!("failed to parse keystore JSON: {e}"))?
        } else {
            serde_json::from_slice(&data)
                .map_err(|e| format!("failed to parse keystore JSON: {e}"))?
        };

        if content.version != KEYSTORE_VERSION {
            return Err(format!(
                "unsupported keystore version: {} (expected {})",
                content.version, KEYSTORE_VERSION
            ));
        }
        self.keys = content.keys;
        Ok(())
    }

    /// Save the keystore to disk atomically.
    pub fn save(&self, password: Option<&str>) -> Result<(), String> {
        let content = KeystoreContent {
            version: KEYSTORE_VERSION,
            keys: self.keys.clone(),
        };
        let json = serde_json::to_string_pretty(&content)
            .map_err(|e| format!("failed to serialize keystore: {e}"))?;

        let data = if self.encrypted {
            let password = password.ok_or("password required for encrypted keystore")?;
            Self::encrypt(json.as_bytes(), password)?
        } else {
            json.into_bytes()
        };

        // Atomic write: write to a temporary file, then rename.
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, &data).map_err(|e| format!("failed to write temporary file: {e}"))?;
        fs::rename(&tmp_path, &self.path).map_err(|e| format!("failed to rename keystore: {e}"))?;
        Ok(())
    }

    /// Add a key entry.
    pub fn add_key(&mut self, entry: KeyEntry) {
        self.keys.push(entry);
    }

    /// Remove a key entry by index.
    pub fn remove_key(&mut self, index: usize) -> Option<KeyEntry> {
        if index < self.keys.len() {
            Some(self.keys.remove(index))
        } else {
            None
        }
    }

    /// Get all key entries.
    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys
    }

    /// Return the first Ed25519 signer found (if any).
    pub fn first_ed25519(&self) -> Option<Ed25519Signer> {
        for key in &self.keys {
            let KeyEntry::Ed25519(seed) = key;
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(seed);
            return Some(Ed25519Signer::from_seed(seed_arr));
        }
        None
    }

    // -------------------------------------------------------------------------
    // Encryption helpers (AES-256-GCM with Argon2id key derivation)
    // -------------------------------------------------------------------------

    /// Derive a 32‑byte key from a password using Argon2id.
    fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        let argon2 = Argon2::default();
        let salt_str = SaltString::encode_b64(salt).expect("32-byte salt fits in SaltString");
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .expect("password hashing failed");
        let binding = hash.hash.expect("argon2 hash output present");
        let hash_bytes = binding.as_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        key
    }

    /// Encrypt data with a password. Returns (salt + nonce + ciphertext).
    fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, String> {
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
        let key = Self::derive_key(password, &salt);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("failed to create cipher: {e}"))?;
        let nonce_bytes: [u8; 12] = OsRng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("encryption failed: {e}"))?;
        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt data with a password. Input format: salt (16) + nonce (12) + ciphertext.
    fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
        if data.len() < 16 + 12 {
            return Err("invalid encrypted keystore format".into());
        }
        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];
        let key = Self::derive_key(password, salt);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("failed to create cipher: {e}"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("decryption failed (wrong password?): {e}"))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use tempfile::tempdir;

    #[test]
    fn test_keystore_plain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut ks = Keystore::new(&path, false);
        let signer = Ed25519Signer::random();
        ks.add_key(KeyEntry::from_ed25519(&signer));
        ks.save(None).unwrap();

        let mut ks2 = Keystore::new(&path, false);
        ks2.load(None).unwrap();
        assert_eq!(ks2.keys().len(), 1);
        let loaded_signer = ks2.first_ed25519().unwrap();
        assert_eq!(loaded_signer.public_key().0, signer.public_key().0);
    }

    #[test]
    fn test_keystore_encrypted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.enc");
        let mut ks = Keystore::new(&path, true);
        let signer = Ed25519Signer::random();
        ks.add_key(KeyEntry::from_ed25519(&signer));
        let password = "testpassword";
        ks.save(Some(password)).unwrap();

        let mut ks2 = Keystore::new(&path, true);
        ks2.load(Some(password)).unwrap();
        assert_eq!(ks2.keys().len(), 1);
        let loaded_signer = ks2.first_ed25519().unwrap();
        assert_eq!(loaded_signer.public_key().0, signer.public_key().0);

        // Wrong password should fail
        let mut ks3 = Keystore::new(&path, true);
        assert!(ks3.load(Some("wrong")).is_err());
    }
}

pub fn decrypt_seed32_from_file(
    path: &std::path::Path,
    password: &str,
) -> std::io::Result<[u8; 32]> {
    let data = std::fs::read(path)?;
    // Simple XOR-based encryption for demo purposes
    let key_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(password.as_bytes())
    };
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = data.get(i).copied().unwrap_or(0) ^ key_hash[i];
    }
    Ok(seed)
}

pub fn encrypt_seed32_to_file(
    path: &std::path::Path,
    seed: [u8; 32],
    password: &str,
) -> std::io::Result<()> {
    let key_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(password.as_bytes())
    };
    let mut encrypted = [0u8; 32];
    for i in 0..32 {
        encrypted[i] = seed[i] ^ key_hash[i];
    }
    std::fs::write(path, &encrypted)
}
