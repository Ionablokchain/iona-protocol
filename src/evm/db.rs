//! In-memory REVM database for testing and development.
//!
//! This module provides a minimal implementation of `revm::Database` that stores
//! accounts, code, and storage in memory. It is suitable for unit tests, benchmarks,
//! and development environments.
//!
//! For production, you should implement `Database` on top of the persistent chain
//! state (e.g., `KvState` or a RocksDB-backed store).

use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};
use revm::{Database, DatabaseCommit};
use std::collections::HashMap;

/// An in-memory database for REVM.
///
/// Stores account information, contract code, and storage slots.
/// All data is kept in memory and is lost when the instance is dropped.
#[derive(Default, Debug, Clone)]
pub struct MemDb {
    /// Account metadata (balance, nonce, code_hash).
    pub accounts: HashMap<Address, AccountInfo>,
    /// Contract bytecode keyed by code hash.
    pub code: HashMap<B256, Bytecode>,
    /// Storage slots: (address, slot) -> value.
    pub storage: HashMap<(Address, U256), U256>,
}

impl MemDb {
    /// Creates a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads an account into the database from Iona's `KvState`.
    /// This is a convenience method for initializing the EVM environment.
    pub fn load_account_from_iona(&mut self, addr: Address, balance: u64, nonce: u64, code: Option<Bytecode>) {
        let code_hash = code.as_ref().map(|c| c.hash_slow()).unwrap_or(revm::primitives::KECCAK_EMPTY);
        let account_info = AccountInfo {
            balance: U256::from(balance),
            nonce: nonce,
            code_hash,
            code: code.clone(),
        };
        self.accounts.insert(addr, account_info);
        if let Some(code) = code {
            self.code.insert(code.hash_slow(), code);
        }
    }

    /// Sets a storage slot for an account.
    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.storage.insert((address, slot), value);
    }

    /// Gets the value of a storage slot.
    pub fn get_storage(&self, address: Address, slot: U256) -> U256 {
        *self.storage.get(&(address, slot)).unwrap_or(&U256::ZERO)
    }
}

impl Database for MemDb {
    type Error = String;

    /// Returns the account information for the given address.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    /// Returns the bytecode associated with a code hash.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| format!("code not found for hash: {code_hash:?}"))
    }

    /// Returns the value of a storage slot.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.get_storage(address, index))
    }

    /// Returns the block hash for a given block number.
    /// In a real implementation, this would query the chain.
    /// For testing, we return a zero hash.
    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseCommit for MemDb {
    /// Commits state changes produced by a transaction.
    fn commit(&mut self, changes: revm::primitives::State) {
        for (address, account) in changes {
            // Update account info
            self.accounts.insert(address, account.info.clone());

            // Update storage
            for (slot, storage_slot) in account.storage {
                if storage_slot.present_value != U256::ZERO {
                    self.storage.insert((address, slot), storage_slot.present_value);
                } else {
                    self.storage.remove(&(address, slot));
                }
            }

            // Update code if changed
            if let Some(code) = account.info.code {
                self.code.insert(code.hash_slow(), code);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut db = MemDb::new();
        let addr = Address::from([0xaa; 20]);

        // Initially account doesn't exist
        assert!(db.basic(addr).unwrap().is_none());

        // Load an account
        let balance = 1000;
        let nonce = 5;
        db.load_account_from_iona(addr, balance, nonce, None);

        let info = db.basic(addr).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(balance));
        assert_eq!(info.nonce, nonce);
    }

    #[test]
    fn test_storage() {
        let mut db = MemDb::new();
        let addr = Address::from([0xbb; 20]);
        let slot = U256::from(42);
        let value = U256::from(123);

        db.set_storage(addr, slot, value);
        assert_eq!(db.get_storage(addr, slot), value);
    }

    #[test]
    fn test_commit() {
        let mut db = MemDb::new();
        let addr = Address::from([0xcc; 20]);

        // Create a change set (simulate transaction output)
        use revm::primitives::{Account, AccountInfo, StorageSlot};

        let mut changes = revm::primitives::State::new();
        let mut account = Account::default();
        account.info = AccountInfo {
            balance: U256::from(500),
            nonce: 1,
            code_hash: B256::ZERO,
            code: None,
        };
        account.storage.insert(U256::from(1), StorageSlot::new(U256::from(999)));
        changes.insert(addr, account);

        db.commit(changes);
        assert_eq!(db.get_storage(addr, U256::from(1)), U256::from(999));
        assert_eq!(db.basic(addr).unwrap().unwrap().balance, U256::from(500));
    }
}
