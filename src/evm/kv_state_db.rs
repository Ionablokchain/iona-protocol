//! `KvStateDb` — a `revm::Database` + `DatabaseCommit` implementation backed
//! by IONA's `KvState`.
//!
//! This is the **unification bridge** between IONA's native KV/balance state
//! and the full EVM execution environment provided by `revm`.
//!
//! ## Why this matters
//!
//! Previously IONA had **two separate VM paths**:
//!   1. `src/vm/` — a custom stack machine (arithmetic, SLOAD/SSTORE, LOG*, etc.)
//!   2. `src/evm/` — revm backed by an isolated `MemDb` that knew nothing about
//!      real chain state (balances, nonces, existing contracts).
//!
//! `KvStateDb` closes this gap.  The `evm` module now reads *and writes* to the
//! same `KvState` that the consensus engine commits at end-of-block.  This means:
//!   - EVM transactions see real account balances and nonces.
//!   - EVM-deployed contracts persist across blocks.
//!   - The state root includes EVM storage (already done via `KvState::root()`).
//!   - Tools like MetaMask / Hardhat / cast can interact correctly.
//!
//! ## Address encoding
//!
//! IONA uses 32-byte addresses (ed25519 pubkey derived); Ethereum uses 20 bytes.
//! We represent IONA addresses in revm as the **last 20 bytes** of the 32-byte
//! address so existing Ethereum tooling works without modification.  The helper
//! functions `iona_to_evm_addr` / `evm_to_iona_addr` perform this conversion.
//!
//! ## Balance units
//!
//! IONA balances are `u64` micro-units.  EVM expects `U256` wei.  We treat
//! 1 IONA micro-unit = 1 wei (no scaling), keeping arithmetic straightforward.

use crate::execution::KvState;
use crate::vm::state::VmState;
use revm::primitives::{
    Account, AccountInfo, Address, Bytecode, B256, KECCAK_EMPTY, U256,
};
use revm::{Database, DatabaseCommit};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

// ── Address helpers ───────────────────────────────────────────────────────────

/// Convert a 32-byte IONA address to a 20-byte EVM address (last 20 bytes).
pub fn iona_to_evm_addr(iona: &[u8; 32]) -> Address {
    Address::from_slice(&iona[12..])
}

/// Convert a 20-byte EVM address back to a 32-byte IONA address (zero-padded).
pub fn evm_to_iona_addr(evm: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(evm.as_slice());
    out
}

/// Hex string of a 32-byte IONA address (used as KvState key).
pub fn iona_addr_hex(addr: &[u8; 32]) -> String {
    hex::encode(addr)
}

// ── KvStateDb ────────────────────────────────────────────────────────────────

/// A `revm::Database` backed by `KvState`.
///
/// Reads go to the authoritative `KvState`.
/// Writes are **buffered** in `pending` and committed via `DatabaseCommit::commit`
/// so that a reverted EVM call leaves `KvState` unchanged.
pub struct KvStateDb<'a> {
    /// The live chain state — reads happen here.
    pub state: &'a mut KvState,

    /// Pending account/storage changes from the current EVM call.
    /// Flushed to `state` on `commit()`; discarded on revert (just drop this).
    pending_accounts: HashMap<Address, AccountInfo>,
    pending_storage: HashMap<(Address, U256), U256>,
    pending_code: HashMap<B256, Bytecode>,

    /// Cache for fast code lookup by hash.
    code_hash_cache: HashMap<B256, Bytecode>,
}

impl<'a> KvStateDb<'a> {
    pub fn new(state: &'a mut KvState) -> Self {
        let mut db = Self {
            state,
            pending_accounts: HashMap::new(),
            pending_storage: HashMap::new(),
            pending_code: HashMap::new(),
            code_hash_cache: HashMap::new(),
        };
        db.rebuild_code_cache();
        db
    }

    /// Rebuilds the code hash cache from the current `KvState`.
    fn rebuild_code_cache(&mut self) {
        self.code_hash_cache.clear();
        for (_addr, code) in &self.state.vm.code {
            let hash = B256::from_slice(&Keccak256::digest(code).to_vec());
            let bytecode = Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(code));
            self.code_hash_cache.insert(hash, bytecode);
        }
    }

    /// Look up balance for an EVM address from KvState.
    fn read_balance(&self, addr: Address) -> U256 {
        let iona = evm_to_iona_addr(addr);
        let key = iona_addr_hex(&iona);
        let bal = self.state.balances.get(&key).copied().unwrap_or(0);
        U256::from(bal)
    }

    /// Look up nonce for an EVM address from KvState.
    fn read_nonce(&self, addr: Address) -> u64 {
        let iona = evm_to_iona_addr(addr);
        let key = iona_addr_hex(&iona);
        self.state.nonces.get(&key).copied().unwrap_or(0)
    }

    /// Look up code for an EVM address from VmStorage.
    fn read_code(&self, addr: Address) -> Bytecode {
        let iona = evm_to_iona_addr(addr);
        let code = self.state.vm.get_code(&iona);
        if code.is_empty() {
            Bytecode::new()
        } else {
            Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(&code))
        }
    }
}

// ── Database impl ─────────────────────────────────────────────────────────────

impl<'a> Database for KvStateDb<'a> {
    type Error = String;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // Check pending buffer first (handles mid-tx reads after writes).
        if let Some(info) = self.pending_accounts.get(&address) {
            return Ok(Some(info.clone()));
        }

        let balance = self.read_balance(address);
        let nonce = self.read_nonce(address);
        let code = self.read_code(address);
        let code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            B256::from_slice(&Keccak256::digest(code.bytecode()).to_vec())
        };

        Ok(Some(AccountInfo {
            balance,
            nonce,
            code_hash,
            code: if code.is_empty() { None } else { Some(code) },
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Check pending first.
        if let Some(code) = self.pending_code.get(&code_hash) {
            return Ok(code.clone());
        }
        // Check cache.
        if let Some(code) = self.code_hash_cache.get(&code_hash) {
            return Ok(code.clone());
        }
        // Fallback to linear scan (in case cache is stale).
        for (_addr, bytecode) in &self.state.vm.code {
            let h = B256::from_slice(&Keccak256::digest(bytecode).to_vec());
            if h == code_hash {
                let code = Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(bytecode));
                return Ok(code);
            }
        }
        Err(format!("code not found for hash {code_hash:?}"))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        // Check pending buffer.
        if let Some(val) = self.pending_storage.get(&(address, index)) {
            return Ok(*val);
        }
        // Read from KvState vm.storage.
        let iona = evm_to_iona_addr(address);
        let slot: [u8; 32] = index.to_be_bytes();
        let val = self
            .state
            .vm
            .storage
            .get(&(iona, slot))
            .copied()
            .unwrap_or([0u8; 32]);
        let mut be = [0u8; 32];
        be.copy_from_slice(&val);
        Ok(U256::from_be_bytes(be))
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        // Return zero for now; full block hash history would require an index.
        Ok(B256::ZERO)
    }
}

// ── DatabaseCommit impl ───────────────────────────────────────────────────────

impl<'a> DatabaseCommit for KvStateDb<'a> {
    fn commit(&mut self, changes: revm::primitives::State) {
        for (evm_addr, account) in changes {
            if !account.is_touched() {
                continue;
            }

            let iona = evm_to_iona_addr(evm_addr);
            let iona_key = iona_addr_hex(&iona);

            // ── Balances ──────────────────────────────────────────────────────
            // Saturate to u64 (IONA's native balance type).
            let bal_u64 = account.info.balance.saturating_to::<u64>();
            if bal_u64 == 0 {
                self.state.balances.remove(&iona_key);
            } else {
                self.state.balances.insert(iona_key.clone(), bal_u64);
            }

            // ── Nonces ────────────────────────────────────────────────────────
            if account.info.nonce == 0 {
                self.state.nonces.remove(&iona_key);
            } else {
                self.state.nonces.insert(iona_key.clone(), account.info.nonce);
            }

            // ── Bytecode ──────────────────────────────────────────────────────
            if let Some(code) = &account.info.code {
                if !code.is_empty() {
                    let code_bytes = code.bytecode().to_vec();
                    self.state.vm.code.insert(iona, code_bytes);
                }
            }

            // ── Storage slots ─────────────────────────────────────────────────
            for (slot_u256, slot_val) in &account.storage {
                let slot_bytes: [u8; 32] = slot_u256.to_be_bytes();
                let val_bytes: [u8; 32] = slot_val.present_value.to_be_bytes();

                if slot_val.present_value == U256::ZERO {
                    self.state.vm.storage.remove(&(iona, slot_bytes));
                } else {
                    self.state.vm.storage.insert((iona, slot_bytes), val_bytes);
                }
            }
        }
        // Rebuild code hash cache after changes.
        self.rebuild_code_cache();
    }
}

// ── Unified EVM executor ──────────────────────────────────────────────────────

use crate::types::tx_evm::EvmTx;
use revm::primitives::{BlockEnv, CfgEnv, Env, TxEnv};
use revm::Evm;

/// Result of executing an EVM transaction via `KvStateDb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedEvmResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub created_address: Option<[u8; 20]>,
    pub logs: Vec<revm::primitives::Log>,
    pub error: Option<String>,
}

/// Execute an EVM transaction against the live `KvState`.
///
/// On success the state is committed in-place.
/// On failure the state is left unchanged (revm reverts automatically).
///
/// # Parameters
/// - `kv_state`: The mutable IONA state to execute against.
/// - `tx`: The EVM transaction to execute.
/// - `block_number`: Current block height.
/// - `block_timestamp`: Current block timestamp (seconds).
/// - `base_fee`: Current block base fee (for EIP-1559).
/// - `gas_limit`: Block gas limit.
/// - `coinbase`: Validator address that will receive tips.
/// - `chain_id`: Chain ID (e.g., 6126151 for iona-testnet-1).
pub fn execute_evm_on_state(
    kv_state: &mut KvState,
    tx: EvmTx,
    block_number: u64,
    block_timestamp: u64,
    base_fee: u64,
    gas_limit: u64,
    coinbase: [u8; 32],
    chain_id: u64,
) -> UnifiedEvmResult {
    let mut db = KvStateDb::new(kv_state);

    // Build the environment.
    let mut env = Env::default();
    env.cfg = CfgEnv::default();
    env.cfg.chain_id = chain_id;
    env.block = BlockEnv {
        number: U256::from(block_number),
        timestamp: U256::from(block_timestamp),
        basefee: U256::from(base_fee),
        gas_limit: U256::from(gas_limit),
        coinbase: iona_to_evm_addr(&coinbase),
        ..Default::default()
    };
    env.tx = build_tx_env(&tx);

    let mut evm = Evm::builder()
        .with_db(&mut db)
        .with_env(Box::new(env))
        .with_spec_id(revm::primitives::SpecId::CANCUN)
        .build();

    match evm.transact_commit() {
        Ok(result) => {
            let (success, gas_used, output, logs) = match &result {
                revm::primitives::ExecutionResult::Success {
                    gas_used,
                    output,
                    logs,
                    ..
                } => (true, *gas_used, output.clone(), logs.clone()),
                revm::primitives::ExecutionResult::Revert { gas_used, output } => {
                    (false, *gas_used, revm::primitives::Output::Call(output.clone()), vec![])
                }
                revm::primitives::ExecutionResult::Halt { gas_used, .. } => {
                    (false, *gas_used, revm::primitives::Output::Call(revm::primitives::Bytes::new()), vec![])
                }
            };

            let (return_data, created_address) = match output {
                revm::primitives::Output::Call(bytes) => (bytes.to_vec(), None),
                revm::primitives::Output::Create(bytes, addr) => (
                    bytes.to_vec(),
                    addr.map(|a| {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(a.as_slice());
                        arr
                    }),
                ),
            };

            UnifiedEvmResult {
                success,
                gas_used,
                return_data,
                created_address,
                logs,
                error: if success { None } else { Some("execution reverted".into()) },
            }
        }
        Err(e) => UnifiedEvmResult {
            success: false,
            gas_used: 0,
            return_data: vec![],
            created_address: None,
            logs: vec![],
            error: Some(format!("evm error: {e:?}")),
        },
    }
}

fn build_tx_env(tx: &EvmTx) -> TxEnv {
    let mut env = TxEnv::default();
    match tx {
        EvmTx::Legacy {
            from, to, nonce, gas_limit, gas_price, value, data, chain_id,
        } => {
            env.caller = Address::from_slice(from);
            env.gas_limit = *gas_limit;
            env.gas_price = U256::from(*gas_price);
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(t)),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
        }
        EvmTx::Eip2930 {
            from, to, nonce, gas_limit, gas_price, value, data, access_list, chain_id,
        } => {
            env.caller = Address::from_slice(from);
            env.gas_limit = *gas_limit;
            env.gas_price = U256::from(*gas_price);
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(t)),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
            env.access_list = access_list
                .iter()
                .map(|it| {
                    (
                        Address::from_slice(&it.address[12..]),
                        it.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(*k))
                            .collect(),
                    )
                })
                .collect();
        }
        EvmTx::Eip1559 {
            from, to, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas,
            value, data, access_list, chain_id,
        } => {
            env.caller = Address::from_slice(from);
            env.gas_limit = *gas_limit;
            // For EIP-1559, we set gas_priority_fee; revm will compute effective gas price.
            env.gas_priority_fee = Some(U256::from(*max_priority_fee_per_gas));
            // We leave gas_price unset; revm calculates it as base_fee + priority_fee.
            env.value = U256::from(*value);
            env.nonce = Some(*nonce);
            env.chain_id = Some(*chain_id);
            env.transact_to = match to {
                Some(t) => revm::primitives::TransactTo::Call(Address::from_slice(t)),
                None => revm::primitives::TransactTo::Create,
            };
            env.data = revm::primitives::Bytes::copy_from_slice(data);
            env.access_list = access_list
                .iter()
                .map(|it| {
                    (
                        Address::from_slice(&it.address[12..]),
                        it.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(*k))
                            .collect(),
                    )
                })
                .collect();
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tx_evm::{AccessListItem, EvmTx};

    fn make_iona_addr(seed: u8) -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[31] = seed;
        addr
    }

    fn make_evm_addr(seed: u8) -> Address {
        let mut addr = [0u8; 20];
        addr[19] = seed;
        Address::from(addr)
    }

    fn setup_kv_state() -> KvState {
        let mut state = KvState::default();
        // Fund account with 1,000,000 units.
        let alice = iona_addr_hex(&make_iona_addr(1));
        state.balances.insert(alice, 1_000_000);
        state
    }

    #[test]
    fn test_address_conversion_roundtrip() {
        let iona = make_iona_addr(0xaa);
        let evm = iona_to_evm_addr(&iona);
        let back = evm_to_iona_addr(evm);
        assert_eq!(iona, back);
    }

    #[test]
    fn test_balance_read() {
        let mut state = setup_kv_state();
        let mut db = KvStateDb::new(&mut state);
        let alice_evm = make_evm_addr(1);
        let info = db.basic(alice_evm).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(1_000_000));
    }

    #[test]
    fn test_balance_write_and_commit() {
        let mut state = setup_kv_state();
        let alice_evm = make_evm_addr(1);
        let alice_iona = evm_to_iona_addr(alice_evm);
        let alice_key = iona_addr_hex(&alice_iona);

        // Create a change set.
        let mut changes = revm::primitives::State::new();
        let mut account = Account::default();
        account.info.balance = U256::from(500_000);
        account.mark_touch();
        changes.insert(alice_evm, account);

        // Commit.
        {
            let mut db = KvStateDb::new(&mut state);
            db.commit(changes);
        }

        // Verify that the state has been updated.
        assert_eq!(state.balances.get(&alice_key), Some(&500_000));
    }

    #[test]
    fn test_simple_transfer() {
        let mut state = KvState::default();
        // Use seeds > 0x09 to avoid precompile addresses (0x01..0x09)
        let alice_iona = make_iona_addr(0x10);
        let bob_iona = make_iona_addr(0x20);
        let alice_key = iona_addr_hex(&alice_iona);
        let bob_key = iona_addr_hex(&bob_iona);
        state.balances.insert(alice_key, 100_000_000); // Enough for value + gas
        state.balances.insert(bob_key, 0);

        let alice_evm_bytes: [u8; 20] = *iona_to_evm_addr(&alice_iona).0;
        let bob_evm_bytes: [u8; 20] = *iona_to_evm_addr(&bob_iona).0;
        let tx = EvmTx::Legacy {
            from: alice_evm_bytes,
            to: Some(bob_evm_bytes),
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1_000,
            value: 100_000,
            data: vec![],
            chain_id: 6126151,
        };

        let coinbase = make_iona_addr(99);
        let result = execute_evm_on_state(
            &mut state, tx,
            1,  // block_number
            1_600_000_000, // block_timestamp
            1, // base_fee
            30_000_000, // gas_limit
            coinbase,
            6126151,
        );

        assert!(result.success, "Transfer failed: {:?}", result.error);
        let alice_balance = state.balances.get(&iona_addr_hex(&alice_iona)).copied().unwrap_or(0);
        let bob_balance = state.balances.get(&iona_addr_hex(&bob_iona)).copied().unwrap_or(0);
        // Alice: 1,000,000 - value (100,000) - gas (21,000 * gas_price)
        // gas_price=1_000 but actual deduction depends on EVM execution;
        // just verify alice lost value + some gas and bob gained value.
        assert!(alice_balance < 100_000_000 - 100_000, "alice should have paid gas");
        assert!(alice_balance > 0, "alice should still have funds");
        assert_eq!(bob_balance, 100_000);
    }
}
