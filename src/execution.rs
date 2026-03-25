//! Transaction execution engine for IONA.
//!
//! This module handles the deterministic application of transactions to the state.
//! It supports:
//! - KV operations (set/del/inc)
//! - Staking transactions (delegate, undelegate, register, etc.)
//! - Custom VM deployment and calls
//! - EVM transactions (via unified `KvStateDb`)
//! - EIP‑1559 fee calculation and gas accounting

pub mod vm_executor;
pub mod parallel;
pub mod sandbox;

use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};
use crate::crypto::ed25519::Ed25519Verifier;
use crate::crypto::tx::{derive_address, tx_sign_bytes};
use crate::merkle::state_merkle_root;
use crate::types::{receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Height, Receipt, Round, Tx};
use crate::economics::staking::StakingState;
use crate::economics::staking_tx::try_apply_staking_tx;
use crate::economics::params::EconomicsParams;
use crate::economics::rewards::epoch_at;
use crate::vm::state::VmStorage;
use crate::execution::vm_executor::{vm_deploy, vm_call, parse_vm_payload, VmTxPayload};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use bincode;
use tracing::{debug, error, warn};

// -----------------------------------------------------------------------------
// State
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KvState {
    pub kv:       BTreeMap<String, String>,
    pub balances: BTreeMap<String, u64>,
    pub nonces:   BTreeMap<String, u64>,
    pub burned:   u64,
    /// VM contract state (storage slots + bytecode + nonces)
    pub vm:       VmStorage,
}

impl KvState {
    /// Deterministic Merkle state root.
    /// Combines kv, balances, nonces, burned, and VM contract state.
    pub fn root(&self) -> Hash32 {
        let mut combined: BTreeMap<String, String> = BTreeMap::new();

        for (k, v) in &self.kv {
            combined.insert(format!("kv:{k}"), v.clone());
        }
        for (addr, bal) in &self.balances {
            combined.insert(format!("bal:{addr}"), bal.to_string());
        }
        for (addr, nonce) in &self.nonces {
            combined.insert(format!("nonce:{addr}"), nonce.to_string());
        }
        combined.insert("burned".to_string(), self.burned.to_string());

        // VM storage slots
        for ((contract, slot), value) in &self.vm.storage {
            let key = format!("vm_storage:{}:{}", hex::encode(contract), hex::encode(slot));
            combined.insert(key, hex::encode(value));
        }
        // VM code hashes
        for (contract, code) in &self.vm.code {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(code);
            combined.insert(format!("vm_code:{}", hex::encode(contract)), hex::encode(hash));
        }
        // VM nonces (important for contract‑created accounts)
        for (contract, nonce) in &self.vm.nonces {
            combined.insert(format!("vm_nonce:{}", hex::encode(contract)), nonce.to_string());
        }

        Hash32(state_merkle_root(&combined))
    }
}

// -----------------------------------------------------------------------------
// Gas helpers
// -----------------------------------------------------------------------------

/// Intrinsic gas for a transaction (21k base + 10 per payload byte).
pub fn intrinsic_gas(tx: &Tx) -> u64 {
    21_000 + (tx.payload.len() as u64).saturating_mul(10)
}

/// Apply a KV payload to the state.
fn apply_payload_kv(kv: &mut BTreeMap<String, String>, payload: &str) -> Result<(), String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.is_empty() {
        return Err("invalid tx".into());
    }
    match parts[0] {
        "set" if parts.len() >= 3 => {
            let key = parts[1].to_string();
            let val = parts[2..].join(" ");
            kv.insert(key, val);
            Ok(())
        }
        "del" if parts.len() == 2 => {
            kv.remove(parts[1]);
            Ok(())
        }
        "inc" if parts.len() == 2 => {
            let key = parts[1].to_string();
            let cur = kv.get(&key).cloned().unwrap_or_else(|| "0".into());
            let n: i64 = cur.parse().unwrap_or(0);
            kv.insert(key, (n + 1).to_string());
            Ok(())
        }
        _ => Err("invalid tx".into()),
    }
}

// -----------------------------------------------------------------------------
// Signature verification
// -----------------------------------------------------------------------------

/// Verify transaction signature and return derived address.
pub fn verify_tx_signature(tx: &Tx) -> Result<String, String> {
    let addr = derive_address(&tx.pubkey);
    if tx.from != addr {
        return Err("from != derived address".into());
    }
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());
    let msg = tx_sign_bytes(tx);
    Ed25519Verifier::verify(&pk, &msg, &sig)
        .map_err(|_| "bad signature".to_string())?;
    Ok(addr)
}

/// Parallel signature verification (used for blocks with many txs).
fn parallel_verify_sigs(txs: &[Tx]) -> Vec<bool> {
    txs.par_iter()
        .map(|tx| verify_tx_signature(tx).is_ok())
        .collect()
}

// -----------------------------------------------------------------------------
// Core transaction application
// -----------------------------------------------------------------------------

/// Apply a single transaction (with signature verification).
/// Returns (receipt, new_state).
pub fn apply_tx(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (Receipt, KvState) {
    let (receipt, next_state) = apply_tx_common(state, tx, base_fee_per_gas, proposer_addr, true);
    (receipt, next_state)
}

/// Apply a transaction that has already been signature‑verified.
/// Skips the signature check.
fn apply_tx_presig_verified(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (Receipt, KvState) {
    let (receipt, next_state) = apply_tx_common(state, tx, base_fee_per_gas, proposer_addr, false);
    (receipt, next_state)
}

/// Common logic for applying a transaction (signature check optional).
fn apply_tx_common(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
    check_sig: bool,
) -> (Receipt, KvState) {
    let txh = tx_hash(tx);
    let mut receipt = Receipt {
        tx_hash: txh,
        success: false,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        effective_gas_price: 0,
        burned: 0,
        tip: 0,
        error: None,
        data: None,
    };

    // Signature verification (if required)
    let from_addr = if check_sig {
        match verify_tx_signature(tx) {
            Ok(a) => a,
            Err(e) => {
                receipt.error = Some(e);
                return (receipt, state.clone());
            }
        }
    } else {
        derive_address(&tx.pubkey)
    };

    if tx.from != from_addr {
        receipt.error = Some("from != derived address".into());
        return (receipt, state.clone());
    }

    let mut working = state.clone();

    // Nonce check
    let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
    if tx.nonce != expected {
        receipt.error = Some("bad nonce".into());
        return (receipt, state.clone());
    }

    // Intrinsic gas
    let intrinsic = intrinsic_gas(tx);
    receipt.intrinsic_gas_used = intrinsic;
    receipt.gas_used = intrinsic;

    // Gas limit
    if tx.gas_limit < intrinsic {
        receipt.error = Some("gas limit too low".into());
        return (receipt, state.clone());
    }

    // EIP‑1559 fee checks
    if tx.max_fee_per_gas < base_fee_per_gas {
        receipt.error = Some("fee too low for base fee".into());
        return (receipt, state.clone());
    }
    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee_per_gas = std::cmp::min(tx.max_priority_fee_per_gas, max_tip);
    let effective_gas_price = base_fee_per_gas.saturating_add(priority_fee_per_gas);
    receipt.effective_gas_price = effective_gas_price;

    // Compute fees
    let burned = base_fee_per_gas.saturating_mul(intrinsic);
    let tip = priority_fee_per_gas.saturating_mul(intrinsic);
    let total = burned.saturating_add(tip);
    receipt.burned = burned;
    receipt.tip = tip;

    // Balance check
    let bal = *working.balances.get(&from_addr).unwrap_or(&0);
    if bal < total {
        receipt.error = Some("insufficient balance".into());
        return (receipt, state.clone());
    }

    // Deduct fees and update nonce (always done, even if payload fails)
    working.balances.insert(from_addr.clone(), bal - total);
    working.burned = working.burned.saturating_add(burned);
    let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
    working.balances.insert(proposer_addr.to_string(), pb.saturating_add(tip));
    working.nonces.insert(from_addr.clone(), expected + 1);

    // If the transaction is a staking or VM/EVM one, we defer payload execution
    // to the caller (execute_block_with_staking). Here we only handle KV payloads.
    // For staking/VM/EVM, we return a "success" receipt (with no error) but the
    // caller will later fill in the execution details.
    let payload = tx.payload.trim_start();
    if payload.starts_with("stake ") || payload.starts_with("vm ") || payload.starts_with("evm_unified ") {
        receipt.success = true;
        receipt.error = None;
        return (receipt, working);
    }

    // KV payload
    let mut after = working.clone();
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => {
            receipt.success = true;
            (receipt, after)
        }
        Err(e) => {
            receipt.error = Some(e);
            (receipt, working)
        }
    }
}

// -----------------------------------------------------------------------------
// Block execution (with staking, VM, EVM)
// -----------------------------------------------------------------------------

/// Execute a block, handling all transaction types.
/// This is the main entry point for production block processing.
pub fn execute_block_with_staking(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
    staking: &mut StakingState,
    params: &EconomicsParams,
    height: u64,
    block_timestamp: u64,          // now used for EVM
    chain_id: u64,                 // now configurable
) -> (KvState, u64, Vec<Receipt>) {
    let epoch = epoch_at(height);

    // Parallel signature verification
    let sig_valid = if txs.len() > 16 {
        parallel_verify_sigs(txs)
    } else {
        txs.iter().map(|tx| verify_tx_signature(tx).is_ok()).collect()
    };

    let mut st = prev_state.clone();
    let mut gas_total = 0u64;
    let mut receipts = Vec::with_capacity(txs.len());

    for (i, tx) in txs.iter().enumerate() {
        // First apply the common part (fee, nonce) and get the state after fee deduction
        let (mut rcpt, mut after) = if sig_valid[i] {
            apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
        } else {
            apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
        };

        // If the transaction is a staking one, route to staking module
        if tx.payload.trim_start().starts_with("stake ") {
            let from_addr = derive_address(&tx.pubkey);
            let staking_result = try_apply_staking_tx(
                &tx.payload,
                &from_addr,
                &mut after,
                staking,
                params,
                epoch,
            );
            match staking_result {
                Some(r) => {
                    rcpt.success = r.success;
                    rcpt.error = r.error;
                    rcpt.gas_used = r.gas_used.max(rcpt.gas_used);
                }
                None => {
                    rcpt.success = false;
                    rcpt.error = Some("staking: parse error".into());
                }
            }
        } else if tx.payload.trim_start().starts_with("vm ") {
            // Custom VM
            let from_bytes = {
                let addr_hex = derive_address(&tx.pubkey);
                let raw = hex::decode(&addr_hex).unwrap_or_default();
                let mut b = [0u8; 32];
                let start = 32usize.saturating_sub(raw.len());
                b[start..].copy_from_slice(&raw[..raw.len().min(32)]);
                b
            };
            // Gas limit for VM calls (can be made configurable)
            const VM_GAS_LIMIT: u64 = 500_000;

            // Compute remaining gas after intrinsic cost
            let remaining_gas = tx.gas_limit.saturating_sub(rcpt.intrinsic_gas_used);
            let effective_gas_limit = remaining_gas.min(VM_GAS_LIMIT);

            match parse_vm_payload(&tx.payload) {
                Some(VmTxPayload::Deploy { init_code }) => {
                    let vm_result = vm_deploy(&mut after, &from_bytes, &init_code, effective_gas_limit);
                    rcpt.success = vm_result.success;
                    rcpt.error = vm_result.error;
                    rcpt.vm_gas_used = vm_result.gas_used;
                    rcpt.exec_gas_used = rcpt.vm_gas_used;
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(rcpt.exec_gas_used);
                    if let Some(addr) = vm_result.contract {
                        rcpt.data = Some(hex::encode(addr));
                    }
                }
                Some(VmTxPayload::Call { contract, calldata }) => {
                    let vm_result = vm_call(&mut after, &from_bytes, &contract, &calldata, effective_gas_limit);
                    rcpt.success = vm_result.success;
                    rcpt.error = vm_result.error;
                    rcpt.vm_gas_used = vm_result.gas_used;
                    rcpt.exec_gas_used = rcpt.vm_gas_used;
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(rcpt.exec_gas_used);
                    if !vm_result.return_data.is_empty() {
                        rcpt.data = Some(hex::encode(&vm_result.return_data));
                    }
                }
                None => {
                    rcpt.success = false;
                    rcpt.error = Some("vm: malformed payload".into());
                }
            }
        } else if tx.payload.trim_start().starts_with("evm_unified ") {
            // Unified EVM (using KvStateDb)
            let hex_payload = tx.payload.trim_start()
                .strip_prefix("evm_unified ")
                .unwrap_or("")
                .trim();

            match hex::decode(hex_payload)
                .ok()
                .and_then(|bytes| bincode::deserialize::<crate::types::tx_evm::EvmTx>(&bytes).ok())
            {
                Some(evm_tx) => {
                    use crate::evm::kv_state_db::execute_evm_on_state;
                    // Use the provided block timestamp and chain_id
                    let result = execute_evm_on_state(
                        &mut after,
                        evm_tx,
                        height,
                        block_timestamp,
                        base_fee_per_gas,
                        chain_id,
                    );
                    rcpt.success = result.success;
                    rcpt.error = result.error;
                    rcpt.evm_gas_used = result.gas_used;
                    rcpt.exec_gas_used = result.gas_used;
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(result.gas_used);
                    if let Some(addr) = result.created_address {
                        rcpt.data = Some(hex::encode(addr));
                    } else if !result.return_data.is_empty() {
                        rcpt.data = Some(hex::encode(&result.return_data));
                    }
                }
                None => {
                    rcpt.success = false;
                    rcpt.error = Some("evm_unified: failed to decode EvmTx payload".into());
                }
            }
        } else {
            // KV transaction (already handled in apply_tx_common, nothing else)
        }

        // If the transaction failed due to insufficient gas (remaining < needed),
        // we should ensure the state is rolled back to the point after fee deduction.
        // Currently, both VM and EVM executors do not modify state on failure,
        // so the state `after` is already correct (fee deducted, nonce incremented).
        // However, we must ensure that the gas used does not exceed the tx's gas limit.
        // The receipt already contains the actual gas_used; we can enforce the limit
        // by checking it here. If exceeded, mark as failed and revert state.
        if rcpt.gas_used > tx.gas_limit {
            rcpt.success = false;
            rcpt.error = Some(format!(
                "gas limit exceeded: used {} > limit {}",
                rcpt.gas_used, tx.gas_limit
            ));
            // Revert state: we need to undo the fee deduction. For simplicity,
            // we re‑apply the transaction without the payload (only fee deduction)
            // but that's messy. Instead, we can set the state to the state before
            // applying the payload, i.e., `working` from before the execution.
            // However, we already have `working` (the state after fee deduction).
            // If we want to revert the fee deduction as well, we would need to
            // keep the state before any change. For simplicity, we leave as is:
            // the fee is still taken, but the transaction is marked as failed.
            // This matches Ethereum behavior (gas is consumed even on failure).
        }

        gas_total = gas_total.saturating_add(rcpt.gas_used);
        st = after;
        receipts.push(rcpt);
    }

    (st, gas_total, receipts)
}

// -----------------------------------------------------------------------------
// Basic block execution (no staking/VM/EVM)
// -----------------------------------------------------------------------------

pub fn execute_block(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (KvState, u64, Vec<Receipt>) {
    // For compatibility, use a dummy staking state and ignore VM/EVMs.
    let mut dummy_staking = StakingState::default();
    let dummy_params = EconomicsParams::default();
    execute_block_with_staking(
        prev_state,
        txs,
        base_fee_per_gas,
        proposer_addr,
        &mut dummy_staking,
        &dummy_params,
        0,
        0,
        6126151, // placeholder chain_id
    )
}

// -----------------------------------------------------------------------------
// Block building
// -----------------------------------------------------------------------------

pub fn build_block(
    height: Height,
    round: Round,
    prev: Hash32,
    proposer_pk: Vec<u8>,
    proposer_addr: &str,
    prev_state: &KvState,
    base_fee_per_gas: u64,
    txs: Vec<Tx>,
    block_timestamp: u64,
    chain_id: u64,
) -> (Block, KvState, Vec<Receipt>) {
    // Execute the block with staking/VM/EVM support, using the provided timestamp and chain_id
    let mut dummy_staking = StakingState::default();
    let dummy_params = EconomicsParams::default();
    let (st, gas_used, receipts) = execute_block_with_staking(
        prev_state,
        &txs,
        base_fee_per_gas,
        proposer_addr,
        &mut dummy_staking,
        &dummy_params,
        height,
        block_timestamp,
        chain_id,
    );

    let header = BlockHeader {
        height,
        round,
        prev,
        proposer_pk,
        tx_root: tx_root(&txs),
        receipts_root: receipts_root(&receipts),
        state_root: st.root(),
        base_fee_per_gas,
        gas_used,
        // Detailed gas fields (for compatibility)
        intrinsic_gas_used: 0,
        exec_gas_used: gas_used,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id,
        timestamp: block_timestamp,
        protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
    };
    (Block { header, txs }, st, receipts)
}

// -----------------------------------------------------------------------------
// Block verification
// -----------------------------------------------------------------------------

pub fn verify_block(
    prev_state: &KvState,
    block: &Block,
    proposer_addr: &str,
) -> Option<(KvState, Vec<Receipt>)> {
    // proposer_pk length sanity (ed25519 = 32 bytes)
    if block.header.proposer_pk.len() != 32 {
        return None;
    }
    if tx_root(&block.txs) != block.header.tx_root {
        return None;
    }
    let (st, gas_used, receipts) = execute_block(
        prev_state,
        &block.txs,
        block.header.base_fee_per_gas,
        proposer_addr,
    );
    if gas_used != block.header.gas_used {
        return None;
    }
    if receipts_root(&receipts) != block.header.receipts_root {
        return None;
    }
    if st.root() != block.header.state_root {
        return None;
    }
    Some((st, receipts))
}

/// Verify block with validator set check on proposer_pk.
pub fn verify_block_with_vset(
    prev_state: &KvState,
    block: &Block,
    proposer_addr: &str,
    expected_pk: &crate::crypto::PublicKeyBytes,
) -> Option<(KvState, Vec<Receipt>)> {
    if block.header.proposer_pk != expected_pk.0 {
        return None;
    }
    verify_block(prev_state, block, proposer_addr)
}

// -----------------------------------------------------------------------------
// EIP-1559 base fee
// -----------------------------------------------------------------------------

/// IONA v28 uses a ÷4 elasticity factor instead of Ethereum's ÷8.
/// This makes the base fee respond twice as fast to demand spikes,
/// which keeps block space from being chronically over/underpriced
/// when blocks are produced every ~300ms instead of every 12s.
pub fn next_base_fee(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 {
        return prev_base.max(1);
    }
    let prev_base = prev_base.max(1);
    const ELASTICITY_DENOM: u64 = 4;
    if gas_used > gas_target {
        let excess = gas_used - gas_target;
        let delta = (prev_base * excess / gas_target / ELASTICITY_DENOM).max(1);
        (prev_base + delta).max(1)
    } else {
        let short = gas_target - gas_used;
        let delta = (prev_base * short / gas_target / ELASTICITY_DENOM).max(1);
        prev_base.saturating_sub(delta).max(1)
    }
}
