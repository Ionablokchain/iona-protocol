//! EVM execution integration for IONA.
//!
//! This module provides the glue between Iona transaction types (`EvmTx`)
//! and the REVM execution engine.

use crate::types::tx_evm::EvmTx;
use revm::primitives::{
    Address, BlockEnv, Bytes, CfgEnv, Env, ExecutionResult, SpecId, TxEnv, U256,
};
use revm::{Database, DatabaseCommit, Evm};

/// Output of an EVM transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmExecOutput {
    /// Logs emitted during execution.
    pub logs: Vec<revm::primitives::Log>,
    /// Address of the newly created contract (if any).
    pub created_address: Option<revm::primitives::Address>,
    /// Gas used by the transaction.
    pub gas_used: u64,
    /// Whether the execution succeeded (not reverted or halted).
    pub success: bool,
    /// Return data (or revert reason) as bytes.
    pub return_data: Vec<u8>,
}

/// Converts an Iona 20‑byte address to a REVM `Address`.
fn to_addr(a: [u8; 20]) -> Address {
    Address::from(a)
}

/// Builds a REVM `Env` from the current block context and chain configuration.
///
/// - `block_header` – Iona block header (provides height, timestamp, base fee, chain ID).
/// - `spec_id` – The EVM specification to use (e.g., `SpecId::LATEST`).
pub fn build_evm_env(
    block_height: u64,
    block_timestamp: u64,
    block_base_fee: Option<u64>,
    chain_id: u64,
    spec_id: SpecId,
) -> Env {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    
    let mut block = BlockEnv::default();
    block.number = U256::from(block_height);
    block.timestamp = U256::from(block_timestamp);
    if let Some(base_fee) = block_base_fee {
        block.basefee = U256::from(base_fee);
    }

    Env {
        cfg,
        block,
        tx: TxEnv::default(),
    }
}

/// Executes an EVM transaction against the given database.
///
/// # Parameters
/// - `db` – The database (must implement `Database` and `DatabaseCommit`).
/// - `block_env` – The block environment (height, timestamp, base fee, etc.).
/// - `tx` – The Iona EVM transaction.
///
/// # Returns
/// `Result<EvmExecOutput, String>` with the execution result or an error.
pub fn execute_evm_tx<DB: Database + DatabaseCommit>(
    db: &mut DB,
    block_env: Env,
    tx: EvmTx,
) -> Result<EvmExecOutput, String>
where
    <DB as revm::Database>::Error: core::fmt::Debug,
{
    // Start with the given block environment (includes block and chain config).
    // REVM v9 uses `Evm::builder()` which takes ownership of the environment.
    let mut evm = Evm::builder()
        .with_db(db)
        .with_env(Box::new(block_env))
        .build();

    // Build the transaction environment based on the transaction type.
    { let tx_env = &mut evm.context.evm.inner.env.tx;
        match tx {
            EvmTx::Eip2930 {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                access_list,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.gas_price = U256::from(gas_price);
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
                tx_env.access_list = access_list
                    .into_iter()
                    .map(|item| {
                        let address = to_addr(item.address);
                        let slots = item.storage_keys
                            .into_iter()
                            .map(U256::from_be_bytes)
                            .collect();
                        (address, slots)
                    })
                    .collect();
            }
            EvmTx::Legacy {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.gas_price = U256::from(gas_price);
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
            }
            EvmTx::Eip1559 {
                from,
                to,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                value,
                data,
                access_list,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(t) => revm::primitives::TransactTo::Call(to_addr(t)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
                tx_env.access_list = access_list
                    .into_iter()
                    .map(|item| {
                        let address = to_addr(item.address);
                        let slots = item.storage_keys
                            .into_iter()
                            .map(U256::from_be_bytes)
                            .collect();
                        (address, slots)
                    })
                    .collect();

                // EIP-1559: compute effective gas price.
                // The base fee is taken from the block environment (already set).
                // Effective gas price = min(max_fee, base_fee + priority_fee)
                // but must be >= base_fee.
                let base_fee = evm.context.evm.inner.env.block.basefee;
                let max_fee = U256::from(max_fee_per_gas);
                let priority_fee = U256::from(max_priority_fee_per_gas);
                let effective_gas_price = max_fee.min(base_fee + priority_fee);
                tx_env.gas_price = effective_gas_price;
            }
        }
    }

    // Execute the transaction and commit state changes.
    let res = evm.transact_commit().map_err(|e| format!("REVM error: {:?}", e))?;

    // Map the REVM execution result to our output type.
    Ok(match res {
        ExecutionResult::Success {
            gas_used,
            logs,
            output,
            ..
        } => {
            let (return_data, created_address) = match output {
                revm::primitives::Output::Call(out) => (out.to_vec(), None),
                revm::primitives::Output::Create(out, addr) => (out.to_vec(), Some(addr)),
            };
            EvmExecOutput {
                logs,
                created_address: created_address.flatten(),
                gas_used,
                success: true,
                return_data,
            }
        }
        ExecutionResult::Revert { gas_used, output } => EvmExecOutput {
            logs: Vec::new(),
            created_address: None,
            gas_used,
            success: false,
            return_data: output.to_vec(),
        },
        ExecutionResult::Halt { gas_used, .. } => EvmExecOutput {
            logs: Vec::new(),
            created_address: None,
            gas_used,
            success: false,
            return_data: Vec::new(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::db::MemDb;
    use crate::types::tx_evm::{AccessListItem, EvmTx};

    fn make_test_address(seed: u8) -> [u8; 20] {
        let mut addr = [0u8; 20];
        addr[0] = seed;
        addr
    }

    #[test]
    fn test_evm_deployment() {
        let mut db = MemDb::new();
        let deployer = make_test_address(1);
        // Fund the deployer account (for gas)
        db.load_account_from_iona(deployer.into(), 1_000_000_000_000_000, 0, None);

        // Simple deployment transaction: create a contract that returns a constant.
        // The init code is just the return opcode. We'll use a very simple contract.
        let init_code = vec![
            0x60, 0x2a, // PUSH1 0x2a
            0x60, 0x00, // PUSH1 0x00
            0x52,       // MSTORE
            0x60, 0x20, // PUSH1 0x20
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ];
        let tx = EvmTx::Legacy {
            from: deployer,
            to: None,
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10_000_000_000, // 10 gwei
            value: 0,
            data: init_code,
            chain_id: 1,
        };

        let block_env = build_evm_env(1, 1_600_000_000, Some(1), 1, SpecId::CANCUN);
        let output = execute_evm_tx(&mut db, block_env, tx).unwrap();
        assert!(output.success, "Deployment failed");
        assert!(output.created_address.is_some(), "No contract address returned");
        assert!(output.gas_used > 0 && output.gas_used < 200_000, "unexpected gas: {}", output.gas_used);
    }

    #[test]
    fn test_evm_call() {
        let mut db = MemDb::new();
        let caller = make_test_address(2);
        let contract_addr = make_test_address(3);

        // Deploy a contract that returns 42.
        let init_code = vec![
            0x60, 0x2a, // PUSH1 0x2a
            0x60, 0x00, // PUSH1 0x00
            0x52,       // MSTORE
            0x60, 0x20, // PUSH1 0x20
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ];
        // We'll deploy by creating a temporary transaction; for simplicity, we'll manually
        // simulate a deployment. But we can also create a dummy deployment via a call.
        // For this test, we'll directly put the code into the DB as if already deployed.
        let bytecode = revm::primitives::Bytecode::new_raw(init_code.into());
        db.load_account_from_iona(contract_addr.into(), 0, 0, Some(bytecode));

        // Fund the caller.
        db.load_account_from_iona(caller.into(), 1_000_000_000_000_000, 0, None);

        // Call the contract (no calldata needed because it just returns constant).
        let tx = EvmTx::Legacy {
            from: caller,
            to: Some(contract_addr),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 0,
            data: vec![],
            chain_id: 1,
        };

        let block_env = build_evm_env(1, 1_600_000_000, Some(1), 1, SpecId::CANCUN);
        let output = execute_evm_tx(&mut db, block_env, tx).unwrap();
        assert!(output.success, "Call failed");
        // MSTORE pads value to 32 bytes, so return data is 32 bytes with 42 at end
        let mut expected = vec![0u8; 31];
        expected.push(0x2a);
        assert_eq!(output.return_data, expected);
    }
}
