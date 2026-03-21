use revm::primitives::{Address, BlockEnv, CfgEnv, Env, SpecId, TxEnv, U256};

/// Creates a default EVM environment for the given chain ID, with a placeholder block.
/// For actual execution, you should build an `Env` from the current block header.
pub fn default_env(chain_id: u64, spec_id: SpecId) -> Env {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    cfg.spec_id = spec_id;

    let mut block = BlockEnv::default();
    block.number = U256::from(0);
    block.coinbase = Address::ZERO;
    block.timestamp = U256::from(0);
    block.basefee = U256::from(0);
    block.gas_limit = U256::from(30_000_000);

    Env {
        cfg,
        block,
        tx: TxEnv::default(),
    }
}

/// Builds an environment from an Iona block header.
pub fn env_from_header(
    header: &crate::types::BlockHeader,
    chain_id: u64,
    spec_id: SpecId,
) -> Env {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    cfg.spec_id = spec_id;

    let mut block = BlockEnv::default();
    block.number = U256::from(header.height);
    block.timestamp = U256::from(header.timestamp);
    block.basefee = U256::from(header.base_fee_per_gas);
    block.gas_limit = U256::from(header.gas_limit);
    // coinbase (proposer) – convert proposer public key to address (simplified)
    block.coinbase = address_from_pubkey(&header.proposer_pk);

    Env { cfg, block, tx: TxEnv::default() }
}
