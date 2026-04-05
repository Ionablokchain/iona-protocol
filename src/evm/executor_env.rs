use revm::primitives::{Address, BlockEnv, CfgEnv, Env, SpecId, TxEnv, U256};

/// Creates a default EVM environment for the given chain ID, with a placeholder block.
/// For actual execution, you should build an `Env` from the current block header.
pub fn default_env(chain_id: u64, _spec_id: SpecId) -> Env {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    // spec_id is set at handler level

    let block = BlockEnv {
        number: U256::from(0),
        coinbase: Address::ZERO,
        timestamp: U256::from(0),
        basefee: U256::from(0),
        gas_limit: U256::from(30_000_000),
        ..Default::default()
    };

    Env {
        cfg,
        block,
        tx: TxEnv::default(),
    }
}

/// Builds an environment from an Iona block header.
pub fn env_from_header(header: &crate::types::BlockHeader, chain_id: u64, _spec_id: SpecId) -> Env {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    // spec_id is set at handler level

    let mut block = BlockEnv::default();
    block.number = U256::from(header.height);
    block.timestamp = U256::from(header.timestamp);
    block.basefee = U256::from(header.base_fee_per_gas);
    block.gas_limit = U256::from(header.gas_used);
    // coinbase (proposer) – convert proposer public key to address (simplified)
    block.coinbase = address_from_pubkey(&header.proposer_pk);

    Env {
        cfg,
        block,
        tx: TxEnv::default(),
    }
}

pub fn address_from_pubkey(pubkey: &[u8]) -> Address {
    if pubkey.len() < 20 {
        return Address::ZERO;
    }
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(pubkey);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    Address::from(addr_bytes)
}
