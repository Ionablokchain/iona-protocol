use iona::consensus::{
    proposal_sign_bytes, BlockStore, Config, ConsensusMsg, Engine, Outbox, Proposal, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::{build_block, KvState};
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct MemStore {
    blocks: Mutex<HashMap<Hash32, Block>>,
}
impl BlockStore for MemStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.blocks.lock().ok()?.get(id).cloned()
    }
    fn put(&self, block: Block) {
        if let Ok(mut m) = self.blocks.lock() {
            m.insert(block.id(), block);
        }
    }
}

#[derive(Default)]
struct WireOutbox {
    pub broadcasts: Vec<ConsensusMsg>,
}
impl Outbox for WireOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg);
    }
    fn request_block(&mut self, _block_id: Hash32) {}
    fn on_commit(
        &mut self,
        _cert: &iona::consensus::CommitCertificate,
        _block: &Block,
        _new_state: &KvState,
        _new_base_fee: u64,
        _receipts: &[iona::types::Receipt],
    ) {
    }
}

fn make_engine(height: u64, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = true;
    Engine::new(
        cfg,
        vset,
        height,
        Hash32([0u8; 32]),
        KvState::default(),
        StakeLedger::default(),
        None,
    )
}

#[test]
fn producer_to_observer_proposal_delivery() {
    let k1 = Ed25519Keypair::from_seed([1u8; 32]);
    let k2 = Ed25519Keypair::from_seed([2u8; 32]);

    let vset = ValidatorSet {
        vals: vec![
            Validator {
                pk: k1.public_key(),
                power: 1,
            },
            Validator {
                pk: k2.public_key(),
                power: 1,
            },
        ],
    };

    // Engine uses proposer_for(height, round) = vals[(height+round) % n].
    // height=1 round=0 => vals[(1+0)%2] = vals[1] => k2 is proposer.
    let proposer_key = &k2;
    let proposer_addr = hex::encode(&blake3::hash(&proposer_key.public_key().0).as_bytes()[..20]);

    let store_o = MemStore::default();
    let mut out_o = WireOutbox::default();

    let mut eng_p = make_engine(1, vset.clone());
    let mut eng_o = make_engine(1, vset.clone());

    // Producer proposes
    assert_eq!(eng_p.state.step, Step::Propose);

    // Build block and proposal directly (include_block_in_proposal = true).
    let (block, _next_state, _receipts) = build_block(
        eng_p.state.height,
        eng_p.state.round,
        Hash32([0u8; 32]),
        proposer_key.public_key().0.clone(),
        &proposer_addr,
        &eng_p.app_state,
        eng_p.base_fee_per_gas,
        vec![],
        0,
        0,
    );
    let bid = block.id();

    let sign_bytes = proposal_sign_bytes(eng_p.state.height, eng_p.state.round, &bid, None);
    let sig = proposer_key.sign(&sign_bytes);
    let proposal = Proposal {
        height: eng_p.state.height,
        round: eng_p.state.round,
        proposer: proposer_key.public_key(),
        block_id: bid.clone(),
        block: Some(block),
        pol_round: None,
        signature: sig,
    };

    // Deliver proposal to observer through "wire"
    let proposal_msg = ConsensusMsg::Proposal(proposal);
    eng_o
        .on_message(&k1, &store_o, &mut out_o, proposal_msg)
        .expect("observer on_message failed");

    // Observer should now have proposal stored in its state
    assert!(
        eng_o.state.proposal.is_some(),
        "observer should store proposal"
    );
}
