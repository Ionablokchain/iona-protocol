//! Integration tests for IONA v22.
//!
//! Tests run multiple engine instances in-process, simulating a 4-validator
//! network with a mock message bus. No actual networking needed.
//!
//! Run with: cargo test --test integration

use iona::consensus::{
    BlockStore, CommitCertificate, Config, ConsensusMsg, Engine, Outbox, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::{execute_block, next_base_fee, verify_block, KvState};
use iona::mempool::Mempool;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32, Receipt, Tx};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Constants used across tests
const CHAIN_ID: u64 = 6126151;
const GAS_TARGET: u64 = 1_000_000;
const BASE_FEE_INITIAL: u64 = 1;

// ── Helper types ──────────────────────────────────────────────────────────

/// In-memory block store shared between nodes.
#[derive(Default, Clone)]
struct MemBlockStore(Arc<Mutex<HashMap<Hash32, Block>>>);

impl BlockStore for MemBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.0
            .lock()
            .expect("MemBlockStore lock poisoned")
            .get(id)
            .cloned()
    }
    fn put(&self, block: Block) {
        let id = block.id();
        self.0
            .lock()
            .expect("MemBlockStore lock poisoned")
            .insert(id, block);
    }
}

/// Outbox that records all broadcasts and commits for later inspection.
#[derive(Default, Clone)]
struct RecordingOutbox {
    pub broadcasts: Arc<Mutex<Vec<ConsensusMsg>>>,
    pub commits: Arc<Mutex<Vec<CommitCertificate>>>,
    pub store: MemBlockStore,
}

impl Outbox for RecordingOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts
            .lock()
            .expect("RecordingOutbox lock poisoned")
            .push(msg);
    }
    fn request_block(&mut self, _id: Hash32) {}
    fn on_commit(
        &mut self,
        cert: &CommitCertificate,
        _block: &Block,
        _state: &KvState,
        _base_fee: u64,
        _receipts: &[Receipt],
    ) {
        self.commits
            .lock()
            .expect("RecordingOutbox lock poisoned")
            .push(cert.clone());
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Generate n deterministic Ed25519 keypairs.
fn make_keypairs(n: usize) -> Vec<Ed25519Keypair> {
    (1..=n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            Ed25519Keypair::from_seed(seed)
        })
        .collect()
}

/// Build a validator set with equal power from a list of keypairs.
fn make_vset(keys: &[Ed25519Keypair]) -> ValidatorSet {
    ValidatorSet {
        vals: keys
            .iter()
            .map(|k| Validator {
                pk: k.public_key(),
                power: 100,
            })
            .collect(),
    }
}

/// Create a stake ledger with equal stakes for each validator.
fn make_stakes(keys: &[Ed25519Keypair]) -> StakeLedger {
    StakeLedger::default_demo_with(
        &keys.iter().map(|k| k.public_key()).collect::<Vec<_>>(),
        100,
    )
}

/// Fast consensus configuration suitable for tests.
#[must_use]
fn fast_config() -> Config {
    Config {
        propose_timeout_ms: 10,
        prevote_timeout_ms: 10,
        precommit_timeout_ms: 10,
        max_rounds: 50,
        max_txs_per_block: 100,
        gas_target: GAS_TARGET,
        initial_base_fee_per_gas: BASE_FEE_INITIAL,
        include_block_in_proposal: true,
        fast_quorum: true,
    }
}

/// A sample transaction for testing.
fn sample_tx() -> Tx {
    Tx {
        pubkey: vec![1u8; 32],
        from: "alice".into(),
        nonce: 0,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 5,
        gas_limit: 50_000,
        payload: "set k v".into(),
        signature: vec![0u8; 64],
        chain_id: CHAIN_ID,
    }
}

/// A sample block header (without transactions).
fn sample_header() -> Block {
    let header = iona::types::BlockHeader {
        pv: 0,
        height: 1,
        round: 0,
        prev: Hash32::zero(),
        proposer_pk: vec![0u8; 32],
        tx_root: Hash32::zero(),
        receipts_root: Hash32::zero(),
        state_root: Hash32::zero(),
        base_fee_per_gas: BASE_FEE_INITIAL,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id: CHAIN_ID,
        timestamp: 0,
        protocol_version: 1,
    };
    Block {
        header,
        txs: vec![],
    }
}

/// A sample state with a few KV entries and a balance.
fn sample_state() -> KvState {
    let mut state = KvState::default();
    state.kv.insert("a".into(), "1".into());
    state.kv.insert("b".into(), "2".into());
    state.balances.insert("addr".into(), 100);
    state
}

/// Deliver all pending messages to all engines (including sender, simplified model).
/// Returns true if any message was delivered.
fn drain_and_deliver(
    engines: &mut [Engine<Ed25519Verifier>],
    outboxes: &mut [RecordingOutbox],
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) -> bool {
    let mut any = false;
    // Collect all messages produced this round
    let mut pending: Vec<ConsensusMsg> = Vec::new();
    for ob in outboxes.iter_mut() {
        let mut msgs = ob.broadcasts.lock().expect("broadcasts lock poisoned");
        pending.extend(msgs.drain(..));
    }
    if pending.is_empty() {
        return false;
    }
    any = true;

    // Deliver to every engine (including sender — simplest correct model)
    for (i, engine) in engines.iter_mut().enumerate() {
        for msg in &pending {
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
    any
}

// ── Consensus tests ────────────────────────────────────────────────────────

mod consensus_tests {
    use super::*;

    /// 4 validators, 1 block commit without any Byzantine behavior.
    #[test]
    fn test_single_block_commit() {
        let keys = make_keypairs(4);
        let vset = make_vset(&keys);
        let cfg = fast_config();
        let state = KvState::default();
        let stakes = make_stakes(&keys);
        let stores: Vec<MemBlockStore> = (0..4).map(|_| MemBlockStore::default()).collect();

        let mut engines: Vec<Engine<Ed25519Verifier>> = keys
            .iter()
            .map(|_| {
                Engine::new(
                    cfg.clone(),
                    vset.clone(),
                    1,
                    Hash32::zero(),
                    state.clone(),
                    stakes.clone(),
                    None,
                )
            })
            .collect();

        let mut outboxes: Vec<RecordingOutbox> = (0..4)
            .map(|i| RecordingOutbox {
                store: stores[i].clone(),
                ..Default::default()
            })
            .collect();

        // Determine the proposer for height=1, round=0.
        let proposer_idx = (0..4)
            .find(|&i| engines[i].is_proposer(&keys[i].public_key()))
            .expect("one engine must be the proposer");

        // Step 1: Tick ONLY the proposer so it produces a proposal + its own prevote.
        // Do NOT tick non-proposers yet — they would vote nil without a proposal.
        {
            let mut ob = outboxes[proposer_idx].clone();
            engines[proposer_idx].tick(
                &keys[proposer_idx],
                &stores[proposer_idx],
                &mut ob,
                cfg.propose_timeout_ms,
                |_| vec![],
            );
        }
        // Step 2: Deliver proposer's messages (Proposal + Prevote) to all engines.
        // on_proposal moves non-proposers to Prevote and they broadcast prevotes for the block.
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);

        // Step 3: Deliver non-proposer prevotes. With 4 prevotes for the same block,
        // quorum is reached and engines transition to Precommit, broadcasting precommits.
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);

        // Step 4: Deliver precommits. Quorum of precommits triggers commit.
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);

        // Step 5: Final delivery for any remaining messages.
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);

        // All 4 validators must have decided
        for (i, engine) in engines.iter().enumerate() {
            assert!(
                engine.state.decided.is_some(),
                "engine {} did not commit",
                i
            );
        }

        // All must have decided on the SAME block
        let block_ids: Vec<_> = engines
            .iter()
            .map(|e| e.state.decided.as_ref().unwrap().block_id.clone())
            .collect();
        assert!(
            block_ids.windows(2).all(|w| w[0] == w[1]),
            "engines committed different blocks: {:?}",
            block_ids
        );

        // All commits must be at height 1
        for engine in &engines {
            assert_eq!(
                engine.state.decided.as_ref().unwrap().height,
                1,
                "commit height should be 1"
            );
        }

        // Verify that the committed block is actually stored and matches
        let first_id = &block_ids[0];
        let block_from_store = stores[0]
            .get(first_id)
            .expect("committed block should be in store");
        assert_eq!(block_from_store.id(), *first_id, "stored block ID mismatch");
    }

    /// Deterministic block ID: same header → same ID.
    #[test]
    fn test_block_id_deterministic() {
        let block1 = sample_header();
        let block2 = sample_header();
        assert_eq!(
            block1.id(),
            block2.id(),
            "block ID not deterministic: same header gave different IDs"
        );
    }
}

// ── State Merkle root tests ─────────────────────────────────────────────────

mod state_tests {
    use super::*;

    /// State Merkle root: same KV content → same root regardless of insertion order.
    #[test]
    fn test_merkle_root_deterministic() {
        let mut s1 = KvState::default();
        s1.kv.insert("a".into(), "1".into());
        s1.kv.insert("b".into(), "2".into());
        s1.balances.insert("addr".into(), 100);

        let mut s2 = KvState::default();
        s2.balances.insert("addr".into(), 100);
        s2.kv.insert("b".into(), "2".into());
        s2.kv.insert("a".into(), "1".into());

        assert_eq!(
            s1.root(),
            s2.root(),
            "Merkle root should be independent of insertion order"
        );
    }

    /// State Merkle root: different values → different root.
    #[test]
    fn test_merkle_root_sensitive() {
        let mut s1 = KvState::default();
        s1.kv.insert("k".into(), "v1".into());
        let mut s2 = KvState::default();
        s2.kv.insert("k".into(), "v2".into());
        assert_ne!(
            s1.root(),
            s2.root(),
            "different values must yield different roots"
        );
    }
}

// ── Transaction hash tests ──────────────────────────────────────────────────

mod tx_tests {
    use super::*;

    /// tx_hash: same tx content → same hash regardless of insertion order.
    #[test]
    fn test_tx_hash_deterministic() {
        let tx = sample_tx();
        let h1 = iona::types::tx_hash(&tx);
        let h2 = iona::types::tx_hash(&tx);
        assert_eq!(
            h1, h2,
            "tx_hash not deterministic: same tx gave different hashes"
        );
    }
}

// ── Base fee adjustment tests ───────────────────────────────────────────────

mod base_fee_tests {
    use super::*;

    /// EIP-1559 base fee: fills up → fee goes up; empty → fee goes down.
    #[test]
    fn test_base_fee_adjustment() {
        let base = 100u64;
        let target = GAS_TARGET;

        let full = next_base_fee(base, target * 2, target); // full block
        let empty = next_base_fee(base, 0, target); // empty block

        assert!(
            full > base,
            "full block should increase base fee: {} > {}? {}",
            full,
            base,
            full > base
        );
        assert!(
            empty < base,
            "empty block should decrease base fee: {} < {}? {}",
            empty,
            base,
            empty < base
        );
    }
}

// ── Mempool tests ───────────────────────────────────────────────────────────

mod mempool_tests {
    use super::*;

    fn tx_with_nonce_tip(from: &str, nonce: u64, tip: u64) -> Tx {
        Tx {
            pubkey: vec![0u8; 32],
            from: from.into(),
            nonce,
            max_fee_per_gas: tip + 10,
            max_priority_fee_per_gas: tip,
            gas_limit: 50_000,
            payload: "set k v".into(),
            signature: vec![0u8; 64],
            chain_id: CHAIN_ID,
        }
    }

    /// Mempool: nonce ordering — must drain in ascending nonce order per sender.
    #[test]
    fn test_mempool_nonce_ordering() {
        let mut mp = iona::mempool::pool::Mempool::new(1000);
        mp.push(tx_with_nonce_tip("alice", 2, 10), 0)
            .expect("push 2");
        mp.push(tx_with_nonce_tip("alice", 0, 10), 0)
            .expect("push 0");
        mp.push(tx_with_nonce_tip("alice", 1, 10), 0)
            .expect("push 1");

        let drained = mp.drain_best(3);
        assert_eq!(drained.len(), 3, "should drain exactly 3 transactions");
        assert_eq!(
            drained[0].nonce, 0,
            "first drained tx nonce should be 0, got {}",
            drained[0].nonce
        );
        assert_eq!(
            drained[1].nonce, 1,
            "second drained tx nonce should be 1, got {}",
            drained[1].nonce
        );
        assert_eq!(
            drained[2].nonce, 2,
            "third drained tx nonce should be 2, got {}",
            drained[2].nonce
        );
    }

    /// Mempool: RBF — replacement needs ≥10% bump, else rejected.
    #[test]
    fn test_mempool_rbf() {
        let mut mp = iona::mempool::pool::Mempool::new(1000);
        let base = tx_with_nonce_tip("bob", 0, 100);
        mp.push(base, 0).expect("initial push");

        // Same tip should be rejected
        let same_tip = tx_with_nonce_tip("bob", 0, 100);
        assert!(
            mp.push(same_tip, 0).is_err(),
            "same tip should be rejected (RBF)"
        );

        // 10% bump should be accepted
        let bump = tx_with_nonce_tip("bob", 0, 110);
        assert!(
            mp.push(bump, 0).is_ok(),
            "10% bump should be accepted (RBF)"
        );

        assert_eq!(mp.metrics.rbf_replaced, 1, "RBF replacement count wrong");
    }

    /// Mempool: TTL expiry.
    #[test]
    fn test_mempool_ttl() {
        let mut mp = iona::mempool::pool::Mempool::new(1000);
        let tx = tx_with_nonce_tip("carol", 0, 5);
        mp.push(tx, 0).expect("push");
        assert_eq!(mp.len(), 1, "mempool should contain 1 tx after push");

        mp.advance_height(10_000); // way past TTL
        assert_eq!(
            mp.len(),
            0,
            "mempool should be empty after advancing height past TTL"
        );
        assert_eq!(mp.metrics.expired, 1, "expired count should be 1");
    }
}

// ── Block verification tests ────────────────────────────────────────────────

mod verification_tests {
    use super::*;
    use iona::crypto::PublicKeyBytes;
    use iona::execution::{build_block, verify_block_with_vset};

    /// Block verification: modified block rejected, original accepted.
    #[test]
    fn test_verify_block_tamper() {
        let state = KvState::default();
        let (block, _next_state, _receipts) = build_block(
            1,
            0,
            Hash32::zero(),
            vec![0u8; 32],
            "proposer",
            &state,
            BASE_FEE_INITIAL,
            vec![],
            0u64, // block_timestamp
            1u64, // chain_id
        );

        // Valid block passes
        assert!(
            verify_block(&state, &block, "proposer").is_some(),
            "valid block should pass verification"
        );

        // Tampered state root fails
        let mut tampered = block.clone();
        tampered.header.state_root = Hash32([99u8; 32]);
        assert!(
            verify_block(&state, &tampered, "proposer").is_none(),
            "tampered state root should fail verification"
        );

        // Tampered gas_used fails
        let mut tampered2 = block.clone();
        tampered2.header.gas_used += 1;
        assert!(
            verify_block(&state, &tampered2, "proposer").is_none(),
            "tampered gas_used should fail verification"
        );
    }

    /// verify_block_with_vset: wrong proposer_pk rejected.
    #[test]
    fn test_verify_block_wrong_proposer() {
        let state = KvState::default();
        let real_pk = vec![1u8; 32];
        let fake_pk = vec![2u8; 32];

        let (block, _, _) = build_block(
            1,
            0,
            Hash32::zero(),
            real_pk.clone(),
            "proposer",
            &state,
            BASE_FEE_INITIAL,
            vec![],
            0u64, // block_timestamp
            1u64, // chain_id
        );

        let correct = PublicKeyBytes(real_pk);
        let wrong = PublicKeyBytes(fake_pk);

        assert!(
            verify_block_with_vset(&state, &block, "proposer", &correct).is_some(),
            "correct proposer_pk should be accepted"
        );
        assert!(
            verify_block_with_vset(&state, &block, "proposer", &wrong).is_none(),
            "block with wrong proposer_pk should be rejected"
        );
    }
}

// ── WAL tests ───────────────────────────────────────────────────────────────
//
// Note: This test requires the `tempfile` crate. Make sure it is listed
// in `dev-dependencies` in `Cargo.toml`:
//   [dev-dependencies]
//   tempfile = "3"

mod wal_tests {
    use super::*;
    use iona::wal::{Wal, WalEvent};
    use tempfile;

    /// WAL: write + replay round-trips events.
    #[test]
    fn test_wal_roundtrip() {
        let dir = tempfile::tempdir().expect("failed to create temporary directory");
        let wal_path = dir.path().to_str().expect("path must be valid UTF-8");

        // Write events
        {
            let mut wal = Wal::open(wal_path).expect("failed to open WAL for writing");
            wal.append(&WalEvent::Note {
                msg: "hello".into(),
            })
            .expect("append Note");
            wal.append(&WalEvent::Step {
                height: 5,
                round: 0,
                step: "Propose".into(),
            })
            .expect("append Step");
        }

        // Replay events
        let events = {
            let w = iona::wal::Wal::open(wal_path).expect("failed to open WAL");
            w.replay().expect("replay should succeed")
        };
        assert_eq!(events.len(), 2, "expected 2 events, got {}", events.len());

        match &events[0] {
            WalEvent::Note { msg } => assert_eq!(msg, "hello", "first event Note msg mismatch"),
            _ => panic!("first event should be Note"),
        }
        match &events[1] {
            WalEvent::Step {
                height,
                round,
                step,
            } => {
                assert_eq!(*height, 5, "Step height mismatch");
                assert_eq!(*round, 0, "Step round mismatch");
                assert_eq!(step, "Propose", "Step step mismatch");
            }
            _ => panic!("second event should be Step"),
        }
    }
}
