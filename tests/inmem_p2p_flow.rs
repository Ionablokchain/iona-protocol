//! Integration test for in-memory network consensus flow.
//!
//! This test sets up a two-validator set and simulates a consensus round
//! where one node (the producer) creates and broadcasts a proposal,
//! and the other node (observer) receives and stores it via the in-memory network.
//!
//! It verifies that the network correctly delivers messages between nodes
//! and that the observer's engine processes the proposal.

use iona::consensus::{
    ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet,
    BlockStore, Outbox, Engine, Step, Config, ValidatorIdentity,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Block};
use iona::slashing::StakeLedger;
use iona::execution::KvState;
use iona::net::inmem::{InMemNet, NodeId};

use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

// In-memory block store for testing
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

/// Outbox that broadcasts over the in-memory network.
struct InMemOutbox {
    net: InMemNet,
    // We keep track of broadcasts for potential test assertions, but not strictly needed.
    _broadcasts: Vec<ConsensusMsg>,
}

impl InMemOutbox {
    fn new(net: InMemNet) -> Self {
        Self {
            net,
            _broadcasts: Vec::new(),
        }
    }
}

impl Outbox for InMemOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self._broadcasts.push(msg.clone());
        self.net.broadcast(msg);
    }

    fn request_block(&mut self, _block_id: Hash32) {
        // Not used in this test
    }

    fn on_commit(
        &mut self,
        _cert: &iona::consensus::CommitCertificate,
        _block: &Block,
        _new_state: &KvState,
        _new_base_fee: u64,
        _receipts: &[iona::types::Receipt],
    ) {
        // Not used in this test
    }
}

/// Create an engine instance for a given height and validator set.
fn make_engine(height: u64, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = true;
    Engine::new(
        cfg,
        vset,
        height,
        Hash32([0u8; 32]), // parent hash (zero for genesis)
        KvState::default(),
        StakeLedger::default(),
        None,
    )
}

/// Message processing pump: forwards incoming messages to the engine.
async fn pump(
    mut rx: mpsc::UnboundedReceiver<ConsensusMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair, // each node uses its own keypair
    store: Arc<MemStore>,
    out: Arc<tokio::sync::Mutex<InMemOutbox>>,
) {
    while let Some(msg) = rx.recv().await {
        let mut eng = engine.lock().await;
        let mut ob = out.lock().await;
        // Ignore errors (e.g., message rejected due to state) — for test we just process.
        let _ = eng.on_message(&signer, store.as_ref(), &mut *ob, msg);
    }
}

#[tokio::test]
async fn inmem_network_delivers_proposal_to_observer() {
    // Create two validator keypairs.
    let keypair1 = Ed25519Keypair::from_seed([1u8; 32]);
    let keypair2 = Ed25519Keypair::from_seed([2u8; 32]);

    let vset = ValidatorSet {
        vals: vec![
            Validator {
                pk: keypair1.public_key(),
                power: 1,
            },
            Validator {
                pk: keypair2.public_key(),
                power: 1,
            },
        ],
    };

    // Setup in-memory network with two nodes (IDs 1 and 2).
    let (net, rx1) = InMemNet::new(1 as NodeId);
    let rx2 = net.register(2 as NodeId);
    let net2 = net.handle(2 as NodeId); // second node's network handle

    // Shared block stores (each node has its own store).
    let store1 = Arc::new(MemStore::default());
    let store2 = Arc::new(MemStore::default());

    // Engines for both nodes at height 1.
    let engine1 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone())));
    let engine2 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone())));

    // Outboxes that use the network handles.
    let outbox1 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(net.clone())));
    let outbox2 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(net2.clone())));

    // Start background message pumps for both nodes.
    let pump1 = tokio::spawn(pump(
        rx1,
        engine1.clone(),
        keypair1.clone(), // node1 signs with its own key
        store1.clone(),
        outbox1.clone(),
    ));
    let pump2 = tokio::spawn(pump(
        rx2,
        engine2.clone(),
        keypair2.clone(), // node2 signs with its own key
        store2.clone(),
        outbox2.clone(),
    ));

    // At height 1, round 0, the producer is validator with index (height + round) % n = (1+0)%2 = 1,
    // which is validator 2 (keypair2). We'll let node2 produce the block.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 100,
        include_block_in_proposal: true,
        allow_empty_blocks: true,
    });

    // Build validator identities for proposer selection.
    let addr1 = hex::encode(&blake3::hash(&keypair1.public_key().0).as_bytes()[..20]);
    let addr2 = hex::encode(&blake3::hash(&keypair2.public_key().0).as_bytes()[..20]);
    // Order validators so that at height=1, round=0: index = (0+0)%2 = 0 → addr2 is proposer.
    let val_ids = vec![
        ValidatorIdentity::new(&addr2),
        ValidatorIdentity::new(&addr1),
    ];

    {
        // Lock node2's engine and outbox to produce.
        let eng2 = engine2.lock().await;
        // Ensure engine is in Propose step.
        assert_eq!(eng2.state.step, Step::Propose);
        let mut out2 = outbox2.lock().await;
        let produced = producer.try_produce(
            eng2.state.height, eng2.state.round, None, [0u8; 32],
            &eng2.app_state, eng2.base_fee_per_gas, &keypair2,
            &addr2,
            keypair2.public_key().0.clone(), &val_ids, &[], false,
        ).ok().flatten();
        assert!(produced.is_some(), "Producer should have created a proposal");
        let (proposal, block) = produced.unwrap();
        // Store the block locally and broadcast the proposal.
        store2.put(block);
        out2.broadcast(ConsensusMsg::Proposal(proposal));
    }

    // Wait for the proposal to be delivered to node1 (observer).
    // Instead of fixed sleep, we poll until condition is met or timeout.
    let timeout_duration = Duration::from_millis(200);
    let result = timeout(timeout_duration, async {
        loop {
            {
                let eng1 = engine1.lock().await;
                if eng1.state.proposal.is_some() {
                    // Optionally, verify proposal fields.
                    let proposal = eng1.state.proposal.as_ref().unwrap();
                    // For example: proposal height should be 1.
                    // (We would need access to the proposal structure; assuming it contains block.)
                    // Since we don't have direct block access here, we just check presence.
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    }).await;

    assert!(
        result.is_ok(),
        "Observer did not receive the proposal within {}ms",
        timeout_duration.as_millis()
    );

    // Clean shutdown: drop network handles and cancel pumps.
    // Dropping the network will close the channels, causing pumps to exit.
    drop(net);
    drop(net2);
    // Wait a bit for pumps to finish (they will exit on channel closed).
    tokio::time::sleep(Duration::from_millis(10)).await;
    pump1.abort();
    pump2.abort();
}
