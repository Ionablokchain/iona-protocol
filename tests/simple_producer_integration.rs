use iona::consensus::block_producer::ValidatorIdentity;
use iona::consensus::{SimpleBlockProducer, SimpleProducerCfg};
use iona::crypto::ed25519::Ed25519Keypair;
use iona::crypto::Signer;
use iona::execution::KvState;

#[test]
fn round_robin_producer_broadcasts_proposal() {
    let k1 = Ed25519Keypair::from_seed([1u8; 32]);
    let k2 = Ed25519Keypair::from_seed([2u8; 32]);
    let k3 = Ed25519Keypair::from_seed([3u8; 32]);

    let addr1 = hex::encode(&blake3::hash(&k1.public_key().0).as_bytes()[..20]);
    let addr2 = hex::encode(&blake3::hash(&k2.public_key().0).as_bytes()[..20]);
    let addr3 = hex::encode(&blake3::hash(&k3.public_key().0).as_bytes()[..20]);

    let validators = vec![
        ValidatorIdentity {
            address: addr1.clone(),
        },
        ValidatorIdentity {
            address: addr2.clone(),
        },
        ValidatorIdentity {
            address: addr3.clone(),
        },
    ];

    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 100,
        include_block_in_proposal: true,
        allow_empty_blocks: true,
    });

    let app_state = KvState::default();
    let prev_block_id = [0u8; 32];

    // Height=1, round=0 => k2 is proposer (idx = (1+0)%3 = 1)
    let result = producer.try_produce(
        1,                         // height
        0,                         // round
        None,                      // valid_round
        prev_block_id,             // prev_block_id
        &app_state,                // app_state
        0,                         // base_fee
        &k2,                       // signer
        &addr2,                    // proposer_addr
        k2.public_key().0.clone(), // proposer_pubkey_bytes
        &validators,               // validators
        &[],                       // mempool_txs
        false,                     // already_proposed
    );

    assert!(
        result.is_ok(),
        "try_produce should not return error: {:?}",
        result.err()
    );

    // Height=2, round=0 => k3 is proposer
    let result2 = producer.try_produce(
        2,
        0,
        None,
        prev_block_id,
        &app_state,
        0,
        &k3,
        &addr3,
        k3.public_key().0.clone(),
        &validators,
        &[],
        false,
    );
    assert!(
        result2.is_ok(),
        "try_produce should not error: {:?}",
        result2.err()
    );
}
