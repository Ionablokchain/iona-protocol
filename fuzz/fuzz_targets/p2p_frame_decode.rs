#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the P2P message deserialization path.
// Any panic here = crash of a live node receiving a malicious packet.
fuzz_target!(|data: &[u8]| {
    use iona::consensus::ConsensusMsg;
    use iona::types::{Block, Tx};

    // ---- 1. Direct bincode deserialization of various types ----
    if let Ok(msg) = bincode::deserialize::<ConsensusMsg>(data) {
        // Round-trip check for ConsensusMsg
        if let Ok(serialized) = bincode::serialize(&msg) {
            let msg2 = bincode::deserialize::<ConsensusMsg>(&serialized)
                .expect("bincode roundtrip failed for ConsensusMsg");
            assert_eq!(msg, msg2, "bincode roundtrip produced different ConsensusMsg");
        }

        // Also try JSON if supported
        if let Ok(json) = serde_json::to_vec(&msg) {
            let msg_json = serde_json::from_slice::<ConsensusMsg>(&json)
                .expect("JSON roundtrip failed for ConsensusMsg");
            assert_eq!(msg, msg_json, "JSON roundtrip produced different ConsensusMsg");
        }
    }

    if let Ok(block) = bincode::deserialize::<Block>(data) {
        if let Ok(serialized) = bincode::serialize(&block) {
            let block2 = bincode::deserialize::<Block>(&serialized)
                .expect("bincode roundtrip failed for Block");
            assert_eq!(block, block2, "bincode roundtrip produced different Block");
        }
    }

    if let Ok(tx) = bincode::deserialize::<Tx>(data) {
        if let Ok(serialized) = bincode::serialize(&tx) {
            let tx2 = bincode::deserialize::<Tx>(&serialized)
                .expect("bincode roundtrip failed for Tx");
            assert_eq!(tx, tx2, "bincode roundtrip produced different Tx");
        }
    }

    // ---- 2. Length-prefixed framing simulation ----
    // Format: first 4 bytes = payload length (big-endian), rest = payload.
    if data.len() >= 4 {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        // Sanity check: avoid huge allocations (e.g., >1MB)
        if len > 1024 * 1024 {
            return; // skip unreasonable lengths
        }

        if let Some(payload) = data.get(4..4 + len.min(data.len() - 4)) {
            // Try to deserialize a ConsensusMsg from the extracted payload
            if let Ok(msg) = bincode::deserialize::<ConsensusMsg>(payload) {
                // Round-trip the extracted message
                if let Ok(serialized) = bincode::serialize(&msg) {
                    let msg2 = bincode::deserialize::<ConsensusMsg>(&serialized)
                        .expect("bincode roundtrip failed for framed ConsensusMsg");
                    assert_eq!(msg, msg2, "bincode roundtrip mismatch for framed message");
                }
            }
        }
    }
});
