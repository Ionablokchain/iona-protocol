#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz JSON deserialization of Tx and verify round-trip consistency.
fuzz_target!(|data: &[u8]| {
    use iona::types::Tx;

    if let Ok(tx) = serde_json::from_slice::<Tx>(data) {
        // Touch some fields to ensure they're accessible (no panic)
        let _ = tx.from;
        let _ = tx.nonce;
        let _ = tx.payload;

        // Round-trip: serialize back to JSON and deserialize again
        if let Ok(serialized) = serde_json::to_vec(&tx) {
            let tx2 = serde_json::from_slice::<Tx>(&serialized)
                .expect("JSON roundtrip failed: deserialization error");
            assert_eq!(tx, tx2, "JSON roundtrip produced different Tx");
        }
    }
});
