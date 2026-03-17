#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz RPC JSON deserialization paths.
// Tests that malformed JSON never causes panics in any RPC-facing type,
// and that successful deserialization round-trips correctly.
fuzz_target!(|data: &[u8]| {
    use iona::types::{Tx, Block, BlockHeader, Receipt};
    use iona::config::NodeConfig;
    use iona::storage::meta::NodeMeta;

    // Helper macro to reduce boilerplate for round-trip checks
    macro_rules! try_roundtrip {
        ($type:ty, $data:expr) => {
            if let Ok(obj) = serde_json::from_slice::<$type>($data) {
                // Optional: touch some fields to ensure they're accessible
                let _ = format!("{:?}", obj); // Debug format to trigger potential panics

                // Round-trip: serialize back to JSON and deserialize again
                if let Ok(serialized) = serde_json::to_vec(&obj) {
                    let obj2 = serde_json::from_slice::<$type>(&serialized)
                        .expect("JSON roundtrip failed: deserialization error");
                    assert_eq!(obj, obj2, "JSON roundtrip produced different object");
                }
            }
        };
    }

    // Apply round-trip checks to all relevant types
    try_roundtrip!(Tx, data);
    try_roundtrip!(Block, data);
    try_roundtrip!(BlockHeader, data);
    try_roundtrip!(Receipt, data);
    try_roundtrip!(NodeConfig, data);
    try_roundtrip!(NodeMeta, data);
});
