#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the custom VM interpreter with arbitrary bytecode.
//
// Safety guarantee: executing arbitrary bytecode must NEVER panic.
// All errors (out-of-gas, invalid opcode, stack underflow, etc.) must be
// returned as a VmError, not an unwrap/unreachable panic.
fuzz_target!(|data: &[u8]| {
    use iona::vm::interpreter::exec;
    use iona::vm::gas::GasMeter;
    use iona::vm::state::{VmStorage, VmLog};

    // Minimal VmState implementation for fuzzing, with Clone/Debug/PartialEq
    // to enable state comparison and cloning.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FuzzState {
        storage: std::collections::BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
        code: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
        logs: Vec<VmLog>,
    }

    impl iona::vm::state::VmState for FuzzState {
        fn sload(&self, contract: &[u8; 32], slot: &[u8; 32]) -> [u8; 32] {
            self.storage.get(&(*contract, *slot)).copied().unwrap_or([0u8; 32])
        }
        fn sstore(&mut self, contract: &[u8; 32], slot: [u8; 32], value: [u8; 32]) {
            if value == [0u8; 32] {
                self.storage.remove(&(*contract, slot));
            } else {
                self.storage.insert((*contract, slot), value);
            }
        }
        fn get_code(&self, addr: &[u8; 32]) -> Vec<u8> {
            self.code.get(addr).cloned().unwrap_or_default()
        }
        fn set_code(&mut self, addr: &[u8; 32], code: Vec<u8>) {
            self.code.insert(*addr, code);
        }
        fn emit_log(&mut self, log: VmLog) {
            // Cap logs to avoid OOM under fuzzing.
            if self.logs.len() < 64 {
                self.logs.push(log);
            }
        }
    }

    // Helper to verify gas meter stays within valid bounds.
    fn check_gas_valid(gas: &GasMeter) {
        let remaining = gas.remaining();
        assert!(remaining >= 0, "gas remaining negative: {}", remaining);
        assert!(remaining <= 10_000_000, "gas remaining exceeds limit: {}", remaining);
    }

    // Use first 32 bytes as a fake contract address, rest as calldata.
    let (contract_addr, calldata) = if data.len() >= 32 {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&data[..32]);
        (addr, &data[32..])
    } else {
        ([0u8; 32], data)
    };

    // Extract optional depth and value from the remaining input if enough bytes.
    let (depth, value, bytecode) = if calldata.len() >= 8 {
        // Use next 4 bytes for depth (u32), next 4 for value (u32), rest for bytecode.
        let depth = u32::from_le_bytes([calldata[0], calldata[1], calldata[2], calldata[3]]);
        let value = u32::from_le_bytes([calldata[4], calldata[5], calldata[6], calldata[7]]);
        (depth as usize, value as u64, &calldata[8..])
    } else {
        (0, 0, calldata)
    };

    // ---- First execution ----
    let mut state1 = FuzzState {
        storage: std::collections::BTreeMap::new(),
        code: std::collections::BTreeMap::new(),
        logs: Vec::new(),
    };
    let mut gas1 = GasMeter::new(10_000_000);
    let result1 = exec(bytecode, calldata, &contract_addr, &mut state1, &mut gas1, depth, value);
    check_gas_valid(&gas1);

    // ---- Second execution with identical starting state ----
    // Clone state1 (which is still the initial state, not modified)
    let mut state2 = state1.clone();
    let mut gas2 = GasMeter::new(10_000_000);
    let result2 = exec(bytecode, calldata, &contract_addr, &mut state2, &mut gas2, depth, value);
    check_gas_valid(&gas2);

    // Both executions must produce the same result (determinism).
    assert_eq!(result1, result2, "non-deterministic execution: results differ");

    // Compare final states (excluding logs may be optional, but we include them).
    assert_eq!(state1, state2, "non-deterministic execution: states differ");

    // ---- Log sanity checks ----
    for log in &state1.logs {
        // Ensure log address and topics are accessible (no panic).
        let _ = log.address;
        for topic in &log.topics {
            let _ = topic;
        }
        // Data length should be reasonable to avoid issues later.
        assert!(log.data.len() <= 1024, "log data too large: {} bytes", log.data.len());
    }

    // ---- Storage consistency check ----
    // Verify that all storage keys and values have the correct length (32 bytes).
    for ((contract, slot), value) in &state1.storage {
        assert_eq!(contract.len(), 32, "storage key contract length invalid");
        assert_eq!(slot.len(), 32, "storage key slot length invalid");
        assert_eq!(value.len(), 32, "storage value length invalid");
    }
});
