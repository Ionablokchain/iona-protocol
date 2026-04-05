use rlp::RlpStream;
use crate::rpc::eth_rpc::{Log, Receipt};

/// Convert a hex string to bytes, with validation.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim_start_matches("0x");
    hex::decode(trimmed).map_err(|e| format!("invalid hex: {}", e))
}

/// Encode a log as RLP.
pub fn rlp_encode_log(log: &Log) -> Result<Vec<u8>, String> {
    let address = hex_to_bytes(&log.address)?;
    if address.len() != 20 {
        return Err(format!("address length {} != 20", address.len()));
    }

    let mut s = RlpStream::new_list(3);
    s.append(&address);

    // topics: list of 32-byte values
    s.begin_list(log.topics.len());
    for topic in &log.topics {
        let topic_bytes = hex_to_bytes(topic)?;
        if topic_bytes.len() != 32 {
            return Err(format!("topic length {} != 32", topic_bytes.len()));
        }
        s.append(&topic_bytes);
    }

    let data = hex_to_bytes(&log.data)?;
    s.append(&data);
    Ok(s.out().to_vec())
}

/// Encode a receipt (post-Byzantium) as RLP.
pub fn rlp_encode_receipt(receipt: &Receipt) -> Result<Vec<u8>, String> {
    let bloom = hex_to_bytes(&receipt.logs_bloom)?;
    if bloom.len() != 256 {
        return Err(format!("bloom length {} != 256", bloom.len()));
    }

    let mut s = RlpStream::new_list(4);
    s.append(&if receipt.status { 1u8 } else { 0u8 });
    s.append(&receipt.cumulative_gas_used);
    s.append(&bloom);

    s.begin_list(receipt.logs.len());
    for log in &receipt.logs {
        let encoded_log = rlp_encode_log(log)?;
        s.append_raw(&encoded_log, 1);
    }

    Ok(s.out().to_vec())
}

/// Encode a typed receipt per EIP-2718.
pub fn rlp_encode_typed_receipt(tx_type: u8, receipt: &Receipt) -> Result<Vec<u8>, String> {
    let inner = rlp_encode_receipt(receipt)?;
    match tx_type {
        0x01 | 0x02 | 0x03 | 0x7e => {
            let mut out = Vec::with_capacity(1 + inner.len());
            out.push(tx_type);
            out.extend_from_slice(&inner);
            Ok(out)
        }
        _ => Ok(inner), // legacy (type 0x00)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::eth_rpc::{Log, Receipt};

    #[test]
    fn test_rlp_encode_log() {
        let log = Log {
            address: "0x0000000000000000000000000000000000000000".to_string(),
            topics: vec!["0x0000000000000000000000000000000000000000000000000000000000000000".to_string()],
            data: "0x".to_string(),
            block_number: 0,
            log_index: 0,
            tx_hash: String::new(),
        };
        let encoded = rlp_encode_log(&log).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_receipt() {
        let receipt = Receipt {
            status: true,
            cumulative_gas_used: 21000,
            logs_bloom: "0x".to_string() + &"00".repeat(256),
            logs: vec![],
            tx_hash: String::new(),
            block_hash: String::new(),
            block_number: 0,
            contract_address: None,
            from: String::new(),
            gas_used: 21000,
            to: String::new(),
            transaction_hash: String::new(),
            transaction_index: 0,
            tx_type: 0,
            effective_gas_price: "0".to_string(),
        };
        let encoded = rlp_encode_receipt(&receipt).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_invalid_address() {
        let log = Log {
            address: "0x123".to_string(),
            topics: vec![],
            data: "0x".to_string(),
            block_number: 0,
            log_index: 0,
            tx_hash: String::new(),
        };
        assert!(rlp_encode_log(&log).is_err());
    }
}
