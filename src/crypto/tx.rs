/// Transaction signing and address derivation.

use crate::crypto::ed25519::Ed25519Signer;
use crate::crypto::Signer;
use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::Tx;
use blake3;

/// Derive an Iona address (20‑byte hex string) from a public key.
pub fn derive_address(pubkey: &[u8]) -> String {
    let hash = blake3::hash(pubkey);
    hex::encode(&hash.as_bytes()[..20])
}

/// Compute the bytes that are signed for a transaction.
pub fn tx_sign_bytes(tx: &Tx) -> Vec<u8> {
    // The order of fields must match what the signer expects.
    serde_json::to_vec(&(
        "iona-tx-v1",
        tx.chain_id,
        &tx.pubkey,
        tx.nonce,
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        tx.gas_limit,
        &tx.payload,
    ))
    .unwrap_or_default()
}

/// Sign a transaction using an Ed25519 signer.
pub fn sign_tx(tx: &mut Tx, signer: &Ed25519Signer) {
    let msg = tx_sign_bytes(tx);
    let sig = signer.sign(&msg);
    tx.signature = sig.0;
    // The from address should match the derived address.
    tx.from = derive_address(&signer.public_key().0);
}

/// Verify a transaction's signature.
pub fn verify_tx_signature(tx: &Tx) -> Result<(), crate::crypto::CryptoError> {
    use crate::crypto::Verifier;
    use crate::crypto::ed25519::Ed25519Verifier;

    let msg = tx_sign_bytes(tx);
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());
    Ed25519Verifier::verify(&pk, &msg, &sig)
}
