//! Simple PoS block producer.
//!
//! This module is intentionally minimal: it does *one* thing — if the local node
//! is the designated proposer (round-robin) for the current height/round, it
//! builds a block from mempool transactions, signs a `Proposal`, and returns it.
//!
//! It does **not** create votes or handle quorum/finality. Those remain the
//! responsibility of the consensus engine (if enabled).
//!
//! The producer does **not** directly modify the engine's state or persist the block.
//! It returns the proposal and block, leaving the engine to decide when to store
//! and broadcast (typically after receiving enough votes).

use crate::consensus::{proposal_sign_bytes, Proposal};
use crate::crypto::Signer;
use crate::execution::{build_block, AppState};
use crate::types::{Block, Tx};

use std::error::Error;
use std::fmt;

/// Validator identity used for deterministic proposer selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorIdentity {
    /// Canonical validator address / id used in proposer rotation.
    pub address: String,
}

impl ValidatorIdentity {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

/// Minimal producer configuration.
#[derive(Clone, Debug)]
pub struct SimpleProducerCfg {
    /// Maximum number of txs to include in a proposed block.
    pub max_txs: usize,
    /// Whether to embed the full block inside the proposal message.
    pub include_block_in_proposal: bool,
    /// Whether producer may create empty blocks when mempool is empty.
    pub allow_empty_blocks: bool,
}

impl Default for SimpleProducerCfg {
    fn default() -> Self {
        Self {
            max_txs: 4096,
            include_block_in_proposal: true,
            allow_empty_blocks: true,
        }
    }
}

/// Errors returned by the block producer.
#[derive(Debug)]
pub enum ProducerError {
    EmptyValidatorSet,
    LocalValidatorNotInSet {
        local_address: String,
    },
    InvalidMaxTxs,
    BlockBuildFailed {
        message: String,
    },
    SigningFailed {
        message: String,
    },
}

impl fmt::Display for ProducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValidatorSet => {
                write!(f, "cannot select proposer: validator set is empty")
            }
            Self::LocalValidatorNotInSet { local_address } => {
                write!(
                    f,
                    "local validator address `{local_address}` is not part of validator set"
                )
            }
            Self::InvalidMaxTxs => {
                write!(f, "invalid producer config: max_txs must be greater than zero")
            }
            Self::BlockBuildFailed { message } => {
                write!(f, "failed to build block: {message}")
            }
            Self::SigningFailed { message } => {
                write!(f, "failed to sign proposal: {message}")
            }
        }
    }
}

impl Error for ProducerError {}

/// Outcome of proposer selection for a given height/round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposerSelection {
    pub proposer_index: usize,
    pub proposer_address: String,
}

impl ProposerSelection {
    pub fn is_local(&self, local_address: &str) -> bool {
        self.proposer_address == local_address
    }
}

/// A simple round-robin PoS producer.
#[derive(Clone, Debug)]
pub struct SimpleBlockProducer {
    pub cfg: SimpleProducerCfg,
}

impl Default for SimpleBlockProducer {
    fn default() -> Self {
        Self {
            cfg: SimpleProducerCfg::default(),
        }
    }
}

impl SimpleBlockProducer {
    pub fn new(cfg: SimpleProducerCfg) -> Self {
        Self { cfg }
    }

    /// Deterministically select proposer for `(height, round)`.
    ///
    /// Rotation rule:
    /// `index = ((height - 1) + round) % validators.len()`
    ///
    /// Using `height - 1` makes height=1, round=0 start at validator index 0.
    pub fn select_proposer(
        &self,
        height: u64,
        round: u32,
        validators: &[ValidatorIdentity],
    ) -> Result<ProposerSelection, ProducerError> {
        if validators.is_empty() {
            return Err(ProducerError::EmptyValidatorSet);
        }

        let len = validators.len() as u64;
        let index = (((height.saturating_sub(1)) + round as u64) % len) as usize;
        let proposer_address = validators[index].address.clone();

        Ok(ProposerSelection {
            proposer_index: index,
            proposer_address,
        })
    }

    /// Check whether `local_address` is the designated proposer for `(height, round)`.
    pub fn is_designated_proposer(
        &self,
        height: u64,
        round: u32,
        local_address: &str,
        validators: &[ValidatorIdentity],
    ) -> Result<bool, ProducerError> {
        if validators.is_empty() {
            return Err(ProducerError::EmptyValidatorSet);
        }

        if !validators.iter().any(|v| v.address == local_address) {
            return Err(ProducerError::LocalValidatorNotInSet {
                local_address: local_address.to_string(),
            });
        }

        let selection = self.select_proposer(height, round, validators)?;
        Ok(selection.is_local(local_address))
    }

    /// Attempt to produce a proposal for the given consensus round.
    ///
    /// Returns:
    /// - `Ok(Some((proposal, block)))` if the local node is the designated proposer
    ///   and a block was built successfully.
    /// - `Ok(None)` if the local node is not the proposer, already proposed, or
    ///   empty blocks are disallowed and there are no mempool txs.
    /// - `Err(...)` if configuration is invalid or block/signing fails.
    ///
    /// # Notes
    /// The caller / consensus engine is still responsible for:
    /// - ensuring it is in the correct consensus step,
    /// - storing the block,
    /// - broadcasting the proposal,
    /// - tracking proposal state.
    ///
    /// # Assumptions about `Signer`
    /// This implementation assumes:
    /// - `signer.public_key()` returns `S::PublicKey`
    /// - `signer.sign(&[u8]) -> Result<Vec<u8>, _>`
    ///
    /// If your concrete `Signer` trait differs, only the signature/public-key calls
    /// need adapting.
    pub fn try_produce<S: Signer>(
        &self,
        height: u64,
        round: u32,
        valid_round: Option<u32>,
        prev_block_id: [u8; 32],
        app_state: &AppState,
        base_fee: u64,
        signer: &S,
        proposer_addr: &str,
        proposer_pubkey_bytes: Vec<u8>,
        validators: &[ValidatorIdentity],
        mempool_txs: &[Tx],
        already_proposed: bool,
    ) -> Result<Option<(Proposal<S::PublicKey>, Block)>, ProducerError> {
        if self.cfg.max_txs == 0 {
            return Err(ProducerError::InvalidMaxTxs);
        }

        if already_proposed {
            return Ok(None);
        }

        if !self.is_designated_proposer(height, round, proposer_addr, validators)? {
            return Ok(None);
        }

        if mempool_txs.is_empty() && !self.cfg.allow_empty_blocks {
            return Ok(None);
        }

        let txs: Vec<Tx> = mempool_txs
            .iter()
            .take(self.cfg.max_txs)
            .cloned()
            .collect();

        let (block, _next_state, _receipts) = build_block(
            height,
            round,
            prev_block_id,
            proposer_pubkey_bytes,
            proposer_addr,
            app_state,
            base_fee,
            txs,
        )
        .map_err(|e| ProducerError::BlockBuildFailed {
            message: e.to_string(),
        })?;

        let block_id = block.id();

        let sign_bytes = proposal_sign_bytes(
            height,
            round,
            &block_id,
            valid_round.map(|r| r as i32),
        );

        let signature = signer
            .sign(&sign_bytes)
            .map_err(|e| ProducerError::SigningFailed {
                message: e.to_string(),
            })?;

        let proposal = Proposal {
            height,
            round,
            proposer: signer.public_key(),
            block_id,
            block: if self.cfg.include_block_in_proposal {
                Some(block.clone())
            } else {
                None
            },
            pol_round: valid_round.map(|r| r as i32),
            signature,
        };

        Ok(Some((proposal, block)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockPubKey(Vec<u8>);

    #[derive(Clone, Debug)]
    struct MockSigner {
        pubkey: MockPubKey,
    }

    impl MockSigner {
        fn new(bytes: &[u8]) -> Self {
            Self {
                pubkey: MockPubKey(bytes.to_vec()),
            }
        }
    }

    // NOTE:
    // These tests assume a Signer trait roughly like:
    //
    // trait Signer {
    //     type PublicKey: Clone;
    //     fn public_key(&self) -> Self::PublicKey;
    //     fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    // }
    //
    // If your actual Signer trait differs, adapt the mock below.

    impl Signer for MockSigner {
        type PublicKey = MockPubKey;

        fn public_key(&self) -> Self::PublicKey {
            self.pubkey.clone()
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut out = b"sig:".to_vec();
            out.extend_from_slice(msg);
            Ok(out)
        }
    }

    fn validators() -> Vec<ValidatorIdentity> {
        vec![
            ValidatorIdentity::new("val1"),
            ValidatorIdentity::new("val2"),
            ValidatorIdentity::new("val3"),
        ]
    }

    #[test]
    fn test_select_proposer_round_robin() {
        let producer = SimpleBlockProducer::default();
        let vals = validators();

        let s1 = producer.select_proposer(1, 0, &vals).unwrap();
        let s2 = producer.select_proposer(1, 1, &vals).unwrap();
        let s3 = producer.select_proposer(1, 2, &vals).unwrap();
        let s4 = producer.select_proposer(2, 0, &vals).unwrap();

        assert_eq!(s1.proposer_address, "val1");
        assert_eq!(s2.proposer_address, "val2");
        assert_eq!(s3.proposer_address, "val3");
        assert_eq!(s4.proposer_address, "val2");
    }

    #[test]
    fn test_select_proposer_empty_set() {
        let producer = SimpleBlockProducer::default();
        let err = producer.select_proposer(1, 0, &[]).unwrap_err();
        assert!(matches!(err, ProducerError::EmptyValidatorSet));
    }

    #[test]
    fn test_is_designated_proposer_true() {
        let producer = SimpleBlockProducer::default();
        let vals = validators();

        assert!(producer
            .is_designated_proposer(1, 0, "val1", &vals)
            .unwrap());
    }

    #[test]
    fn test_is_designated_proposer_false() {
        let producer = SimpleBlockProducer::default();
        let vals = validators();

        assert!(!producer
            .is_designated_proposer(1, 0, "val2", &vals)
            .unwrap());
    }

    #[test]
    fn test_is_designated_proposer_not_in_set() {
        let producer = SimpleBlockProducer::default();
        let vals = validators();

        let err = producer
            .is_designated_proposer(1, 0, "unknown", &vals)
            .unwrap_err();

        assert!(matches!(
            err,
            ProducerError::LocalValidatorNotInSet { .. }
        ));
    }

    #[test]
    fn test_cfg_default() {
        let cfg = SimpleProducerCfg::default();
        assert_eq!(cfg.max_txs, 4096);
        assert!(cfg.include_block_in_proposal);
        assert!(cfg.allow_empty_blocks);
    }

    #[test]
    fn test_invalid_max_txs_rejected() {
        let producer = SimpleBlockProducer::new(SimpleProducerCfg {
            max_txs: 0,
            include_block_in_proposal: true,
            allow_empty_blocks: true,
        });

        let signer = MockSigner::new(&[1, 2, 3]);
        let vals = validators();

        let res = producer.try_produce(
            1,
            0,
            None,
            [0u8; 32],
            &AppState::default(),
            1,
            &signer,
            "val1",
            vec![1, 2, 3],
            &vals,
            &[],
            false,
        );

        assert!(matches!(res.unwrap_err(), ProducerError::InvalidMaxTxs));
    }

    #[test]
    fn test_returns_none_if_already_proposed() {
        let producer = SimpleBlockProducer::default();
        let signer = MockSigner::new(&[1, 2, 3]);
        let vals = validators();

        let res = producer
            .try_produce(
                1,
                0,
                None,
                [0u8; 32],
                &AppState::default(),
                1,
                &signer,
                "val1",
                vec![1, 2, 3],
                &vals,
                &[],
                true,
            )
            .unwrap();

        assert!(res.is_none());
    }

    #[test]
    fn test_returns_none_if_not_proposer() {
        let producer = SimpleBlockProducer::default();
        let signer = MockSigner::new(&[1, 2, 3]);
        let vals = validators();

        let res = producer
            .try_produce(
                1,
                0,
                None,
                [0u8; 32],
                &AppState::default(),
                1,
                &signer,
                "val2",
                vec![1, 2, 3],
                &vals,
                &[],
                false,
            )
            .unwrap();

        assert!(res.is_none());
    }

    #[test]
    fn test_returns_none_if_empty_blocks_disabled_and_no_txs() {
        let producer = SimpleBlockProducer::new(SimpleProducerCfg {
            max_txs: 100,
            include_block_in_proposal: true,
            allow_empty_blocks: false,
        });

        let signer = MockSigner::new(&[1, 2, 3]);
        let vals = validators();

        let res = producer
            .try_produce(
                1,
                0,
                None,
                [0u8; 32],
                &AppState::default(),
                1,
                &signer,
                "val1",
                vec![1, 2, 3],
                &vals,
                &[],
                false,
            )
            .unwrap();

        assert!(res.is_none());
    }

    // Integration-style test for successful production is intentionally omitted
    // here because it depends on the concrete crate implementations of:
    // - AppState::default()
    // - Tx construction
    // - build_block(...)
    // - Proposal field types
    //
    // Once those are fixed in your codebase, add:
    // - success path test
    // - tx truncation to max_txs
    // - include_block_in_proposal true/false
    // - valid_round propagation
}
