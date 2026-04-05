//! Evidence of consensus violations used for slashing.
//!
//! This module defines the types of slashable offenses:
//! - `DoubleVote`: voting for two different blocks in the same round.
//! - `DoubleProposal`: proposing two different blocks at the same height/round.

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::warn;

/// Evidence of a slashable consensus offense.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Evidence {
    /// A validator has signed two different votes at the same height and round.
    DoubleVote {
        /// The public key of the offending validator.
        voter: PublicKeyBytes,
        /// Height at which the double vote occurred.
        height: Height,
        /// Round at which the double vote occurred.
        round: Round,
        /// Type of vote (prevote or precommit).
        vote_type: VoteType,
        /// Block ID of the first vote (if any).
        a: Option<Hash32>,
        /// Block ID of the second vote (if any).
        b: Option<Hash32>,
        /// The raw first vote for auditability.
        vote_a: Vote,
        /// The raw second vote for auditability.
        vote_b: Vote,
    },

    /// A validator has proposed two different blocks at the same height and round.
    DoubleProposal {
        /// The public key of the offending proposer.
        proposer: PublicKeyBytes,
        /// Height at which the double proposal occurred.
        height: Height,
        /// Round at which the double proposal occurred.
        round: Round,
        /// Block ID of the first proposal (if any).
        a: Option<Hash32>,
        /// Block ID of the second proposal (if any).
        b: Option<Hash32>,
        /// The raw first proposal for auditability.
        proposal_a: Proposal,
        /// The raw second proposal for auditability.
        proposal_b: Proposal,
    },
}

impl Evidence {
    /// Returns the height of the offense.
    pub fn height(&self) -> Height {
        match self {
            Evidence::DoubleVote { height, .. } => *height,
            Evidence::DoubleProposal { height, .. } => *height,
        }
    }

    /// Returns the round of the offense.
    pub fn round(&self) -> Round {
        match self {
            Evidence::DoubleVote { round, .. } => *round,
            Evidence::DoubleProposal { round, .. } => *round,
        }
    }

    /// Returns the public key of the offending validator.
    pub fn offender(&self) -> &PublicKeyBytes {
        match self {
            Evidence::DoubleVote { voter, .. } => voter,
            Evidence::DoubleProposal { proposer, .. } => proposer,
        }
    }

    /// Computes a unique hash for this evidence to avoid double‑processing.
    pub fn hash(&self) -> Hash32 {
        use crate::types::hash_bytes;
        let bytes = match self {
            Evidence::DoubleVote {
                voter,
                height,
                round,
                vote_type,
                a,
                b,
                vote_a,
                vote_b,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"EVIDENCE_DOUBLE_VOTE");
                buf.extend_from_slice(voter.as_bytes());
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&round.to_le_bytes());
                buf.extend_from_slice(&[*vote_type as u8]);
                if let Some(h) = a {
                    buf.extend_from_slice(&h.0);
                }
                if let Some(h) = b {
                    buf.extend_from_slice(&h.0);
                }
                buf.extend_from_slice(&vote_a.hash().0);
                buf.extend_from_slice(&vote_b.hash().0);
                buf
            }
            Evidence::DoubleProposal {
                proposer,
                height,
                round,
                a,
                b,
                proposal_a,
                proposal_b,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"EVIDENCE_DOUBLE_PROPOSAL");
                buf.extend_from_slice(proposer.as_bytes());
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&round.to_le_bytes());
                if let Some(h) = a {
                    buf.extend_from_slice(&h.0);
                }
                if let Some(h) = b {
                    buf.extend_from_slice(&h.0);
                }
                buf.extend_from_slice(&proposal_a.hash().0);
                buf.extend_from_slice(&proposal_b.hash().0);
                buf
            }
        };
        hash_bytes(&bytes)
    }

    /// Basic sanity check: ensures the two votes/proposals are actually conflicting.
    pub fn is_valid(&self) -> bool {
        match self {
            Evidence::DoubleVote {
                vote_type,
                vote_a,
                vote_b,
                a,
                b,
                height,
                round,
                voter,
                ..
            } => {
                // Same height, round, voter, and vote type
                if vote_a.height != *height || vote_b.height != *height {
                    warn!("DoubleVote height mismatch");
                    return false;
                }
                if vote_a.round != *round || vote_b.round != *round {
                    warn!("DoubleVote round mismatch");
                    return false;
                }
                if vote_a.voter != *voter || vote_b.voter != *voter {
                    warn!("DoubleVote voter mismatch");
                    return false;
                }
                if vote_a.vote_type != *vote_type || vote_b.vote_type != *vote_type {
                    warn!("DoubleVote vote_type mismatch");
                    return false;
                }
                // The two block IDs must differ
                if let (Some(id_a), Some(id_b)) = (a, b) {
                    if id_a == id_b {
                        warn!("DoubleVote identical block IDs");
                        return false;
                    }
                } else if a.is_none() && b.is_none() {
                    // Both nil votes – not a double vote (but could be same round both nil?)
                    // Usually double vote means two non‑nil conflicting votes.
                    // We'll reject if both are nil.
                    warn!("DoubleVote both nil");
                    return false;
                }
                true
            }
            Evidence::DoubleProposal {
                proposal_a,
                proposal_b,
                a,
                b,
                height,
                round,
                proposer,
                ..
            } => {
                if proposal_a.height != *height || proposal_b.height != *height {
                    warn!("DoubleProposal height mismatch");
                    return false;
                }
                if proposal_a.round != *round || proposal_b.round != *round {
                    warn!("DoubleProposal round mismatch");
                    return false;
                }
                if proposal_a.proposer.0 != proposer.0
                    || proposal_b.proposer.0 != proposer.0
                {
                    warn!("DoubleProposal proposer mismatch");
                    return false;
                }
                if let (Some(id_a), Some(id_b)) = (a, b) {
                    if id_a == id_b {
                        warn!("DoubleProposal identical block IDs");
                        return false;
                    }
                }
                true
            }
        }
    }

    /// Factory: create a double‑vote evidence from two conflicting votes.
    /// Returns `None` if the votes are not from the same validator or do not conflict.
    pub fn from_votes(vote_a: Vote, vote_b: Vote) -> Option<Self> {
        if vote_a.voter != vote_b.voter {
            return None;
        }
        if vote_a.height != vote_b.height || vote_a.round != vote_b.round {
            return None;
        }
        if vote_a.vote_type != vote_b.vote_type {
            return None;
        }
        // Must be two different block IDs (or one nil, one non‑nil)
        let a = vote_a.block_id.clone();
        let b = vote_b.block_id.clone();
        if a == b {
            return None;
        }

        Some(Evidence::DoubleVote {
            voter: vote_a.voter.clone(),
            height: vote_a.height,
            round: vote_a.round,
            vote_type: vote_a.vote_type,
            a,
            b,
            vote_a,
            vote_b,
        })
    }

    /// Factory: create a double‑proposal evidence from two conflicting proposals.
    pub fn from_proposals(proposal_a: Proposal, proposal_b: Proposal) -> Option<Self> {
        if proposal_a.proposer.0 != proposal_b.proposer.0 {
            return None;
        }
        if proposal_a.height != proposal_b.height
            || proposal_a.round != proposal_b.round
        {
            return None;
        }
        let a = Some(proposal_a.block_id.clone());
        let b = Some(proposal_b.block_id.clone());
        if a == b {
            return None;
        }

        Some(Evidence::DoubleProposal {
            proposer: PublicKeyBytes(proposal_a.proposer.0.clone()),
            height: proposal_a.height,
            round: proposal_a.round,
            a,
            b,
            proposal_a,
            proposal_b,
        })
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Evidence::DoubleVote {
                voter,
                height,
                round,
                vote_type,
                a,
                b,
                ..
            } => {
                write!(
                    f,
                    "DoubleVote(voter={:?}, height={}, round={}, type={:?}, a={:?}, b={:?})",
                    voter, height, round, vote_type, a, b
                )
            }
            Evidence::DoubleProposal {
                proposer,
                height,
                round,
                a,
                b,
                ..
            } => {
                write!(
                    f,
                    "DoubleProposal(proposer={:?}, height={}, round={}, a={:?}, b={:?})",
                    proposer, height, round, a, b
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::messages::{Proposal, Vote, VoteType};
    use crate::types::{Block, BlockHeader, Hash32, Height, Round};

    fn dummy_vote(hash: Option<Hash32>, height: Height, round: Round, voter: &[u8]) -> Vote {
        Vote {
            voter: PublicKeyBytes(voter.to_vec()),
            height,
            round,
            vote_type: VoteType::Prevote,
            block_id: hash,
                        signature: crate::crypto::SignatureBytes(vec![]),
        }
    }

    fn dummy_proposal(hash: Hash32, height: Height, round: Round, proposer: &[u8]) -> Proposal {
        Proposal {
            height,
            round,
            proposer: crate::crypto::PublicKeyBytes(proposer.to_vec()),
            block_id: hash,
            pol_round: None,
            block: None,
            signature: crate::crypto::SignatureBytes(vec![]),
        }
    }

    #[test]
    fn test_double_vote_creation() {
        let voter = [1u8; 32];
        let hash1 = Some(Hash32([1; 32]));
        let hash2 = Some(Hash32([2; 32]));
        let vote1 = dummy_vote(hash1, 1, 0, &voter);
        let vote2 = dummy_vote(hash2, 1, 0, &voter);
        let ev = Evidence::from_votes(vote1.clone(), vote2.clone()).unwrap();
        assert!(ev.is_valid());
        assert_eq!(ev.height(), 1);
        assert_eq!(ev.round(), 0);
        assert_eq!(ev.offender(), &PublicKeyBytes(voter.to_vec()));
    }

    #[test]
    fn test_double_vote_same_hash_invalid() {
        let voter = [1u8; 32];
        let hash = Some(Hash32([1; 32]));
        let vote1 = dummy_vote(hash.clone(), 1, 0, &voter);
        let vote2 = dummy_vote(hash.clone(), 1, 0, &voter);
        assert!(Evidence::from_votes(vote1, vote2).is_none());
    }

    #[test]
    fn test_double_proposal_creation() {
        let proposer = [2u8; 32];
        let hash1 = Hash32([1; 32]);
        let hash2 = Hash32([2; 32]);
        let prop1 = dummy_proposal(hash1, 1, 0, &proposer);
        let prop2 = dummy_proposal(hash2, 1, 0, &proposer);
        let ev = Evidence::from_proposals(prop1.clone(), prop2.clone()).unwrap();
        assert!(ev.is_valid());
        assert_eq!(ev.height(), 1);
        assert_eq!(ev.round(), 0);
        assert_eq!(ev.offender(), &PublicKeyBytes(proposer.to_vec()));
    }

    #[test]
    fn test_hash_deterministic() {
        let voter = [1u8; 32];
        let hash1 = Some(Hash32([1; 32]));
        let hash2 = Some(Hash32([2; 32]));
        let vote1 = dummy_vote(hash1, 1, 0, &voter);
        let vote2 = dummy_vote(hash2, 1, 0, &voter);
        let ev = Evidence::from_votes(vote1, vote2).unwrap();
        let h1 = ev.hash();
        let h2 = ev.hash();
        assert_eq!(h1, h2);
    }
}
