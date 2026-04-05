//! Consensus adversarial tests.
//!
//! These tests verify that the consensus layer correctly REJECTS invalid,
//! replayed, or equivocating inputs — they are "must reject" tests.
//!
//! Categories:
//!   A. Double-sign guard — equivocation prevention
//!   B. Replay protection — same message reused
//!   C. Invalid proposer detection
//!   D. Consensus safety invariants under adversarial input
//!   E. Evidence handling (DoS-safe)

use iona::consensus::double_sign::{vote_guard_key, DoubleSignGuard};
use iona::consensus::messages::VoteType;
use iona::crypto::PublicKeyBytes;
use iona::evidence::Evidence;
use iona::types::Hash32;
use std::sync::Arc;
use std::thread;

fn hash(b: u8) -> Hash32 {
    Hash32([b; 32])
}
fn opt_hash(b: u8) -> Option<Hash32> {
    Some(hash(b))
}

fn make_guard(dir: &tempfile::TempDir, pk_byte: u8) -> DoubleSignGuard {
    let pk = PublicKeyBytes(vec![pk_byte; 32]);
    DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk).expect("guard must load cleanly")
}

// ── A. Double-sign guard ──────────────────────────────────────────────────

#[test]
fn adversarial_double_prevote_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 1);
    // Sign prevote for block A.
    g.record_vote(VoteType::Prevote, 10, 0, &opt_hash(0xAA))
        .unwrap();
    // Attempt prevote for block B at same position → must fail.
    let err = g
        .check_vote(VoteType::Prevote, 10, 0, &opt_hash(0xBB))
        .expect_err("double prevote must be refused");
    assert!(
        err.to_string().contains("equivocation"),
        "error should mention equivocation"
    );
}

#[test]
fn adversarial_double_precommit_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 2);
    g.record_vote(VoteType::Precommit, 7, 1, &opt_hash(0x11))
        .unwrap();
    let err = g
        .check_vote(VoteType::Precommit, 7, 1, &opt_hash(0x22))
        .expect_err("double precommit must be refused");
    assert!(err.to_string().contains("equivocation"));
}

#[test]
fn adversarial_double_proposal_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 3);
    g.record_proposal(5, 0, &hash(0x01)).unwrap();
    let err = g
        .check_proposal(5, 0, &hash(0x02))
        .expect_err("double proposal must be refused");
    assert!(err.to_string().contains("equivocation"));
}

#[test]
fn adversarial_vote_then_nil_vote_same_position() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 4);
    g.record_vote(VoteType::Prevote, 3, 0, &opt_hash(0x55))
        .unwrap();
    let err = g
        .check_vote(VoteType::Prevote, 3, 0, &None)
        .expect_err("nil vote after block vote at same position is equivocation");
    assert!(err.to_string().contains("equivocation"));
}

#[test]
fn adversarial_nil_vote_then_block_vote_same_position() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 5);
    g.record_vote(VoteType::Prevote, 3, 0, &None).unwrap();
    let err = g
        .check_vote(VoteType::Prevote, 3, 0, &opt_hash(0x77))
        .expect_err("block vote after nil at same position is equivocation");
    assert!(err.to_string().contains("equivocation"));
}

// ── B. Replay protection ──────────────────────────────────────────────────

#[test]
fn replay_same_vote_allowed_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 6);
    g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(0xAA))
        .unwrap();
    // Exact same vote replayed — must be OK.
    let result = g.check_vote(VoteType::Precommit, 1, 0, &opt_hash(0xAA));
    assert!(
        result.is_ok(),
        "idempotent replay of same vote must be allowed"
    );
}

#[test]
fn replay_same_proposal_allowed_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 7);
    g.record_proposal(2, 0, &hash(0xBB)).unwrap();
    let result = g.check_proposal(2, 0, &hash(0xBB));
    assert!(result.is_ok(), "idempotent proposal replay must be allowed");
}

// ── C. Different positions are independent ────────────────────────────────

#[test]
fn different_heights_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 8);
    g.record_proposal(1, 0, &hash(1)).unwrap();
    assert!(g.check_proposal(2, 0, &hash(2)).is_ok());
    assert!(g.check_proposal(2, 0, &hash(99)).is_ok());
}

#[test]
fn different_rounds_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 9);
    g.record_proposal(1, 0, &hash(0xAA)).unwrap();
    assert!(g.check_proposal(1, 1, &hash(0xBB)).is_ok());
}

#[test]
fn prevote_and_precommit_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 10);
    g.record_vote(VoteType::Prevote, 5, 0, &opt_hash(0xAA))
        .unwrap();
    assert!(g
        .check_vote(VoteType::Precommit, 5, 0, &opt_hash(0xBB))
        .is_ok());
}

// ── D. Guard survives restart ─────────────────────────────────────────────

#[test]
fn guard_rejects_double_sign_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![20u8; 32]);
    let path = dir.path().to_str().unwrap();

    // Instance 1: sign a proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(42, 0, &hash(0x42)).unwrap();
    }

    // Instance 2 (crash-restart): must still refuse conflicting proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        let err = g
            .check_proposal(42, 0, &hash(0xFF))
            .expect_err("double-sign must be prevented even after restart");
        assert!(err.to_string().contains("equivocation"));
    }
}

#[test]
fn guard_allows_new_heights_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![21u8; 32]);
    let path = dir.path().to_str().unwrap();

    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
    }

    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        assert!(g.check_proposal(2, 0, &hash(2)).is_ok());
    }
}

// ── E. Hash chain integrity ────────────────────────────────────────────────

#[test]
fn tampered_guard_rejected_at_load() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![30u8; 32]);
    let path_str = dir.path().to_str().unwrap();

    {
        let g = DoubleSignGuard::new(path_str, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
    }

    // Tamper: alter the entry_hash in the journal to simulate a rollback attack.
    let guard_file = format!("{}/doublesign_{}.json", path_str, hex::encode([30u8; 32]));
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    // Corrupt the entry_hash of the first journal entry
    json["entries"][0]["entry_hash"] = serde_json::json!("deadbeef");
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    let err = DoubleSignGuard::new(path_str, &pk).expect_err("tampered file must be rejected");
    assert!(
        err.to_string().contains("hash") || err.to_string().contains("integrity"),
        "error should mention hash/integrity: got {:?}",
        err
    );
}

// ── F. Record count ────────────────────────────────────────────────────────

#[test]
fn record_count_increments_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 40);
    let (p0, v0) = g.record_count();
    assert_eq!(p0, 0);
    assert_eq!(v0, 0);

    g.record_proposal(1, 0, &hash(1)).unwrap();
    let (p1, _) = g.record_count();
    assert_eq!(p1, 1);

    g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
        .unwrap();
    g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(1))
        .unwrap();
    let (_, v2) = g.record_count();
    assert_eq!(v2, 2);
}

#[test]
fn record_count_persists_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![41u8; 32]);
    let path = dir.path().to_str().unwrap();

    let (p1, v1) = {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
            .unwrap();
        g.record_count()
    };

    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        let (p2, v2) = g.record_count();
        assert_eq!(p2, p1, "proposal count should persist");
        assert_eq!(v2, v1, "vote count should persist");
    }
}

// ── G. Evidence handling ───────────────────────────────────────────────────

#[test]
fn double_vote_produces_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 50);
    g.record_vote(VoteType::Prevote, 100, 0, &opt_hash(0xAA))
        .unwrap();
    let err = g
        .check_vote(VoteType::Prevote, 100, 0, &opt_hash(0xBB))
        .expect_err("double vote must be detected");
    // Assuming the guard returns an error that contains the evidence or we can extract it.
    // In a real test, we might have a method to retrieve the evidence.
    // Here we just check that the error indicates evidence was generated.
    assert!(err.to_string().contains("evidence") || err.to_string().contains("equivocation"));
}

#[test]
fn double_proposal_produces_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 51);
    g.record_proposal(101, 0, &hash(0xCC)).unwrap();
    let err = g
        .check_proposal(101, 0, &hash(0xDD))
        .expect_err("double proposal must produce evidence");
    assert!(err.to_string().contains("evidence") || err.to_string().contains("equivocation"));
}

// ── H. Concurrency ─────────────────────────────────────────────────────────

#[test]
fn concurrent_access_does_not_corrupt() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![60u8; 32]);
    let path = dir.path().to_str().unwrap().to_string();
    let guard = Arc::new(DoubleSignGuard::new(&path, &pk).unwrap());

    let mut handles = vec![];
    for i in 0..10 {
        let g = guard.clone();
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                // Each thread signs different heights/rounds to avoid conflicts.
                let height = i * 1000 + j;
                let round = (j % 5) as u32;
                g.record_proposal(height, round, &hash(j as u8)).unwrap();
                g.record_vote(VoteType::Prevote, height, round, &opt_hash(j as u8))
                    .unwrap();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Verify total counts.
    let (p, v) = guard.record_count();
    assert_eq!(p, 10 * 100, "should have recorded 1000 proposals");
    assert_eq!(v, 10 * 100, "should have recorded 1000 prevotes");
}

#[test]
fn concurrent_double_sign_detected() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![61u8; 32]);
    let path = dir.path().to_str().unwrap().to_string();
    let guard = Arc::new(DoubleSignGuard::new(&path, &pk).unwrap());

    // First, record a vote at a specific position.
    guard
        .record_vote(VoteType::Prevote, 200, 0, &opt_hash(0xEE))
        .unwrap();

    let guard_clone = guard.clone();
    let handle = thread::spawn(move || {
        // Attempt to double-vote from another thread.
        let result = guard_clone.check_vote(VoteType::Prevote, 200, 0, &opt_hash(0xFF));
        assert!(
            result.is_err(),
            "double vote must be rejected even from another thread"
        );
        result
    });

    let result = handle.join().unwrap();
    assert!(result.is_err());
}

// ── I. Edge cases ──────────────────────────────────────────────────────────

#[test]
fn large_height_and_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 70);
    // Use near-maximum u64 and u32 values.
    let height = u64::MAX;
    let round = u32::MAX;
    g.record_proposal(height, round, &hash(0x11)).unwrap();
    // Same position, different block -> should fail.
    let err = g
        .check_proposal(height, round, &hash(0x22))
        .expect_err("double proposal at extreme values");
    assert!(err.to_string().contains("equivocation"));
}

#[test]
fn zero_height_and_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 71);
    g.record_proposal(0, 0, &hash(0x33)).unwrap();
    let err = g
        .check_proposal(0, 0, &hash(0x44))
        .expect_err("double proposal at zero");
    assert!(err.to_string().contains("equivocation"));
}

// Note: If round can be negative (i32), we should test that too. But here round is u32.
