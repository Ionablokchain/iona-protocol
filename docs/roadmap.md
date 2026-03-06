# IONA Development Roadmap

This document outlines the current development stages and future direction of the IONA protocol.

IONA is being developed incrementally with a focus on deterministic execution, validator synchronization, and protocol correctness.

---

## Phase 1 — Core Protocol Foundation

Status: Completed

Objectives:

- core node implementation
- block structure and validation rules
- deterministic execution model
- peer-to-peer networking
- basic validator participation
- persistent state storage

Outcome:

A working node capable of running a small validator network.

---

## Phase 2 — Public Testnet

Status: Active

Objectives:

- deploy validator-based testnet
- validate peer-to-peer networking
- verify validator synchronization
- test deterministic block execution
- expose public RPC access
- monitor network stability

Current Testnet Infrastructure:

Validators:

val1 — 78.47.130.101  
val2 — 78.47.69.99  
val3 — 91.99.206.120  
val4 — 46.224.87.156  

RPC Node:

46.225.107.91

Goals of this phase:

- detect consensus inconsistencies
- test replay validation
- validate network stability
- improve operational tooling

---

## Phase 3 — Deterministic Validation Framework

Status: In Progress

Objectives:

- historical block replay testing
- state root reproducibility checks
- deterministic execution validation
- divergence detection across nodes
- logging of nondeterministic inputs

This phase focuses on improving protocol correctness guarantees.

---

## Phase 4 — Upgrade Simulation Environment

Status: Planned

Objectives:

- protocol version transition testing
- schema migration validation
- rolling upgrade simulations
- backward compatibility verification

Upgrade safety is critical before wider network adoption.

---

## Phase 5 — Observability and Monitoring

Status: Planned

Objectives:

- improved node metrics
- network observability
- validator performance tracking
- debugging tools for consensus behavior

These improvements help operators maintain reliable network nodes.

---

## Phase 6 — Security Hardening

Status: Planned

Objectives:

- protocol hardening
- adversarial testing scenarios
- fault injection testing
- external security review preparation

Security maturity increases before production deployment.

---

## Phase 7 — Expanded Testnet

Status: Future

Objectives:

- larger validator set
- external node operators
- broader network participation
- ecosystem experimentation

This stage prepares the protocol for wider adoption.

---

## Phase 8 — Mainnet Preparation

Status: Long-term

Objectives:

- finalize protocol rules
- verify deterministic execution
- finalize validator participation model
- operational readiness validation

Mainnet readiness requires stable deterministic behavior and consistent validator operation.

---

## Development Philosophy

IONA development follows several principles:

- correctness before complexity
- deterministic behavior across nodes
- transparent protocol design
- incremental testing via public testnet
- clear operational documentation

This approach helps ensure that protocol behavior remains predictable and verifiable.

---

## Summary

The IONA roadmap progresses through several stages:

1. core protocol implementation
2. validator-based public testnet
3. deterministic execution validation
4. upgrade safety testing
5. observability improvements
6. security hardening
7. expanded testnet participation
8. mainnet readiness

Development continues through iterative validation and testing of each phase.
