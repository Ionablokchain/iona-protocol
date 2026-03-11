# Iona Protocol

Iona is an open-source protocol and infrastructure project focused on deterministic execution, validator reliability, upgrade safety, and reproducible multi-node operation.

Rather than positioning itself as a generic new blockchain, Iona is being developed as a systems-oriented protocol stack for validating core distributed ledger behavior under real operational conditions: execution determinism, peer reliability, storage safety, restart/recovery correctness, and protocol upgrade discipline.

This repository contains the active implementation, validation work, and operational documentation for the current Iona development line.

## What Iona is optimizing for

The current development line is centered on four core goals:

- **deterministic execution** across environments
- **reliable validator operation** under realistic network conditions
- **safe protocol evolution** through explicit upgrade and migration checks
- **reproducible deployment** of a controlled multi-node testnet

The near-term objective is to reach a clean, reproducible build and validate core protocol behavior in a controlled validator testnet environment.

## Current Development Focus

Iona is currently focused on protocol hardening and staged testnet readiness.

Main engineering priorities:

1. stabilize the build across protocol-support modules
2. strengthen deterministic execution and validation workflows
3. validate protocol upgrade safety through simulation and migration checks
4. prepare and document controlled multi-validator testnet deployment
5. improve operational reliability around restart, recovery, storage, and peer behavior

This phase prioritizes **correctness, reproducibility, safety, and operational clarity** over premature feature expansion.

## Repository Direction

This repository is being prepared to demonstrate:

- protocol engineering discipline
- deterministic execution awareness
- validator and operator reliability
- explicit upgrade-safety validation
- structured recovery and storage behavior
- reproducible testnet deployment workflows

The goal is not to optimize for superficial feature count, but to make protocol behavior easier to validate, operate, and evolve safely.

## Quick Validation Path

The fastest way to understand the repository is to validate one focused path end-to-end:

1. **review the architecture and current direction**  
   Start with [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/roadmap.md`](docs/roadmap.md).

2. **review the controlled testnet plan**  
   Read [`docs/testnet-plan.md`](docs/testnet-plan.md) and [`docs/TESTNET.md`](docs/TESTNET.md) to understand the staged validator topology and deployment flow.

3. **review upgrade-safety expectations**  
   See [`docs/upgrade.md`](docs/upgrade.md) for version transition, rollback, migration, and post-upgrade verification requirements.

4. **inspect validation and issue grouping**  
   Use [`docs/issue-map.md`](docs/issue-map.md) to understand the current engineering areas around determinism, networking, storage, and recovery.

5. **trace the active implementation**  
   The repository is organized so that protocol core, execution, networking, persistence, RPC, and validation tooling can be reviewed as separate but related parts of the current development line.

This validation path is intentionally documentation-first because the current phase is centered on reproducibility, safety, and controlled operational validation rather than premature deployment claims.

## Architecture

At a high level, Iona is organized around the following areas:

- protocol core
- execution layer
- node runtime
- networking layer
- persistence layer
- RPC layer
- validation and safety tooling
- operational documentation and deployment guidance

The architecture is being shaped around:

- deterministic state progression
- reliable validator operation
- safe protocol upgrades
- repeatable deployment procedures
- controlled multi-node testing

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture overview.

## Validation and Safety

A major part of the current work is focused on validation, reproducibility, and failure handling.

This includes work around:

- deterministic build verification
- execution reproducibility across environments
- state root consistency checks
- storage and recovery safety
- validator peer reliability
- protocol upgrade simulation
- rollback and migration validation
- fuzzing and failure-oriented testing

These areas are treated as first-class engineering concerns, not as post-testnet cleanup.

## Controlled Testnet Direction

The current testnet strategy is intentionally staged and controlled.

Initial target topology:

- **4 validator nodes**
- **1 RPC / observer / seed node**

The first testnet phase is intended to validate:

- peer connectivity
- block production
- sync correctness
- restart and recovery behavior
- deployment reproducibility
- operational consistency across nodes

Relevant documents:

- [`docs/testnet-plan.md`](docs/testnet-plan.md) — initial deployment plan
- [`docs/TESTNET.md`](docs/TESTNET.md) — operational testnet guide

## Upgrade Safety

Protocol upgrades are treated as a high-risk operation and are approached with explicit validation requirements.

Current upgrade-related work is focused on:

- version transition testing
- backward compatibility checks
- rollback validation
- schema migration validation
- deterministic post-upgrade state verification

The goal is to make protocol evolution measurable and testable before broader deployment.

See [`docs/upgrade.md`](docs/upgrade.md) for the current upgrade safety process.

## Roadmap

The current roadmap is focused on:

- build and reproducibility
- core reliability
- networking and validator stability
- storage and recovery behavior
- RPC and execution stabilization
- upgrade safety
- testnet readiness
- validation and testing
- documentation and operational clarity

See [`docs/roadmap.md`](docs/roadmap.md) for the full roadmap.

## Open Engineering Areas

Current engineering work includes:

- deterministic build verification
- state root reproducibility across environments
- validator peer scoring and isolation
- network partition simulation
- storage corruption detection and recovery
- structured logging improvements
- fuzz coverage expansion
- keystore hardening and environment isolation
- protocol upgrade simulation and rollback validation

See [`docs/issue-map.md`](docs/issue-map.md) for grouped engineering work.

## Project Documentation

Key project documents:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — protocol and system architecture
- [`docs/TESTNET.md`](docs/TESTNET.md) — operational testnet guide
- [`docs/testnet-plan.md`](docs/testnet-plan.md) — initial testnet deployment plan
- [`docs/upgrade.md`](docs/upgrade.md) — protocol upgrade safety process
- [`docs/roadmap.md`](docs/roadmap.md) — project roadmap
- [`docs/issue-map.md`](docs/issue-map.md) — grouped engineering work

## Current Status

Iona is under active development and currently in a protocol-hardening and controlled-testnet-preparation phase.

Interfaces, internal modules, validation tooling, and operational procedures may continue to evolve as the project moves toward a more stable multi-validator testnet.

At this stage, the emphasis remains on:

- correctness
- reproducibility
- safety
- operational discipline
- controlled protocol evolution

## License

Apache-2.0 (see `LICENSE`)
