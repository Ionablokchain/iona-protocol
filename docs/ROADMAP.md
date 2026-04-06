# IONA Roadmap

IONA is an experimental open-source framework focused on deterministic execution, reproducibility, and upgrade safety in distributed systems.

This roadmap reflects the current direction of the project and aligns the repository with its main research and engineering goals.

## Current Focus Areas

The current development effort is organized into three major tracks.

### 1. Deterministic Execution Validation

Goal:
Improve confidence that state transitions remain reproducible and deterministic across environments.

Current and planned work includes:

- cross-platform reproducibility testing
- deterministic replay verification tooling
- state root validation datasets
- execution trace comparison workflows
- validation of deterministic behavior under controlled environments

### 2. Upgrade Simulation Framework

Goal:
Provide tooling and workflows for testing protocol evolution before broader deployment.

Current and planned work includes:

- explicit protocol version activation logic
- schema version compatibility checks
- rolling upgrade test scenarios
- upgrade replay and migration validation
- failure-oriented testing for partial and interrupted upgrade paths

### 3. Protocol Documentation and Experimental Testnet

Goal:
Document protocol assumptions and provide a controlled environment for practical validation.

Current and planned work includes:

- documentation of protocol invariants
- documentation of security assumptions
- operator-oriented runbooks
- experimental deterministic testnet workflows
- local and multi-node validation environments

## Near-Term Priorities

The near-term priorities for the repository are:

- improve reproducibility verification coverage
- strengthen upgrade compatibility testing
- expand deterministic replay tooling
- improve operator-facing documentation
- refine experimental multi-node test environments

## Repository Status

IONA is under active development.

At the current stage, the project should be understood as:

- suitable for local development and controlled multi-node testing
- useful for research into deterministic execution and upgrade safety
- appropriate for architecture review and infrastructure experimentation
- not a final production deployment claim

## Non-Goals at the Current Stage

IONA is not currently presented as:

- a finalized production blockchain deployment
- a fully audited public-network system
- a complete guarantee of production safety under adversarial conditions

## Long-Term Direction

The long-term aim of IONA is to contribute reusable tools, methods, and documentation for:

- deterministic execution validation
- reproducible infrastructure workflows
- compatibility-aware protocol upgrades
- safer operator procedures for distributed systems

## Open Development

All core outputs are intended to remain available as open-source software and documentation under a permissive license.
