# Iona Testnet

## Overview

This document describes the operational purpose, structure, validation goals, and execution flow of the Iona testnet.

The testnet is intended to provide a controlled environment for validating protocol behavior before larger-scale rollout. Its purpose is not only to confirm that nodes can start, but to verify that the protocol behaves consistently across multiple nodes under realistic operational conditions.

The current focus is on:

- validator connectivity
- block production stability
- deterministic state progression
- restart and recovery behavior
- sync correctness
- deployment reproducibility
- readiness for future upgrade validation

## Testnet Goals

The Iona testnet is designed to validate the following areas:

- stable multi-validator network operation
- correct block production across nodes
- peer discovery and connectivity reliability
- consistent chain state progression
- safe node restart and recovery
- clean sync behavior for new or restarted nodes
- operational readiness for future scaling and upgrade testing

The testnet is also intended to support documentation, issue tracking, and grant-readiness by providing a reproducible validation path for the protocol.

## Current Testnet Scope

The current testnet scope is intentionally controlled.

Initial target topology:

- 4 validator nodes
- 1 RPC / observer / seed node

This initial phase is sufficient to validate core distributed behavior without introducing unnecessary operational complexity too early.

The testnet should first prove:

- validators can connect and remain connected
- blocks are produced consistently
- restart does not corrupt state
- a joining node can sync successfully
- the deployment process is repeatable

## Node Roles

## Validator Nodes

Validator nodes are responsible for:

- maintaining canonical state
- participating in protocol execution
- validating and applying chain transitions
- remaining consistent with the rest of the network
- recovering safely after restart

Each validator node should run:

- the same release candidate build
- the same genesis file
- standardized configuration format
- node-specific identity and networking parameters

## RPC / Observer Node

The RPC node is responsible for:

- exposing chain query endpoints
- providing visibility into network status
- supporting sync and health validation
- acting as a stable observer during test runs
- optionally serving as a bootstrap / seed node

Separating the observer/RPC role from validators improves operational clarity during debugging and rollout.

## Deployment Principles

The testnet should always follow these deployment rules:

- all nodes must run the same selected build
- genesis must be generated once and distributed identically
- chain ID must be identical across all nodes
- node configs should be standardized
- only role-specific fields should differ between nodes
- deployment steps should be documented and reproducible

A testnet run should never rely on undocumented manual steps if those steps can affect reproducibility.

## Infrastructure Assumptions

Each node should have:

- fixed hostname
- static public IP
- deployed Iona binary
- systemd service for lifecycle management
- open P2P ports
- RPC enabled on the observer node
- persistent data directory
- log access through journal or file-based logging

Recommended baseline requirements:

- enough CPU and memory for stable validator execution
- reliable disk storage for chain data
- consistent OS/runtime environment across nodes

## Release Candidate Discipline

Before testnet deployment:

1. choose a specific release candidate commit
2. build the binary from that commit
3. record the binary hash
4. deploy the same binary to all nodes
5. verify binary consistency across nodes
6. freeze the build during rollout

This avoids confusion between runtime failures and untracked code changes.

## Genesis Discipline

Genesis handling is a critical part of testnet correctness.

The process should be:

1. generate genesis once
2. define validator set explicitly
3. define chain ID explicitly
4. distribute the exact same genesis file to all nodes
5. verify the hash on every node before starting services

The testnet must not start unless genesis consistency has been confirmed.

## Network Topology

The initial topology should define:

- validator node names
- IP addresses
- P2P ports
- RPC ports
- bootnode / seed node role
- peer lists or bootstrap flow

Example role layout:

- `val1`
- `val2`
- `val3`
- `val4`
- `rpc1`

This layout is sufficient for the first controlled phase and can later be expanded.

## Launch Strategy

The recommended launch strategy is staged.

## Stage 1
Start:

- `rpc1`
- `val1`

Validate:

- process startup
- correct configuration load
- expected log output
- ports listening correctly

## Stage 2
Add:

- `val2`
- `val3`

Validate:

- peer discovery
- stable connectivity
- expected network formation
- normal block progression

## Stage 3
Add:

- `val4`

Validate:

- multi-validator stability
- continued block production
- no persistent network fragmentation
- no obvious state divergence

This staged approach reduces debugging complexity and makes failure isolation easier.

## Validation Areas

## 1. Genesis Consistency

Checks:

- identical genesis hash on all nodes
- identical chain ID on all nodes
- identical validator set initialization

Failure in this area invalidates the testnet immediately.

## 2. Binary Consistency

Checks:

- same build deployed on all nodes
- binary hash matches across all nodes
- no node runs an unintended local variant

This prevents false divergence caused by build mismatch.

## 3. Peer Connectivity

Checks:

- nodes discover peers correctly
- nodes maintain connections over time
- reconnect behavior is stable after temporary interruption
- seed/bootstrap flow works as expected

## 4. Block Production

Checks:

- block height increases consistently
- validators remain active
- no repeated block production failures appear
- no long unexplained stalls occur

## 5. State Progression

Checks:

- chain state advances consistently
- no node diverges from canonical progression
- state updates appear stable across validators

This area becomes especially important once deterministic replay and upgrade validation are integrated more deeply.

## 6. Restart and Recovery

Checks:

- stopped nodes restart cleanly
- restarted nodes rejoin without corruption
- persisted state loads successfully
- node resumes expected execution after restart

## 7. Sync Validation

Checks:

- a clean or lagging node can join and sync
- synchronized node matches current network state
- catch-up does not introduce divergence

## 8. RPC Validation

Checks:

- status and chain queries respond correctly
- block queries work on the observer node
- transaction and receipt queries behave as expected
- RPC reflects current network state

## Acceptance Criteria

A testnet run is considered successful only if:

- all intended nodes start successfully
- genesis is confirmed identical across all nodes
- peer connectivity remains stable
- blocks are produced consistently
- validator restart does not corrupt local state
- a joining or restarted node can sync correctly
- RPC on the observer node works correctly
- no state divergence is observed during the run

## Operational Checks

During each testnet run, monitor:

- process health
- block height
- peer count
- restart behavior
- sync progress
- persistent error logs
- CPU, RAM, and disk usage
- chain continuity after restarts

Operational observation is part of test validation, not a separate concern.

## Failure Conditions

A testnet run should be considered failed if any of the following occurs:

- mismatched genesis between nodes
- mismatched binary versions
- persistent peer connectivity failure
- repeated block production stalls
- corrupted state after restart
- failed sync for a new node
- unexplained divergence between nodes
- observer/RPC node unable to reflect current state reliably

## Logging and Evidence

Each testnet run should produce enough evidence to support later review.

Recommended evidence includes:

- node list and role mapping
- commit hash used for the build
- binary hash
- genesis hash
- start/stop times
- block height progression notes
- restart test results
- sync test results
- relevant logs for failures or anomalies

This documentation is useful for internal engineering review and external grant evaluation.

## Relationship to Other Validation Work

The testnet is only one part of the broader validation strategy.

It should be used alongside:

- deterministic build verification
- state root reproducibility checks
- structured logging improvements
- storage corruption detection and recovery
- network partition simulation
- protocol upgrade simulation and rollback validation

Together, these areas increase confidence that the protocol is not only functional, but also stable and safe to evolve.

## Future Testnet Expansion

Once the initial controlled testnet is stable, the next phases may include:

- more validator nodes
- more diverse infrastructure placement
- stronger monitoring and metrics
- staged upgrade testing
- partition and fault simulation
- more explicit state comparison workflows

The early testnet is intended as a disciplined foundation, not the final operational shape.

## Related Documentation

- [`README.md`](../README.md) — repository overview and current priorities
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — architectural direction
- [`docs/testnet-plan.md`](testnet-plan.md) — initial deployment plan
- [`docs/upgrade.md`](upgrade.md) — protocol upgrade safety process
- [`docs/issue-map.md`](issue-map.md) — grouped engineering work

## Status

The current testnet effort should be understood as an active readiness phase.

The immediate goal is to establish a clean, reproducible, and well-documented multi-node environment that validates:

- deployment consistency
- validator operation
- connectivity stability
- recovery safety
- sync correctness

This phase is a prerequisite for broader scaling, stronger automation, and future upgrade-oriented network validation.
