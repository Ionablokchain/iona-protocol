# IONA Enterprise Pack

Professional-grade tooling and support for validators, exchanges, and infrastructure operators running IONA in production.

---

## What's Included

### 1. HSM/KMS Integration

Full hardware security module and key management service support, enabling validators to keep private keys offline.

- **HashiCorp Vault Transit**: Encrypt/decrypt operations via Vault; keys never leave the HSM
- **AWS KMS**: Native integration for AWS-hosted validators
- **GCP Cloud KMS**: For Google Cloud deployments
- **PKCS#11 Interface**: Generic hardware HSM support (YubiHSM, Thales, etc.)
- **Key Rotation**: Automated cert rotation and key versioning

See `docs/VALIDATOR_KEYS.md` for setup guides.

### 2. Certificate Management

Automated mTLS certificate lifecycle management for admin authentication and inter-validator communication.

- **ACME Integration**: Automatic Let's Encrypt certificate provisioning
- **Cert Expiry Alerts**: Prometheus alerts 30 days before expiry
- **Rotation Playbooks**: Zero-downtime certificate rotation
- **Chain Bundling**: Multi-level CA support

### 3. Managed Upgrades

Coordinated rolling upgrades with automated canary deployments and instant rollback.

- **Upgrade Playbooks**: Test plans and rollout procedures
- **Canary Deployment Scripts**: Test upgrades on 1 node before fleet-wide rollout
- **One-Click Rollback**: Revert to previous version in seconds if needed
- **Upgrade Scheduling**: Coordinate upgrades across validator networks
- **Downtime-Zero Upgrades**: For non-consensus-critical updates

### 4. Advanced Monitoring Pack

Pre-built dashboards, SLO tracking, and incident alerting integrated with your existing stacks.

- **Grafana Dashboards**: Validator health, consensus metrics, peer connectivity, RPC latency
- **PagerDuty Integration**: Automatic incident creation for critical alerts
- **OpsGenie Integration**: Escalation policies and on-call schedules
- **SLO Dashboard**: Uptime, block signing rate, RPC availability tracking
- **Capacity Planning**: Storage, network, and compute forecasting
- **Custom Alert Rules**: Context-aware thresholds for your infrastructure

See `ops/monitoring-quickstart.md` for 5-minute setup.

### 5. Compliance Exports

Weekly audit log exports with GPG signing and multi-format support for regulatory compliance.

- **Destination Support**: S3, GCS, Azure Blob Storage
- **Formats**: JSON (native), CSV (spreadsheet-friendly)
- **Signing**: GPG-signed exports for audit trail integrity
- **Retention**: Automatic retention policies (default: 7 years)
- **Field Selection**: Choose which fields to export (ledger flexibility)

### 6. Custom RBAC Policies

Attribute-based access control with SSO integration for enterprise user management.

- **Policy-as-Code**: Define access rules in YAML
- **SAML 2.0**: Enterprise SSO integration (Okta, Azure AD, etc.)
- **OIDC**: OpenID Connect providers (Auth0, Keycloak, etc.)
- **Attribute Mapping**: Grant roles based on LDAP attributes
- **Audit Logging**: All role assignments logged in hashchain

### 7. Priority CVE Response

Accelerated patching for critical vulnerabilities in IONA and its upstream dependencies.

- **24h SLA**: Critical patches released within 24 hours of discovery
- **Dependency Monitoring**: Automated alerts for CVEs in Rust crates and system libraries
- **Coordinated Disclosure**: Private notification before public release
- **Backport Policy**: Patches available for current and previous major versions

### 8. Dedicated Support

Direct access to IONA engineers via private Slack/Telegram channel.

- **Named Engineer**: Same person handles your tickets for continuity
- **4h Response SLA**: Critical issues get human response within 4 hours
- **Monthly Calls**: Architecture review and capacity planning
- **Escalation Path**: Direct line to IONA core team if needed
- **Incident Management**: We help you debug production issues in real-time

---

## Deployment Reference Architectures

Enterprise Pack includes three tested architectures for different scales.

### Architecture A: Single Validator + Sentry (Small Operator)

**Topology**: 1 validator node + 1 sentry node on separate machines

**Use case**: Small validators (< 10 delegators), minimal infrastructure

**Components**:
- Validator node (signing keys in memory, mTLS admin auth)
- Sentry node (public P2P, filters incoming connections)
- Prometheus scraper (single box)
- Grafana dashboard (local port 3000)

**Files**: `deploy/validator/single-sentry/`

**Estimated cost**: $200-500/month (2x small VMs)

### Architecture B: 3-Node Validator Cluster + Sentry Pair (Mid-Size)

**Topology**: 3 validator nodes (1 active, 2 warm standby) + 2 sentry nodes + monitoring stack

**Use case**: Medium validators (1000+ delegators), institutional operators, HA requirements

**Components**:
- Validator cluster (primary + 2 replicas, shared signing WAL on NFS)
- 2x sentry nodes (load-balanced P2P)
- Prometheus + Grafana + AlertManager stack (dedicated box)
- EBS volumes for WAL persistence

**Files**: `deploy/validator/ha-cluster/`

**Estimated cost**: $2000-3000/month (5x medium VMs + NFS + monitoring)

**Failover**: Automatic via shared WAL; primary goes down, replica takes over within 10s

### Architecture C: Multi-Region Active-Passive (Institutional)

**Topology**: Region A (active) + Region B (warm standby), dedicated admin bastion, HSM-backed keys

**Use case**: Large institutional validators, regulatory requirements, disaster recovery

**Components**:
- Primary region: 3-node validator cluster + 2 sentries (see Architecture B)
- Backup region: standby validator (no active signing, can be promoted)
- Admin bastion: hardened jump host with HSM or remote signer
- Audit logging: CloudTrail / GCS Audit Logs + IONA audit log exports to S3
- Disaster recovery: automated backup sync, RTO < 1 hour

**Files**: `deploy/validator/multi-region/`

**Estimated cost**: $5000-8000/month (all infrastructure across 2 regions)

**Recovery**: If Region A fails, promote Region B replica; signing resumes in < 2 minutes

---

## SLA Commitments

Enterprise Pack customers receive the following guarantees:

| Tier | Response Time | Availability SLA | Patch SLA |
|------|---|---|---|
| Professional | 48h | None | Best-effort |
| Enterprise | 4h | 99.5% (14.4h downtime/month) | 24h for critical CVEs |

**Availability** is measured as:
- Validator produces at least 1 block per epoch (30s)
- RPC endpoint responds to health check (GET /_health)
- Measured over rolling 30-day period

**Exclusions**: Hardware failure, ISP outages, misconfiguration by customer (we'll help debug but don't cover SLA)

---

## Onboarding Process

Enterprise Pack customers follow a structured onboarding:

### Step 1: Sign Enterprise License Agreement

- Review and sign the IONA Enterprise License Agreement
- Specify your validator count, regions, and support tier
- Typical timeline: 2-5 days

### Step 2: Configure mTLS Certs and RBAC Policy

- Generate or provide CSR for admin mTLS certificate
- Define RBAC roles (Auditor, Operator, Maintainer)
- Configure SSO (optional; SAML/OIDC setup call)
- Typical timeline: 1 day (coordination call + implementation)

### Step 3: Deploy with --profile hard

```bash
iona init --profile hard                    # Hardened defaults
iona node --config config-enterprise.toml   # Enterprise-grade config
```

Deploys with:
- mTLS admin authentication (cert-required)
- Audit logging enabled (BLAKE3 hashchain)
- Enhanced DoS limits
- Prometheus metrics on 0.0.0.0:9090 (requires mTLS)

### Step 4: Connect Monitoring Stack

- Deploy Prometheus scraper (pre-built config provided)
- Import Grafana dashboards (CycloneDX bundle)
- Configure PagerDuty / OpsGenie integrations
- Test alert routing with dry-run
- Typical timeline: 2-4 hours

### Step 5: Tabletop Exercise (Disaster Recovery Simulation)

- We simulate a validator failure or network split
- Your team follows runbooks (ops/runbooks/)
- We observe and provide feedback
- Results documented in post-incident review
- Typical timeline: 2 hours scheduled

**Total onboarding**: 5-10 business days from contract signature to production readiness

---

## Getting Started

1. Email **enterprise@example.invalid** with your organization details and infrastructure setup
2. Schedule a discovery call with our sales team
3. Receive a customized quote based on your validator count and support tier
4. Follow the onboarding process above

For open source (free) deployments, see `PRICING.md` and `docs/QUICKSTART.md`.
