# IONA Monitoring Quickstart

**Get Prometheus + Grafana running in 5 minutes**

---

## Overview

IONA exposes rich operational metrics via Prometheus-compatible HTTP endpoint (`/metrics`).

**Metrics exposed**:
- Consensus: block height, round, voting power, peer connection health
- Mempool: transaction count, transaction bytes, eviction rate
- RPC: request latency (P50/P95/P99), error rate, rate-limit firing
- Networking: inbound/outbound peer count, bandwidth, connection churn
- System: WAL growth, disk I/O, memory usage, CPU

**Recommended stack**: Prometheus (time-series database) + Grafana (visualization) + AlertManager (incident routing)

---

## 5-Minute Setup

### Prerequisites

- Docker & Docker Compose (install from https://docs.docker.com/compose/install/)
- IONA node running with metrics enabled (default port 9090)
- 2 GB free disk space for Prometheus data

### Step 1: Pull Docker Images

```bash
docker pull prom/prometheus:latest
docker pull grafana/grafana:latest
docker pull prom/alertmanager:latest
```

### Step 2: Create Prometheus Config

Save this as `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'iona-validator'
    static_configs:
      - targets: ['localhost:9090']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

  - job_name: 'iona-sentry'
    static_configs:
      - targets: ['localhost:9091']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
```

Adjust targets to match your IONA node's metrics ports (default: 9090 for validator, 9091 for sentry).

### Step 3: Create Docker Compose File

Save as `docker-compose.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: iona-prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9000:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: iona-grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_USERS_ALLOW_SIGN_UP: 'false'
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped
    depends_on:
      - prometheus

  alertmanager:
    image: prom/alertmanager:latest
    container_name: iona-alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:
```

### Step 4: Start the Stack

```bash
docker-compose up -d

# Verify all services started
docker-compose ps
# All should show "Up"

# Check Prometheus is scraping
curl http://localhost:9000/api/v1/targets
# Should list your IONA node(s) with status "up"
```

### Step 5: Access Grafana UI

1. Open browser: http://localhost:3000
2. Login: admin / admin
3. Change password (you'll be prompted)
4. Add Prometheus data source (http://prometheus:9090)
5. Import IONA dashboard (see next section)

---

## Importing the Dashboard

IONA provides a pre-built Grafana dashboard for validators.

### Option A: Import JSON (Recommended)

1. In Grafana, click **+** → **Dashboard** → **Import**
2. Upload the JSON file: `ops/grafana/iona_validator_dashboard.json`
3. Select Prometheus as the data source
4. Click **Import**

The dashboard auto-populates with your metrics.

### Option B: Manual Import (CycloneDX Bundle)

If using the Enterprise Pack:

```bash
# Extract the dashboard bundle
tar xzf iona-enterprise-dashboards-v28.3.tar.gz

# Copy to Grafana container
docker cp iona_validator_dashboard.json iona-grafana:/grafana/dashboards/
```

---

## Key Metrics to Watch

These metrics indicate validator health. Set up alerts for values outside healthy range.

| Metric | What It Measures | Healthy Value | Alert Threshold |
|--------|-----------------|---------------|-----------------|
| `iona_peer_count` | Connected peers in your validator's peer table | ≥ 5 | < 3 (page on call), < 1 (critical) |
| `iona_consensus_height_lag` | How many blocks behind the network tip your validator is | 0 | > 5 (warn), > 20 (page) |
| `iona_rpc_request_duration_seconds` (P99) | 99th percentile RPC latency | < 100 ms | > 500 ms (warn), > 2 s (page) |
| `iona_mempool_size` / `iona_mempool_capacity` | Current vs max transaction count | < 50% utilization | > 75% (warn), > 90% (page) |
| `iona_blocks_committed_total` (rate) | Block production rate (should be ~1 per 5s) | > 0 per 5 min | == 0 (critical page) |
| `iona_wal_bytes_total` (rate) | Write-ahead log growth rate | < 100 MiB/hour | > 1 GiB/hour (warn) |
| `iona_rpc_rate_limited_total` (rate) | Count of rate-limited requests | 0 | > 5/sec (warn) |
| `iona_signing_failures_total` (rate) | Failed block signatures | 0 | > 0 (critical page) |
| `iona_double_sign_guard_hits` (counter) | Double-sign protection triggered | 0 | > 0 (investigate) |
| `iona_consensus_round` | Current consensus round | Stable at 0 | > 10 (network stuck) |

---

## SLO Pack

Enterprise Pack includes three Service Level Objectives (SLOs) to track validator reliability.

### SLO 1: Validator Uptime (99.5%)

Target: Validator is healthy and able to sign blocks 99.5% of the time.

- **Metric**: `iona_blocks_committed_total`
- **Definition**: At least 1 block signed per 5-minute window
- **Calculation**: (blocks signed / expected blocks) over rolling 30 days
- **Failure budget**: 3.6 hours/month downtime allowed

### SLO 2: Block Signing Rate (99.9%)

Target: When the validator is in the active set, it signs > 95% of proposed blocks.

- **Metric**: `iona_blocks_signed_total` / `iona_blocks_proposed_total`
- **Definition**: 0.95 signing rate or better
- **Calculation**: Rolling average over 1-day windows
- **Failure budget**: 8.6 minutes/month missed blocks allowed

### SLO 3: RPC Availability (99.9%)

Target: Admin RPC endpoint responds to health checks.

- **Metric**: `iona_rpc_healthcheck_total` (success rate)
- **Definition**: GET /_health returns 200 OK
- **Calculation**: 99.9% success rate over rolling 5-minute windows
- **Failure budget**: 8.6 minutes/month unavailable

See `ops/slo/slo_config.yml` for full SLO definitions and error budgets.

---

## Alert Rules

IONA includes pre-built Prometheus alert rules for common failure modes.

### Alert Rules File

**Location**: `ops/alerts/prometheus_rules.yml`

**Sample rules**:
- `IonaPeerCountLow`: < 3 peers (network isolation warning)
- `IonaFinalityLagCritical`: Consensus height lagging > 20 blocks
- `IonaNoBlocksProduced`: No blocks signed in 5 minutes
- `IonaRpcP99LatencyHigh`: RPC P99 latency > 2 seconds
- `IonaMempoolNearCapacity`: Mempool > 90% full
- `IonaDiskFreeBelow20Pct`: Disk space running low
- `IonaWalSizeGrowthRapid`: WAL growth > 1 GiB/hour
- `IonaDoubleSignGuardTriggered`: Double-sign protection activated
- `IonaSingingFailures`: Block signing errors detected

### Loading Alert Rules into Prometheus

1. Copy `ops/alerts/prometheus_rules.yml` to your Prometheus config directory
2. Update `prometheus.yml`:

```yaml
rule_files:
  - 'prometheus_rules.yml'
```

3. Reload Prometheus:

```bash
curl -X POST http://localhost:9000/-/reload
```

4. View active alerts: http://localhost:9000/alerts

---

## Log Aggregation

IONA outputs structured JSON logs (tracing-subscriber format) that integrate with log aggregation platforms.

### Logs on Local Machine

IONA writes JSON logs to `~/.iona/iona.log` by default.

Extract errors:

```bash
tail -f ~/.iona/iona.log | jq 'select(.level == "ERROR")'
```

Extract consensus events:

```bash
tail -f ~/.iona/iona.log | jq 'select(.target | contains("consensus"))'
```

### Loki Integration (Stack: Prometheus Logs)

Add Loki to your Docker Compose:

```yaml
loki:
  image: grafana/loki:latest
  ports:
    - "3100:3100"
  volumes:
    - ./loki-config.yml:/etc/loki/local-config.yml
    - loki-data:/loki
  command: -config.file=/etc/loki/local-config.yml

promtail:
  image: grafana/promtail:latest
  volumes:
    - ~/.iona/iona.log:/var/log/iona/node.log
    - ./promtail-config.yml:/etc/promtail/config.yml
  command: -config.file=/etc/promtail/config.yml
```

Example Promtail config (promtail-config.yml):

```yaml
clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: iona-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: iona
          __path__: /var/log/iona/node.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            target: target
```

In Grafana, add Loki as a data source (http://loki:3100) and explore logs with label selectors:

```
{job="iona", level="ERROR"}
{job="iona", target=~".*consensus.*"}
```

---

## Runbooks

IONA includes runbooks for responding to common alerts. Each runbook describes:
- What triggered the alert
- How to investigate
- Recovery steps
- Escalation path

### Available Runbooks

| Runbook | Handles These Alerts | 
|---------|---------------------|
| `ops/runbooks/peer_drop.md` | `IonaPeerCountLow`, `IonaPeerBanRateHigh` |
| `ops/runbooks/rpc_latency.md` | `IonaRpcP99LatencyHigh`, `IonaRpcErrorRateHigh` |
| `ops/runbooks/mempool_pressure.md` | `IonaMempoolNearCapacity`, `IonaMempoolEvictionRateHigh` |
| `ops/runbooks/finality_lag.md` | `IonaFinalityLagCritical`, `IonaNoBlocksProduced` |
| `ops/runbooks/disk_wal_growth.md` | `IonaDiskFreeBelow20Pct`, `IonaWalSizeGrowthRapid` |
| `ops/runbooks/signing_failures.md` | `IonaSigningFailures`, `IonaDoubleSignGuardTriggered` |

**Usage**: When an alert fires, open the corresponding runbook and follow the investigation steps.

---

## Advanced Topics

### Custom Alert Rules

To add custom alerts, edit `prometheus_rules.yml`:

```yaml
groups:
  - name: iona-custom
    rules:
      - alert: MyCustomAlert
        expr: iona_some_metric > 100
        for: 5m
        annotations:
          summary: "My metric is high"
          runbook_url: https://wiki.internal/myalert
```

### PagerDuty Integration

Add to `alertmanager.yml`:

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: 'pagerduty'

receivers:
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_INTEGRATION_KEY'
        description: '{{ .GroupLabels.alertname }}'
```

### OpsGenie Integration

Add to `alertmanager.yml`:

```yaml
receivers:
  - name: 'opsgenie'
    opsgenie_configs:
      - api_key: 'YOUR_OPSGENIE_API_KEY'
        priority: '{{ .AlertStatus }}'
```

---

## Recommended Metrics Queries for Grafana

Copy these PromQL expressions into Grafana panels:

**Block Height**:
```
iona_consensus_height
```

**Block Production Rate (per minute)**:
```
rate(iona_blocks_committed_total[1m])
```

**Peer Count**:
```
iona_peer_count
```

**Mempool Size vs Capacity**:
```
iona_mempool_size / iona_mempool_capacity
```

**RPC Latency (P99)**:
```
histogram_quantile(0.99, rate(iona_rpc_request_duration_seconds_bucket[5m]))
```

---

## Getting Help

- **Grafana questions**: https://grafana.com/docs/grafana/latest/
- **Prometheus questions**: https://prometheus.io/docs/
- **IONA metrics questions**: See `docs/METRICS.md` or contact support@example.invalid
- **Enterprise support**: email enterprise@example.invalid for SLO dashboards and runbook customization
