# Runbook: RPC Latency / Error Rate

**Alerts**: `IonaRpcP99LatencyHigh`, `IonaRpcP99LatencyWarning`, `IonaRpcErrorRateHigh`, `IonaRpcRateLimitFiring`
**Severity**: Page (P99 > 2s or error rate > 5%) / Warning otherwise

---

## Impact

High RPC latency degrades user-facing applications, wallets, and indexers that poll the node. Error rates above 5% typically indicate a failing handler, OOM condition, or saturated thread pool.

---

## Diagnosis

### 1. Identify slow endpoints

```bash
# Prometheus query (run in Grafana or promtool)
topk(5,
  histogram_quantile(0.99,
    rate(iona_rpc_request_duration_seconds_bucket[5m])
  ) by (method, path)
)
```

This shows which RPC methods are slowest.

### 2. Check system resources on the node

```bash
top -bn1 | head -20
free -h
df -h /data
iostat -x 1 5
```

Look for:
- CPU > 90% sustained — thread pool saturation
- Memory > 85% — potential OOM / heavy GC
- Disk I/O > 80% util — storage bottleneck (especially on `eth_getLogs` or `debug_traceTransaction`)

### 3. Check concurrency limiter metrics

```bash
curl -s http://localhost:9001/metrics | grep iona_rpc_concurrent
```

If `iona_rpc_concurrent_requests` is at the concurrency limit and requests are queuing, the node is overloaded.

### 4. Check for large requests / JSON depth abuses

```bash
tail -200 /var/log/iona/node.log | grep "422\|UNPROCESSABLE\|depth"
```

Attacker sending deeply-nested JSON → CPU spike in depth checker. Check `iona_rpc_depth_limit_hits_total` metric.

### 5. Check the rate limiter

```bash
curl -s http://localhost:9001/metrics | grep rate_limited
```

If `IonaRpcRateLimitFiring` is alerting, verify it is protecting correctly:

```bash
# See the top IPs hitting the rate limit
tail -500 /var/log/iona/node.log | grep "429\|rate.limit" | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

---

## Remediation

### A. RPC latency — general

If load is legitimate and the node is under-provisioned:

1. Increase the concurrency limit in config:
   ```toml
   [rpc]
   # Not yet a config knob — patch MAX_CONCURRENT in middleware.rs (default: 256)
   ```

2. Move read-heavy callers (indexers, explorers) to a dedicated read-replica node that does not participate in consensus.

### B. RPC latency — storage bottleneck

If `eth_getLogs` or state queries are slow:

```bash
# Check RocksDB compaction status
curl -s http://localhost:9001/metrics | grep rocksdb
```

Trigger a snapshot to compact state:

```bash
curl -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/snapshot
```

### C. Error rate > 5%

Check the error breakdown by status code:

```bash
curl -s http://localhost:9001/metrics | grep 'iona_rpc_errors_total{' | sort -t= -k2
```

- 5xx errors → internal handler failure; check node logs for panics.
- 4xx errors at high volume → likely a misconfigured client or fuzz attempt.

For internal failures, restart the node if no recovery within 5 minutes:

```bash
systemctl restart iona-node
```

### D. Rate limiter firing (legitimate load)

If the source IPs are legitimate services:

1. Coordinate with the team to move heavy callers to WebSocket subscriptions instead of polling.
2. If the source is a known IP, consider whitelisting at the load-balancer level.
3. Never disable the rate limiter globally in production.

---

## Escalation

- P99 > 5s sustained for 10 minutes → escalate to lead engineer.
- Error rate > 20% → potential chain issue; cross-check `finality_lag` alert.

---

## Post-incident

1. Capture `curl -s http://localhost:9001/metrics` snapshot before restarting.
2. Review whether the endpoint causing the latency needs a dedicated cache layer.
3. Update load test suite to replicate the traffic pattern.
