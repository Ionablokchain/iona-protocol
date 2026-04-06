# Runbook: Mempool Pressure

**Alerts**: `IonaMempoolNearCapacity`, `IonaMempoolCapacityWarning`, `IonaMempoolEvictionRateHigh`
**Severity**: Page (> 90% full) / Warning (> 75% full or high eviction rate)

---

## Impact

A full mempool drops incoming transactions silently, causing user-facing "transaction not found" errors and potential double-submission by clients. If the mempool is full because blocks are not being produced, this often indicates a consensus issue.

---

## Diagnosis

### 1. Check current mempool stats

```bash
curl -s http://localhost:9001/mempool | jq
# or via RPC
curl -s http://localhost:9001/ -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}' | jq
```

Key fields:
- `pending` — transactions ready to include in the next block
- `queued` — transactions waiting for a nonce gap to be filled
- `capacity` — configured maximum (default: 200,000)

### 2. Is the block height advancing?

```bash
curl -s http://localhost:9001/status | jq '.result.sync_info.latest_block_height'
# Wait 2 seconds and check again
```

If height is NOT advancing → the mempool is backing up because blocks are stalled. Treat as a consensus issue (see `finality_lag` runbook) rather than a mempool issue.

### 3. Identify the top fee-payers / spammers

```bash
curl -s http://localhost:9001/mempool | jq '.transactions | group_by(.from) |
  map({addr: .[0].from, count: length}) | sort_by(.count) | reverse | .[0:10]'
```

A single address with thousands of transactions suggests a spam attack.

### 4. Check average gas price

```bash
curl -s http://localhost:9001/mempool | jq '[.transactions[].gas_price | tonumber] |
  {min: min, max: max, avg: (add/length)}'
```

If many transactions have very low gas price → EIP-1559 base fee may have risen while old transactions are stranded. These will never be included and are wasting mempool slots.

---

## Remediation

### A. Flush the mempool (maintenance window)

Use this only during a planned maintenance window. It discards all unconfirmed transactions.

```bash
curl -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/mempool-flush
```

> **Warning**: flushed transactions are NOT rebroadcast. Senders will need to resubmit.

### B. Increase mempool capacity (temporary relief)

Edit `config.toml` and reload:

```toml
[mempool]
capacity = 400000  # doubled from 200000
```

```bash
curl -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/config-reload
```

Note: increasing capacity uses more RAM. Each transaction slot uses approximately 500 bytes; 400,000 slots ≈ 200 MiB.

### C. Spam mitigation

If a single address is spamming:

1. Increase the minimum gas price floor (contact the team to adjust protocol params via governance).
2. If the node is a validator, the proposer can be configured to skip transactions from banned addresses.
3. Consider blocking the source IP at the load balancer for the RPC port.

### D. Stale transaction cleanup

Stale (low-fee, stuck-nonce) transactions will be evicted naturally by the priority queue when new transactions arrive. To accelerate this:

1. Wait for the next block to raise the base fee, which will evict sub-base-fee transactions.
2. If the chain is not advancing, address the consensus issue first.

### E. Alert during high-volume periods (planned)

During token launches or known high-traffic events, proactively:

1. Double the mempool capacity in advance (see B above).
2. Enable rate limiting on `eth_sendRawTransaction` separately from read endpoints:
   ```toml
   # In future config: [rpc.rate_limits.submit]
   # max_per_ip_per_sec = 5
   ```

---

## Escalation

- Mempool > 95% full AND blocks not advancing → page both on-call network and protocol engineers.
- Mempool flush required during peak hours → get sign-off from on-call lead.

---

## Post-incident

1. Capture mempool statistics snapshot before flush.
2. Review whether the capacity default (200,000) needs a permanent increase.
3. If spam attack confirmed, open a governance proposal to raise minimum gas price.
