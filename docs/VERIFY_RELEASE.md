# IONA Release Verification Guide — v30.0.0

Every release ships the following artefacts, all attached to the GitHub Release at
`https://github.com/iona/iona/releases/tag/v30.0.0`:

| File | Description |
|------|-------------|
| `iona-v30.0.0-linux-x86_64.tar.gz` | Linux x86_64 binary tarball |
| `iona-v30.0.0-linux-aarch64.tar.gz` | Linux ARM64 binary tarball |
| `iona-v30.0.0-darwin-aarch64.tar.gz` | macOS Apple Silicon tarball |
| `iona-node_30.0.0_amd64.deb` | Debian/Ubuntu node package |
| `iona-cli_30.0.0_amd64.deb` | Debian/Ubuntu CLI package |
| `iona-signer_30.0.0_amd64.deb` | Debian/Ubuntu remote signer package |
| `SHA256SUMS` | SHA-256 checksums for all files |
| `SHA256SUMS.asc` | GPG signature over SHA256SUMS |
| `SHA512SUMS` | SHA-512 checksums for all files |
| `sbom.cdx.json` | CycloneDX 1.4 SBOM |
| `iona-release-signing-key.asc` | GPG public key for verification |
| `cosign.pub` | cosign public key |
| `release-notes.md` | Human-readable release notes |

---

## 5 Copy-Paste Verification Commands

Run these five commands to fully verify a release. No prior setup needed beyond
standard Linux tools (`curl`, `sha256sum`, `gpg`).

### Command 1 — Download artefacts + checksums

```bash
VERSION=v30.0.0
BASE="https://github.com/iona/iona/releases/download/${VERSION}"

curl -LO "${BASE}/iona-${VERSION}-linux-x86_64.tar.gz"
curl -LO "${BASE}/SHA256SUMS"
curl -LO "${BASE}/SHA256SUMS.asc"
curl -LO "${BASE}/iona-release-signing-key.asc"
```

### Command 2 — Verify SHA-256 checksum (integrity)

```bash
sha256sum --check --ignore-missing SHA256SUMS
# Expected output:
# iona-v30.0.0-linux-x86_64.tar.gz: OK
```

This verifies the downloaded file matches what the IONA team published. If this
fails, the file is corrupt or tampered — do not proceed.

### Command 3 — Verify GPG signature (authenticity)

```bash
gpg --import iona-release-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
# Expected output:
# gpg: Good signature from "IONA Release Signing Key <packages@example.invalid>"
# Primary key fingerprint: 70DD DC99 E884 72E2 AF8D  EB2D A76E E4EE 0B46 3E62
```

This proves the checksums were produced by the IONA engineering team, not a
mirror or attacker. Verify the fingerprint independently at https://iona.network/security.

### Command 4 — Verify cosign signature (CI provenance)

```bash
curl -LO "${BASE}/cosign.pub"
curl -LO "${BASE}/iona-${VERSION}-linux-x86_64.tar.gz.sig"

cosign verify-blob \
  --key cosign.pub \
  --signature "iona-${VERSION}-linux-x86_64.tar.gz.sig" \
  "iona-${VERSION}-linux-x86_64.tar.gz"
# Expected: Verified OK
```

This proves the binary was built by the IONA GitHub Actions CI pipeline.
Install cosign: `brew install cosign` or from https://github.com/sigstore/cosign/releases

### Command 5 — Scan SBOM for known CVEs

```bash
curl -LO "${BASE}/sbom.cdx.json"
# Using grype (https://github.com/anchore/grype):
grype sbom:sbom.cdx.json
# Expected: No vulnerabilities found  (or review any reported issues)

# Using trivy (https://trivy.dev):
trivy sbom sbom.cdx.json
```

---

## All-in-one: Automated install with full verification

The official installer runs all checks automatically:

```bash
curl -fsSL https://install.iona.sh | sudo sh -s -- --version v30.0.0
# Performs: SHA-256 + GPG + cosign checks before installing
```

Or with a specific cosign key:
```bash
COSIGN_PUBLIC_KEY=./cosign.pub curl -fsSL https://install.iona.sh | sudo sh
```

---

## GPG Key Details

```
Key: IONA Release Signing Key <packages@example.invalid>
Fingerprint: 70DD DC99 E884 72E2 AF8D  EB2D A76E E4EE 0B46 3E62
Algorithm: RSA 4096
Expires: 2027-03-05
Published at: https://iona.network/security.gpg
              https://keys.openpgp.org
```

## Reporting Verification Failures

If any verification step fails, **do not run the binary**. Report to:
- security@example.invalid (GPG: https://iona.network/security.gpg)
- GitHub: https://github.com/iona/iona/security/advisories/new
