#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# IONA APT Repository Setup Script
# ─────────────────────────────────────────────────────────────────────────────
# Sets up a self-hosted APT repository using dpkg-scanpackages / apt-ftparchive.
# Suitable for hosting on GitHub Pages, S3, or any static file server.
#
# Usage:
#   ./setup-apt-repo.sh --debs /path/to/deb/files --output /path/to/repo --sign-key <KEY_ID>
#
# After running, the repo is at --output. Point apt to it with:
#   echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/iona.gpg] \
#     https://YOUR_URL/apt stable main" | sudo tee /etc/apt/sources.list.d/iona.list
#   sudo apt-get update
#   sudo apt-get install iona-node
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

DEBS_DIR="${DEBS_DIR:-./debs}"
OUTPUT_DIR="${OUTPUT_DIR:-./apt-repo}"
SIGN_KEY="${SIGN_KEY:-}"
CODENAME="${CODENAME:-stable}"
COMPONENT="${COMPONENT:-main}"
ARCH="${ARCH:-amd64}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debs)       DEBS_DIR="$2";   shift 2 ;;
    --output)     OUTPUT_DIR="$2"; shift 2 ;;
    --sign-key)   SIGN_KEY="$2";   shift 2 ;;
    --codename)   CODENAME="$2";   shift 2 ;;
    *) warn "Unknown: $1"; shift ;;
  esac
done

# ── Prerequisites ──────────────────────────────────────────────────────────
for cmd in dpkg-scanpackages apt-ftparchive gzip bzip2; do
  command -v "$cmd" &>/dev/null || die "Required: $cmd (apt-get install -y dpkg-dev apt-utils)"
done

# ── Structure ──────────────────────────────────────────────────────────────
info "Creating repository structure at ${OUTPUT_DIR}/"
POOL="${OUTPUT_DIR}/pool/${COMPONENT}"
DISTS="${OUTPUT_DIR}/dists/${CODENAME}/${COMPONENT}/binary-${ARCH}"

mkdir -p "${POOL}" "${DISTS}"

# ── Copy .deb files ────────────────────────────────────────────────────────
info "Copying .deb files from ${DEBS_DIR}/..."
if ! ls "${DEBS_DIR}"/*.deb &>/dev/null; then
  die "No .deb files found in ${DEBS_DIR}/"
fi
cp "${DEBS_DIR}"/*.deb "${POOL}/"
info "Copied: $(ls "${POOL}"/*.deb | wc -l) package(s)"

# ── Generate Packages index ────────────────────────────────────────────────
info "Generating Packages index..."
(
  cd "${OUTPUT_DIR}"
  dpkg-scanpackages "pool/${COMPONENT}" /dev/null > "dists/${CODENAME}/${COMPONENT}/binary-${ARCH}/Packages"
)
gzip  -k "${DISTS}/Packages"
bzip2 -k "${DISTS}/Packages"
info "Packages index: $(wc -l < "${DISTS}/Packages") entries"

# ── Generate Release file ──────────────────────────────────────────────────
info "Generating Release file..."
cat > "${OUTPUT_DIR}/dists/${CODENAME}/Release" <<RELEASE
Origin: IONA
Label: IONA Blockchain Node
Suite: ${CODENAME}
Codename: ${CODENAME}
Version: 1.0
Architectures: ${ARCH}
Components: ${COMPONENT}
Description: IONA blockchain node official package repository
Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')
RELEASE

# Append checksums for all index files
(
  cd "${OUTPUT_DIR}/dists/${CODENAME}"
  echo "MD5Sum:"
  find "${COMPONENT}" -name "Packages*" -type f | sort | while read f; do
    printf " %s %8s %s\n" "$(md5sum "$f" | cut -d' ' -f1)" "$(wc -c < "$f")" "$f"
  done
  echo "SHA1:"
  find "${COMPONENT}" -name "Packages*" -type f | sort | while read f; do
    printf " %s %8s %s\n" "$(sha1sum "$f" | cut -d' ' -f1)" "$(wc -c < "$f")" "$f"
  done
  echo "SHA256:"
  find "${COMPONENT}" -name "Packages*" -type f | sort | while read f; do
    printf " %s %8s %s\n" "$(sha256sum "$f" | cut -d' ' -f1)" "$(wc -c < "$f")" "$f"
  done
) >> "${OUTPUT_DIR}/dists/${CODENAME}/Release"

# ── Sign the Release file ──────────────────────────────────────────────────
if [[ -n "${SIGN_KEY}" ]]; then
  info "Signing Release with GPG key: ${SIGN_KEY}..."
  gpg --default-key "${SIGN_KEY}" \
    --armor --detach-sign \
    --output "${OUTPUT_DIR}/dists/${CODENAME}/Release.gpg" \
    "${OUTPUT_DIR}/dists/${CODENAME}/Release"
  gpg --default-key "${SIGN_KEY}" \
    --armor --clearsign \
    --output "${OUTPUT_DIR}/dists/${CODENAME}/InRelease" \
    "${OUTPUT_DIR}/dists/${CODENAME}/Release"
  info "Release signed (Release.gpg + InRelease created)"

  # Export public key for users to import
  gpg --armor --export "${SIGN_KEY}" > "${OUTPUT_DIR}/iona-archive-keyring.gpg"
  info "Public key exported: ${OUTPUT_DIR}/iona-archive-keyring.gpg"
else
  warn "No SIGN_KEY set — Release not signed (unsigned repos will require [trusted=yes])"
fi

# ── Summary ────────────────────────────────────────────────────────────────
info "Repository ready at: ${OUTPUT_DIR}/"
echo ""
echo "─── Repository layout ─────────────────────────────────────"
find "${OUTPUT_DIR}" -type f | sort | sed "s|${OUTPUT_DIR}/||"
echo "───────────────────────────────────────────────────────────"
echo ""
info "To use this repository, on each client run:"
echo ""
echo "  # Import GPG key (if signed)"
echo "  curl -fsSL https://YOUR_REPO_URL/iona-archive-keyring.gpg \\"
echo "    | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/iona.gpg"
echo ""
echo "  # Add the repository"
echo "  echo \"deb [arch=${ARCH} signed-by=/etc/apt/trusted.gpg.d/iona.gpg] \\"
echo "    https://YOUR_REPO_URL/apt ${CODENAME} ${COMPONENT}\" \\"
echo "    | sudo tee /etc/apt/sources.list.d/iona.list"
echo ""
echo "  # Install"
echo "  sudo apt-get update && sudo apt-get install iona-node"
