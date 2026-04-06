#!/bin/bash
set -e

# Build script for IONA Debian package

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=========================================="
echo "Building IONA v28.4.0 Debian Package"
echo "=========================================="
echo ""

# Check for required tools
if command -v dpkg-buildpackage >/dev/null 2>&1; then
  echo "Using dpkg-buildpackage for package build..."
  USE_DPK=true
elif command -v fpm >/dev/null 2>&1; then
  echo "Using fpm for package build..."
  USE_FPM=true
else
  echo "ERROR: Neither dpkg-buildpackage nor fpm found"
  echo "Install with: sudo apt-get install build-essential devscripts # for dpkg"
  echo "Or: sudo apt-get install ruby ruby-dev && sudo gem install fpm # for fpm"
  exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -f "$PROJECT_ROOT"/iona-node_*.deb
rm -rf "$PROJECT_ROOT"/debian

# Build with Cargo
echo ""
echo "Building Rust binaries (release mode)..."
cd "$PROJECT_ROOT"
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
cargo build --release 2>&1 | tail -20

if [ ! -f target/release/iona-node ]; then
  echo "ERROR: Binary build failed - iona-node not found"
  exit 1
fi

if [ ! -f target/release/iona-cli ]; then
  echo "ERROR: Binary build failed - iona-cli not found"
  exit 1
fi

if [ ! -f target/release/iona-remote-signer ]; then
  echo "ERROR: Binary build failed - iona-remote-signer not found"
  exit 1
fi

echo "Binaries built successfully"
echo ""

# Build package with fpm (simpler, more portable)
if [ "$USE_FPM" = "true" ]; then
  echo "Building .deb package with fpm..."
  
  # Create temporary staging directory
  STAGING=$(mktemp -d)
  trap "rm -rf $STAGING" EXIT
  
  # Stage binaries
  mkdir -p "$STAGING/usr/local/bin"
  cp -v target/release/iona-node "$STAGING/usr/local/bin/"
  cp -v target/release/iona-cli "$STAGING/usr/local/bin/"
  cp -v target/release/iona-remote-signer "$STAGING/usr/local/bin/"
  
  # Strip binaries
  strip "$STAGING/usr/local/bin/iona-node"
  strip "$STAGING/usr/local/bin/iona-cli"
  strip "$STAGING/usr/local/bin/iona-remote-signer"
  
  # Stage systemd service
  mkdir -p "$STAGING/lib/systemd/system"
  cp -v "$SCRIPT_DIR/iona-node.service" "$STAGING/lib/systemd/system/"
  
  # Stage configuration
  mkdir -p "$STAGING/etc/iona"
  cp -v "$PROJECT_ROOT/config.toml" "$STAGING/etc/iona/config.toml.default"
  
  # Stage directories for data
  mkdir -p "$STAGING/var/lib/iona"
  mkdir -p "$STAGING/var/log/iona"
  
  # Build with fpm
  fpm \
    -s dir \
    -t deb \
    -n iona-node \
    -v 28.4.0 \
    -C "$STAGING" \
    --prefix / \
    --after-install "$SCRIPT_DIR/postinst" \
    --before-remove "$SCRIPT_DIR/prerm" \
    --depends "libssl3 >= 3.0" \
    --depends "adduser" \
    --depends "systemd" \
    --recommends "prometheus-node-exporter" \
    --recommends "jq" \
    --maintainer "IONA Engineering <packages@example.invalid>" \
    --url "https://github.com/iona/iona" \
    --description "IONA blockchain node with Byzantine Fault Tolerant consensus" \
    --deb-priority "optional" \
    --deb-field "Section: net" \
    --architecture amd64 \
    .
  
  echo ""
  echo "=========================================="
  echo "Package built successfully!"
  echo "=========================================="
  echo ""
  
elif [ "$USE_DPK" = "true" ]; then
  echo "Building .deb package with dpkg-buildpackage..."
  
  # Create debian directory structure
  mkdir -p "$PROJECT_ROOT/debian"
  cp "$SCRIPT_DIR/control" "$PROJECT_ROOT/debian/"
  cp "$SCRIPT_DIR/rules" "$PROJECT_ROOT/debian/"
  chmod +x "$PROJECT_ROOT/debian/rules"
  cp "$SCRIPT_DIR/postinst" "$PROJECT_ROOT/debian/"
  chmod +x "$PROJECT_ROOT/debian/postinst"
  cp "$SCRIPT_DIR/prerm" "$PROJECT_ROOT/debian/"
  chmod +x "$PROJECT_ROOT/debian/prerm"
  
  # Create changelog
  cat > "$PROJECT_ROOT/debian/changelog" << 'CHANGELOG'
iona-node (28.4.0) stable; urgency=medium

  * Release v28.4.0: Production-grade BFT consensus
  * Enterprise-grade RBAC and audit logging
  * Cosmos-compatible key management
  * Pluggable execution layers
  * Cosign-signed release artifacts

 -- IONA Engineering <packages@example.invalid>  Wed, 04 Mar 2026 00:00:00 +0000
CHANGELOG

  # Create copyright file
  cat > "$PROJECT_ROOT/debian/copyright" << 'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2024-2026 IONA Engineering <packages@example.invalid>
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0
 See https://github.com/iona/iona/blob/main/LICENSE
COPYRIGHT

  cd "$PROJECT_ROOT"
  dpkg-buildpackage -us -uc -b 2>&1 | tail -30
  
  echo ""
  echo "=========================================="
  echo "Package built successfully!"
  echo "=========================================="
  echo ""
fi

# Sign package if gpg key available
echo ""
if command -v dpkg-sig >/dev/null 2>&1 && [ -n "$GPG_KEY" ]; then
  echo "Signing package with GPG..."
  dpkg-sig -k "$GPG_KEY" -s builder "$PROJECT_ROOT"/iona-node_*.deb
  echo "Package signed successfully"
else
  echo "GPG signing skipped (GPG_KEY not set or dpkg-sig not available)"
fi

echo ""
echo "Build artifacts:"
ls -lh "$PROJECT_ROOT"/iona-node_*.deb 2>/dev/null || echo "Package not found in expected location"

echo ""
echo "To install: sudo dpkg -i iona-node_28.4.0_amd64.deb"
echo ""
