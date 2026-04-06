#!/usr/bin/env bash
# Build all 3 .deb packages for a given arch
# Usage: bash build-deb.sh <version> <arch> <bindir>
set -euo pipefail

VER="${1:?version required}"
ARCH="${2:?arch required (amd64|arm64)}"
BINDIR="${3:?bindir required}"

declare -A BINARIES=(
  [iona-node]="iona-node"
  [iona-cli]="iona-cli"
  [iona-signer]="iona-remote-signer"
)

for PKG in iona-node iona-cli iona-signer; do
  echo "Building ${PKG}_${VER}_${ARCH}.deb ..."
  PKGDIR="${PKG}_${VER}_${ARCH}"
  mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/local/bin" "$PKGDIR/lib/systemd/system"

  # Copy control file (prefer split packaging, fallback to inline)
  if [ -f "packaging/deb-split/${PKG}/control" ]; then
    cp "packaging/deb-split/${PKG}/control" "$PKGDIR/DEBIAN/control"
    sed -i "s/^Version:.*/Version: ${VER}/" "$PKGDIR/DEBIAN/control"
    sed -i "s/^Architecture:.*/Architecture: ${ARCH}/" "$PKGDIR/DEBIAN/control"
  else
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: IONA Engineering <packages@example.invalid>\nDepends: libssl3 (>= 3.0)\nDescription: IONA blockchain %s v%s\n' \
      "$PKG" "$VER" "$ARCH" "$PKG" "$VER" > "$PKGDIR/DEBIAN/control"
  fi

  # Install binary
  case "$PKG" in
    iona-node)
      [ -f "$BINDIR/iona-node" ]    && install -m755 "$BINDIR/iona-node" "$PKGDIR/usr/local/bin/"
      [ -f "$BINDIR/iona-node.service" ] && \
        cp "$BINDIR/iona-node.service" "$PKGDIR/lib/systemd/system/" || \
        cp "packaging/deb/iona-node.service" "$PKGDIR/lib/systemd/system/" 2>/dev/null || true
      ;;
    iona-cli)
      [ -f "$BINDIR/iona-cli" ]     && install -m755 "$BINDIR/iona-cli" "$PKGDIR/usr/local/bin/"
      ;;
    iona-signer)
      [ -f "$BINDIR/iona-remote-signer" ] && \
        install -m755 "$BINDIR/iona-remote-signer" "$PKGDIR/usr/local/bin/iona-remote-signer"
      ;;
  esac

  dpkg-deb --build "$PKGDIR" "${PKG}_${VER}_${ARCH}.deb"
  echo "  → ${PKG}_${VER}_${ARCH}.deb ($(du -sh ${PKG}_${VER}_${ARCH}.deb | cut -f1))"
done

echo "All .deb packages built successfully."
