#!/bin/bash
#
# IONA v28 Node Upgrade Script
# =============================
# Safely upgrades the IONA node binary with validation and rollback support.
# Creates backups before upgrade and verifies health after completion.
#
# Usage:
#   sudo ./upgrade.sh v28.1.0
#   sudo ./upgrade.sh v28.1.0 --dry-run
#

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/opt/iona/data"
CONFIG_DIR="/etc/iona"
BACKUP_DIR="/opt/iona/backups"
SERVICE_NAME="iona-node"
GITHUB_REPO="iona-labs/iona"
DRY_RUN=false
TARGET_VERSION="${1:-}"
CURRENT_BINARY="$INSTALL_DIR/iona-node"
BACKUP_BINARY="$INSTALL_DIR/iona-node.backup"
RPC_ENDPOINT="http://127.0.0.1:9001"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo or as root"
        exit 1
    fi
}

# Parse arguments
parse_args() {
    if [[ -z "$TARGET_VERSION" ]]; then
        log_error "Usage: $0 <version> [--dry-run]"
        exit 1
    fi

    if [[ "${2:-}" == "--dry-run" ]]; then
        DRY_RUN=true
        log_warn "DRY RUN MODE - no changes will be made"
    fi
}

# Get current version
get_current_version() {
    if [[ ! -f "$CURRENT_BINARY" ]]; then
        echo "unknown"
        return
    fi
    "$CURRENT_BINARY" --version 2>/dev/null | awk '{print $2}' || echo "unknown"
}

# Create backup
create_backup() {
    log_section "Creating Backup"

    mkdir -p "$BACKUP_DIR"

    # Backup binary
    if [[ -f "$CURRENT_BINARY" ]]; then
        cp "$CURRENT_BINARY" "$BACKUP_BINARY"
        log_info "Binary backed up to $BACKUP_BINARY"
    fi

    # Backup data directory
    local data_backup="$BACKUP_DIR/data-$(date +%Y%m%d-%H%M%S).tar.gz"
    log_info "Backing up data directory to $data_backup..."
    tar czf "$data_backup" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" --exclude='*.log'
    log_info "Data backup complete: $data_backup"
}

# Download new binary
download_binary() {
    log_section "Downloading Binary"

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${TARGET_VERSION}/iona-node-${TARGET_VERSION}-x86_64-unknown-linux-gnu"
    local sha256_url="https://github.com/${GITHUB_REPO}/releases/download/${TARGET_VERSION}/iona-node-${TARGET_VERSION}-x86_64-unknown-linux-gnu.sha256"

    log_info "Downloading version $TARGET_VERSION..."

    if ! curl -fSL "$download_url" -o /tmp/iona-node-upgrade; then
        log_error "Failed to download binary"
        return 1
    fi

    # Verify SHA256
    if curl -fSL "$sha256_url" -o /tmp/iona-node-upgrade.sha256; then
        log_info "Verifying SHA256 checksum..."
        (cd /tmp && sha256sum -c iona-node-upgrade.sha256) || {
            log_error "SHA256 verification failed"
            rm -f /tmp/iona-node-upgrade
            return 1
        }
        log_info "SHA256 verification passed"
    else
        log_warn "SHA256 file not found, skipping verification"
    fi

    chmod +x /tmp/iona-node-upgrade
    log_info "Binary downloaded and verified"
}

# Check compatibility
check_compatibility() {
    log_section "Checking Compatibility"

    if [[ $DRY_RUN == true ]]; then
        log_info "[DRY RUN] Would run compatibility check"
        return 0
    fi

    log_info "Running compatibility check..."
    if ! /tmp/iona-node-upgrade --check-compat --config "$CONFIG_DIR/config.toml"; then
        log_error "Compatibility check failed"
        log_info "Rolling back to previous binary..."
        return 1
    fi

    log_info "Compatibility check passed"
}

# Stop service
stop_service() {
    log_section "Stopping Service"

    if [[ $DRY_RUN == true ]]; then
        log_info "[DRY RUN] Would stop $SERVICE_NAME"
        return 0
    fi

    log_info "Stopping $SERVICE_NAME..."
    systemctl stop "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_warn "Service still running, forcing stop..."
        systemctl kill -s KILL "$SERVICE_NAME" || true
        sleep 1
    fi

    log_info "Service stopped"
}

# Replace binary
replace_binary() {
    log_section "Installing New Binary"

    if [[ $DRY_RUN == true ]]; then
        log_info "[DRY RUN] Would install /tmp/iona-node-upgrade to $CURRENT_BINARY"
        return 0
    fi

    mv /tmp/iona-node-upgrade "$CURRENT_BINARY"
    log_info "Binary replaced: $CURRENT_BINARY"
}

# Start service
start_service() {
    log_section "Starting Service"

    if [[ $DRY_RUN == true ]]; then
        log_info "[DRY RUN] Would start $SERVICE_NAME"
        return 0
    fi

    log_info "Starting $SERVICE_NAME..."
    systemctl start "$SERVICE_NAME"
    sleep 3

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        log_error "Service failed to start"
        return 1
    fi

    log_info "Service started successfully"
}

# Health check
health_check() {
    log_section "Health Check"

    if [[ $DRY_RUN == true ]]; then
        log_info "[DRY RUN] Would check node health"
        return 0
    fi

    log_info "Waiting for node to be ready..."
    local max_attempts=30
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        if curl -sf "$RPC_ENDPOINT/health" &>/dev/null; then
            log_info "Health check passed after ${attempt}s"
            return 0
        fi

        log_info "Waiting for node... ($attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    log_error "Health check failed after ${max_attempts}s"
    return 1
}

# Rollback on failure
rollback() {
    log_section "Rolling Back"

    log_error "Upgrade failed, rolling back..."

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
    fi

    if [[ -f "$BACKUP_BINARY" ]]; then
        log_info "Restoring previous binary..."
        cp "$BACKUP_BINARY" "$CURRENT_BINARY"
        log_info "Binary restored"
    fi

    log_info "Starting service with previous binary..."
    systemctl start "$SERVICE_NAME"
    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Rollback successful - service is running"
    else
        log_error "Rollback failed - service is not running"
        return 1
    fi
}

# Print summary
print_summary() {
    log_section "Upgrade Summary"

    local current=$(get_current_version)
    echo ""
    echo -e "${GREEN}Upgrade completed successfully!${NC}"
    echo "  Previous version: $(get_current_version || echo 'unknown')"
    echo "  New version:      $TARGET_VERSION"
    echo "  Binary:           $CURRENT_BINARY"
    echo "  Backup:           $BACKUP_BINARY"
    echo ""
    echo "View logs:"
    echo "  sudo journalctl -u $SERVICE_NAME -f"
    echo ""
}

# Main execution
main() {
    check_root
    parse_args

    log_section "IONA Node Upgrade"
    log_info "Current version: $(get_current_version)"
    log_info "Target version:  $TARGET_VERSION"
    echo ""

    # Upgrade steps
    create_backup || exit 1
    download_binary || exit 1
    check_compatibility || {
        log_error "Compatibility check failed, aborting upgrade"
        exit 1
    }
    stop_service || exit 1
    replace_binary || exit 1
    start_service || {
        rollback
        exit 1
    }
    health_check || {
        rollback
        exit 1
    }
    print_summary
}

# Trap errors
trap 'rollback' ERR

main "$@"
