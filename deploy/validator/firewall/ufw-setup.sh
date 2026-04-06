#!/bin/bash
#
# IONA Validator Node UFW Firewall Configuration
# ================================================
# Configures UFW (Uncomplicated Firewall) for production IONA validator deployment.
# This script sets up restrictive firewall rules to:
# - Allow peer-to-peer consensus traffic (P2P port)
# - Block public access to sensitive endpoints (RPC, Admin)
# - Enforce IP-based rate limiting on SSH
# - Allow Prometheus metrics scraping from monitoring infrastructure
#
# Usage: sudo ./ufw-setup.sh
# To remove: sudo ./ufw-setup.sh --remove
#

set -euo pipefail

# ANSI color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
P2P_PORT=7001
RPC_PORT=9001
ADMIN_PORT=9002
PROMETHEUS_PORT=9090
SSH_PORT=22
MONITORING_SUBNET="10.0.0.0/8"

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if UFW is installed
check_ufw_installed() {
    if ! command -v ufw &> /dev/null; then
        log_error "UFW is not installed. Install with: apt-get install ufw"
        exit 1
    fi
}

# Remove all UFW rules and disable
remove_rules() {
    log_warn "Removing all UFW rules and disabling firewall..."
    ufw --force disable
    ufw --force reset
    log_info "UFW firewall disabled and reset"
    exit 0
}

# Configure UFW rules
configure_firewall() {
    log_info "Starting UFW configuration for IONA validator..."

    # Set default policies
    log_info "Setting default policies: deny incoming, allow outgoing"
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH with rate limiting
    log_info "Configuring SSH access with rate limiting (port ${SSH_PORT})"
    log_warn "IMPORTANT: In production, consider whitelisting specific management IPs instead of allowing SSH globally"
    ufw limit ${SSH_PORT}/tcp comment "SSH with rate limiting"

    # Allow P2P port from anywhere (validators must be reachable by peers)
    log_info "Allowing P2P port ${P2P_PORT} from any source (required for consensus)"
    ufw allow ${P2P_PORT}/tcp comment "IONA P2P port - open to all peers"
    ufw allow ${P2P_PORT}/udp comment "IONA P2P port UDP - open to all peers"

    # Deny RPC port from public (only accessible via loopback)
    log_info "Denying public access to RPC port ${RPC_PORT} (enforced at app level too)"
    log_warn "RPC is only accessible from localhost (127.0.0.1:${RPC_PORT})"
    log_warn "Public RPC should be proxied through nginx on port 443 with rate limiting"
    ufw deny ${RPC_PORT}/tcp comment "IONA RPC - blocked from public, use nginx reverse proxy"

    # Deny Admin port from public (admin-only access)
    log_info "Denying public access to Admin port ${ADMIN_PORT}"
    log_warn "Admin interface should only be accessible from management IP addresses"
    ufw deny ${ADMIN_PORT}/tcp comment "IONA Admin - blocked from public"

    # Allow Prometheus metrics from monitoring subnet
    log_info "Allowing Prometheus scrape from monitoring subnet ${MONITORING_SUBNET}"
    ufw allow from ${MONITORING_SUBNET} to any port ${PROMETHEUS_PORT}/tcp comment "Prometheus metrics - monitoring subnet only"

    # Enable UFW
    log_info "Enabling UFW firewall..."
    ufw --force enable

    # Print summary
    log_info "UFW configuration complete"
    echo ""
    echo -e "${GREEN}=== Firewall Rules Summary ===${NC}"
    echo ""
    ufw status verbose
    echo ""
    log_info "Port Summary:"
    echo "  SSH (${SSH_PORT}): ALLOWED with rate limiting"
    echo "  P2P (${P2P_PORT}): ALLOWED from any (required for consensus)"
    echo "  RPC (${RPC_PORT}): DENIED from public (loopback only, proxy via nginx)"
    echo "  Admin (${ADMIN_PORT}): DENIED from public (management IPs only)"
    echo "  Prometheus (${PROMETHEUS_PORT}): ALLOWED from ${MONITORING_SUBNET}"
    echo ""
}

# Main execution
main() {
    check_root
    check_ufw_installed

    # Parse command line arguments
    if [[ "${1:-}" == "--remove" ]]; then
        remove_rules
    fi

    configure_firewall
}

main "$@"
