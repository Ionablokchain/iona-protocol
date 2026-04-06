#!/bin/bash
#
# IONA Validator Node iptables Firewall Configuration
# ====================================================
# Configures iptables rules for production IONA validator deployment.
# Provides low-level packet filtering with rate limiting support.
#
# Usage: sudo ./iptables-rules.sh
#

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
P2P_PORT=7001
RPC_PORT=9001
ADMIN_PORT=9002
SSH_PORT=22
PROMETHEUS_PORT=9090

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Flush all existing rules
flush_rules() {
    log_info "Flushing all existing iptables rules..."
    iptables -F
    iptables -X
    iptables -Z
    ip6tables -F
    ip6tables -X
    ip6tables -Z
}

# Reset to accept all
reset_policies() {
    log_info "Resetting default policies..."
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
}

# Configure IPv4 rules
configure_ipv4() {
    log_info "Configuring IPv4 iptables rules..."

    # Set default policies
    iptables -P INPUT DROP
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP

    # Accept loopback traffic
    iptables -A INPUT -i lo -j ACCEPT

    # Accept established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP

    # Allow SSH with rate limiting: 10 new connections per minute per IP
    iptables -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 5 -j ACCEPT
    iptables -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -j DROP

    # Allow P2P consensus traffic (7001/tcp and 7001/udp)
    # Apply rate limiting: 10 connections per minute per IP
    iptables -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -j DROP
    iptables -A INPUT -p udp --dport ${P2P_PORT} -j ACCEPT

    # Allow Prometheus from monitoring subnet (10.0.0.0/8)
    iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport ${PROMETHEUS_PORT} -j ACCEPT

    # Drop RPC port access from public (enforced at app level as well)
    iptables -A INPUT -p tcp --dport ${RPC_PORT} -j DROP

    # Drop Admin port access
    iptables -A INPUT -p tcp --dport ${ADMIN_PORT} -j DROP

    # Drop all other incoming traffic
    iptables -A INPUT -j DROP

    log_info "IPv4 rules configured successfully"
}

# Configure IPv6 rules (conservative: drop all incoming by default)
configure_ipv6() {
    log_info "Configuring IPv6 ip6tables rules..."

    # Set default policies
    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT ACCEPT
    ip6tables -P FORWARD DROP

    # Accept loopback traffic
    ip6tables -A INPUT -i lo -j ACCEPT

    # Accept established and related connections
    ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packets
    ip6tables -A INPUT -m state --state INVALID -j DROP

    # Allow SSH with rate limiting
    ip6tables -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 5 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -j DROP

    # Allow P2P if using IPv6
    ip6tables -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -m limit --limit 10/min --limit-burst 20 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport ${P2P_PORT} -m state --state NEW -j DROP
    ip6tables -A INPUT -p udp --dport ${P2P_PORT} -j ACCEPT

    # Drop sensitive ports
    ip6tables -A INPUT -p tcp --dport ${RPC_PORT} -j DROP
    ip6tables -A INPUT -p tcp --dport ${ADMIN_PORT} -j DROP

    # Drop all other incoming traffic
    ip6tables -A INPUT -j DROP

    log_info "IPv6 rules configured successfully"
}

# Save rules to persistent files
save_rules() {
    log_info "Saving iptables rules to persistent files..."

    # Create directory if needed
    mkdir -p /etc/iptables

    # Save IPv4 rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4
        log_info "IPv4 rules saved to /etc/iptables/rules.v4"
    fi

    # Save IPv6 rules
    if command -v ip6tables-save &> /dev/null; then
        ip6tables-save > /etc/iptables/rules.v6
        log_info "IPv6 rules saved to /etc/iptables/rules.v6"
    fi

    # Create systemd service to restore rules on boot
    if [[ ! -f /etc/systemd/system/iptables-restore.service ]]; then
        log_info "Creating iptables-restore systemd service..."
        cat > /etc/systemd/system/iptables-restore.service << 'SYSTEMD_EOF'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
        systemctl daemon-reload
        systemctl enable iptables-restore.service
    fi
}

# Show current rules
show_rules() {
    log_info "Current IPv4 iptables rules:"
    echo ""
    iptables -L -n -v
    echo ""
    log_info "Current IPv6 ip6tables rules:"
    echo ""
    ip6tables -L -n -v
    echo ""
}

# Main execution
main() {
    check_root
    reset_policies
    flush_rules
    configure_ipv4
    configure_ipv6
    save_rules
    show_rules
}

main "$@"
