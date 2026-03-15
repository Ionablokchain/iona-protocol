#!/usr/bin/env bash
set -euo pipefail

# Defaults
FORCE=0
INTERFACE=""
VERBOSE=0

show_help() {
    cat <<EOF
Usage: $0 [options] [interface]

Remove network emulation (netem) settings from a network interface.

Options:
  -f, --force           Skip confirmation prompt.
  -v, --verbose         Show current qdisc settings before clearing.
  -h, --help            Display this help message.

Arguments:
  interface             Network interface (e.g., eth0). If omitted, you will be prompted.

Examples:
  sudo $0 eth0          # Clear netem on eth0 (with confirmation)
  sudo $0 -f eth0       # Force clear without confirmation
  sudo $0 -v eth0       # Show current settings then clear

Note: This script must be run as root (use sudo).
EOF
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force)
            FORCE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            show_help
            exit 1
            ;;
        *)
            # First non-option argument is the interface
            INTERFACE="$1"
            shift
            break
            ;;
    esac
done

# If interface still empty, prompt
if [[ -z "$INTERFACE" ]]; then
    read -p "Enter network interface (e.g., eth0): " INTERFACE
fi

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root. Use sudo." >&2
    exit 1
fi

# Interface existence check
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Error: Interface $INTERFACE does not exist." >&2
    exit 1
fi

# Optional: show current qdisc
if [[ $VERBOSE -eq 1 ]]; then
    echo "Current qdisc on $INTERFACE:"
    tc qdisc show dev "$INTERFACE" || echo "No qdisc configured."
fi

# Confirmation unless forced
if [[ $FORCE -eq 0 ]]; then
    read -p "Clear netem on $INTERFACE? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Attempt to delete root qdisc
if tc qdisc del dev "$INTERFACE" root 2>/dev/null; then
    echo "Netem cleared on $INTERFACE."
else
    echo "No netem settings found on $INTERFACE or removal failed." >&2
    exit 1
fi
