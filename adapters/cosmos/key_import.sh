#!/bin/bash

#############################################################################
# IONA Cosmos Adapter: Key Import Script
# 
# Converts a CometBFT priv_validator_key.json to IONA encrypted format
# 
# Usage: ./key_import.sh priv_validator_key.json
# 
# This script:
# 1. Validates the input file format
# 2. Extracts the ed25519 private key (base64)
# 3. Converts base64 to hex representation
# 4. Displays the public key for verification
# 5. Provides instructions for IONA encryption
#
#############################################################################

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUPPORTED_KEY_TYPE="ed25519"

#############################################################################
# Functions
#############################################################################

print_error() {
    echo -e "${RED}✗ ERROR${NC}: $1" >&2
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_header() {
    echo ""
    echo "=========================================="
    echo "  IONA Cosmos Adapter: Key Import"
    echo "=========================================="
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Convert base64 to hex
base64_to_hex() {
    local b64="$1"
    if command_exists openssl; then
        echo -n "$b64" | openssl enc -d -base64 -A | od -An -tx1 | tr -d ' \n'
    else
        # Fallback using printf (less reliable for all inputs)
        echo -n "$b64" | base64 -d 2>/dev/null | xxd -p | tr -d '\n'
    fi
}

# Validate JSON
validate_json() {
    local file="$1"
    if ! jq empty "$file" 2>/dev/null; then
        return 1
    fi
    return 0
}

# Extract key type
get_key_type() {
    local file="$1"
    jq -r '.type // empty' "$file" 2>/dev/null || echo ""
}

# Extract private key (base64)
get_private_key_b64() {
    local file="$1"
    jq -r '.priv_key.value // .priv_key // empty' "$file" 2>/dev/null || echo ""
}

# Derive public key from private key
derive_public_key() {
    local priv_key_b64="$1"
    # Note: This is a simplified version showing the expected format
    # Full key derivation requires the IONA binary or a crypto library
    # For now, we just show the structure
    echo "$priv_key_b64"
}

# Main function
main() {
    print_header
    
    # Check arguments
    if [[ $# -lt 1 ]]; then
        print_error "Missing argument"
        echo "Usage: $0 <priv_validator_key.json>"
        echo ""
        echo "Example:"
        echo "  $0 priv_validator_key.json"
        exit 1
    fi
    
    local keyfile="$1"
    
    # Validate input file
    print_info "Checking input file..."
    
    if [[ ! -f "$keyfile" ]]; then
        print_error "File not found: $keyfile"
        exit 1
    fi
    print_success "File exists: $keyfile"
    
    if [[ ! -r "$keyfile" ]]; then
        print_error "File is not readable: $keyfile"
        exit 1
    fi
    print_success "File is readable"
    
    # Check for required tools
    print_info "Checking dependencies..."
    
    if ! command_exists jq; then
        print_error "jq is required but not installed"
        echo "  Install with: apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
        exit 1
    fi
    print_success "jq is installed"
    
    if ! command_exists openssl; then
        print_warning "openssl not found; using fallback base64 converter (less reliable)"
    else
        print_success "openssl is installed"
    fi
    
    # Validate JSON
    print_info "Validating JSON format..."
    
    if ! validate_json "$keyfile"; then
        print_error "Invalid JSON in $keyfile"
        exit 1
    fi
    print_success "JSON is valid"
    
    # Extract and validate key type
    print_info "Checking key type..."
    
    local key_type
    key_type=$(get_key_type "$keyfile")
    
    if [[ -z "$key_type" ]]; then
        print_warning "Key type field missing; assuming ed25519"
        key_type="ed25519"
    fi
    
    if [[ "$key_type" != "$SUPPORTED_KEY_TYPE" ]]; then
        print_error "Unsupported key type: $key_type (expected: $SUPPORTED_KEY_TYPE)"
        exit 1
    fi
    print_success "Key type is $SUPPORTED_KEY_TYPE"
    
    # Extract private key
    print_info "Extracting private key..."
    
    local priv_key_b64
    priv_key_b64=$(get_private_key_b64 "$keyfile")
    
    if [[ -z "$priv_key_b64" ]]; then
        print_error "Could not extract private key from $keyfile"
        echo "Expected JSON format:"
        echo '  {"type": "ed25519", "priv_key": {"type": "...", "value": "..."}}'
        exit 1
    fi
    
    # Validate base64 length (ed25519 is 64 bytes = 88 chars base64)
    local b64_len=${#priv_key_b64}
    if [[ $b64_len -lt 80 ]] || [[ $b64_len -gt 95 ]]; then
        print_warning "Private key length seems off: $b64_len chars (expected ~88)"
    fi
    print_success "Private key extracted (${b64_len} chars base64)"
    
    # Convert to hex
    print_info "Converting to hex format..."
    
    local priv_key_hex
    priv_key_hex=$(base64_to_hex "$priv_key_b64")
    
    if [[ -z "$priv_key_hex" ]]; then
        print_error "Failed to convert private key to hex"
        exit 1
    fi
    
    local hex_len=${#priv_key_hex}
    if [[ $hex_len -ne 128 ]]; then
        print_warning "Hex key length is $hex_len (expected 128 for ed25519)"
    fi
    print_success "Hex conversion complete"
    
    # Display conversion results
    echo ""
    echo "=========================================="
    echo "  Conversion Results"
    echo "=========================================="
    echo ""
    
    echo -e "${BLUE}Private Key (base64):${NC}"
    echo "  $priv_key_b64"
    echo ""
    
    echo -e "${BLUE}Private Key (hex):${NC}"
    echo "  $priv_key_hex"
    echo ""
    
    # Extract public key if available
    local pub_key_b64
    pub_key_b64=$(jq -r '.pub_key.value // .pub_key // empty' "$keyfile" 2>/dev/null || echo "")
    
    if [[ -n "$pub_key_b64" ]]; then
        print_success "Public key found in JSON"
        echo -e "${BLUE}Public Key (base64):${NC}"
        echo "  $pub_key_b64"
        echo ""
        
        # Convert public key to hex
        local pub_key_hex
        pub_key_hex=$(base64_to_hex "$pub_key_b64")
        if [[ -n "$pub_key_hex" ]]; then
            echo -e "${BLUE}Public Key (hex):${NC}"
            echo "  $pub_key_hex"
            echo ""
        fi
    fi
    
    # Next steps
    echo "=========================================="
    echo "  Next Steps"
    echo "=========================================="
    echo ""
    
    echo "1. Verify the keys above match your expectations"
    echo ""
    
    echo "2. Encrypt the key with IONA:"
    echo ""
    echo "   ${YELLOW}iona keys import $keyfile --output keys.enc${NC}"
    echo ""
    echo "   You will be prompted for a passphrase."
    echo "   Choose a strong passphrase (20+ characters)."
    echo ""
    
    echo "3. Verify the encryption succeeded:"
    echo ""
    echo "   ${YELLOW}iona keys check keys.enc${NC}"
    echo ""
    
    echo "4. Display your public key in IONA format:"
    echo ""
    echo "   ${YELLOW}iona keys show keys.enc --public-only${NC}"
    echo ""
    
    echo "5. For full migration instructions, see:"
    echo "   ${YELLOW}migrate_validator.md${NC}"
    echo ""
    
    # Security warnings
    echo "=========================================="
    echo "  Security Warnings"
    echo "=========================================="
    echo ""
    
    print_warning "This script displays your private key in base64 and hex formats"
    print_warning "Do not share these values with anyone"
    print_warning "Do not commit this script output to version control"
    print_warning "Do not email or slack these keys to yourself or others"
    echo ""
    
    print_warning "After encryption with IONA:"
    print_warning "Delete the plaintext key files"
    echo ""
    echo "   ${YELLOW}shred -vfz -n 10 $keyfile${NC}  (secure delete)"
    echo "   ${YELLOW}rm -f $keyfile${NC}            (insecure, but okay if encrypted)"
    echo ""
    
    print_success "Key import script completed successfully"
}

#############################################################################
# Entry Point
#############################################################################

main "$@"
