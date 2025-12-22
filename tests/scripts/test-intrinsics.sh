#!/bin/bash
#
# Test script for running intrinsics tests with different SIMD configurations
#
# Usage:
#   ./tests/scripts/test-intrinsics.sh pqc [portable|avx2|neon|all]   # Test PQC intrinsics
#   ./tests/scripts/test-intrinsics.sh mac [portable|avx2|neon|all]   # Test MAC intrinsics
#   ./tests/scripts/test-intrinsics.sh hash [portable|avx2|neon|all]  # Test hash intrinsics
#   ./tests/scripts/test-intrinsics.sh all [portable|avx2|neon|all]   # Test all intrinsics
#
# PQC Test suites:
#   - CAVP tests (NIST official test vectors for ML-KEM, ML-DSA)
#   - Wycheproof tests (Google's crypto test vectors)
#
# MAC Test suites:
#   - GHASH (GCM authentication)
#   - POLYVAL (AES-GCM-SIV authentication)
#
# Hash Test suites:
#   - 1-way: CAVP SHA3/SHAKE + hpcrypt-hash sha3 unit tests + RFC TurboSHAKE
#   - 4-way: CAVP SHAKE x4 + hpcrypt-hash x4 unit tests
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

print_header() {
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

# Check if cross is installed (needed for NEON testing)
check_cross() {
    if ! command -v cross &> /dev/null; then
        print_warning "Warning: 'cross' is not installed. Install it with: cargo install cross"
        print_warning "NEON tests will be skipped."
        return 1
    fi
    return 0
}

# Check if CPU supports AVX2+PCLMULQDQ
check_avx2_support() {
    if [[ "$(uname -m)" != "x86_64" ]]; then
        return 1
    fi
    if grep -q "avx2" /proc/cpuinfo 2>/dev/null && grep -q "pclmulqdq" /proc/cpuinfo 2>/dev/null; then
        return 0
    fi
    return 1
}

# Run PQC tests for a specific configuration
run_pqc_tests() {
    local config="$1"
    local test_suite="$2"
    local features=""
    local runner="cargo"
    local target=""

    case "$config" in
        portable)
            ;;
        avx2)
            features="avx2"
            if [[ "$(uname -m)" != "x86_64" ]]; then
                print_warning "Skipping AVX2 tests: not on x86_64 architecture"
                return 0
            fi
            ;;
        neon)
            features="neon"
            runner="cross"
            target="aarch64-unknown-linux-gnu"
            if ! check_cross; then
                return 0
            fi
            ;;
        *)
            print_error "Unknown configuration: $config"
            return 1
            ;;
    esac

    print_header "Running $test_suite tests with $config implementation"

    local cmd=""
    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package $test_suite --target $target --features \"$features\" -- --nocapture"
        else
            cmd="cross test --package $test_suite --target $target -- --nocapture"
        fi
    else
        if [[ -n "$features" ]]; then
            cmd="cargo test --package $test_suite --features \"$features\" -- --nocapture"
        else
            cmd="cargo test --package $test_suite -- --nocapture"
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: $test_suite with $config"
        return 0
    else
        print_error "FAILED: $test_suite with $config"
        return 1
    fi
}

# Run all PQC test suites for a configuration
run_pqc_suites() {
    local config="$1"
    local failed=0

    # CAVP tests (ML-KEM, ML-DSA only - never enable SLH-DSA tests)
    if ! run_pqc_tests "$config" "cavp-tests"; then
        failed=1
    fi

    # Wycheproof tests (only ML-KEM and ML-DSA tests)
    if ! run_pqc_wycheproof_tests "$config"; then
        failed=1
    fi

    return $failed
}

# Run only PQC-related Wycheproof tests (ML-KEM, ML-DSA)
run_pqc_wycheproof_tests() {
    local config="$1"
    local features=""
    local runner="cargo"
    local target=""

    case "$config" in
        portable)
            ;;
        avx2)
            features="avx2"
            if [[ "$(uname -m)" != "x86_64" ]]; then
                print_warning "Skipping AVX2 tests: not on x86_64 architecture"
                return 0
            fi
            ;;
        neon)
            features="neon"
            runner="cross"
            target="aarch64-unknown-linux-gnu"
            if ! check_cross; then
                return 0
            fi
            ;;
        *)
            print_error "Unknown configuration: $config"
            return 1
            ;;
    esac

    print_header "Running wycheproof-tests (ML-KEM, ML-DSA) with $config implementation"

    local cmd=""
    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package wycheproof-tests --target $target --features \"$features\" --test mlkem --test mldsa -- --nocapture"
        else
            cmd="cross test --package wycheproof-tests --target $target --test mlkem --test mldsa -- --nocapture"
        fi
    else
        if [[ -n "$features" ]]; then
            cmd="cargo test --package wycheproof-tests --features \"$features\" --test mlkem --test mldsa -- --nocapture"
        else
            cmd="cargo test --package wycheproof-tests --test mlkem --test mldsa -- --nocapture"
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: wycheproof-tests (ML-KEM, ML-DSA) with $config"
        return 0
    else
        print_error "FAILED: wycheproof-tests (ML-KEM, ML-DSA) with $config"
        return 1
    fi
}

# Run MAC intrinsics tests for a specific configuration
# Only tests GHASH and POLYVAL (the only primitives with intrinsics)
run_mac_tests() {
    local config="$1"
    local runner="cargo"
    local target=""
    local rustflags=""
    local features=""
    local failed=0

    case "$config" in
        portable)
            # No special flags, use default portable implementation
            ;;
        avx2)
            if [[ "$(uname -m)" != "x86_64" ]]; then
                print_warning "Skipping AVX2 tests: not on x86_64 architecture"
                return 0
            fi
            if ! check_avx2_support; then
                print_warning "Skipping AVX2 tests: CPU does not support AVX2+PCLMULQDQ"
                return 0
            fi
            # Use target-cpu=native to enable all CPU features for cfg detection
            rustflags="-C target-cpu=native"
            features="avx2"
            ;;
        neon)
            runner="cross"
            target="aarch64-unknown-linux-gnu"
            features="neon"
            if ! check_cross; then
                return 0
            fi
            ;;
        *)
            print_error "Unknown configuration: $config"
            return 1
            ;;
    esac

    # Test GHASH and POLYVAL from hpcrypt-mac
    print_header "Running GHASH/POLYVAL unit tests with $config implementation"

    local cmd=""
    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package hpcrypt-mac --target $target --features \"$features\" -- --nocapture ghash polyval"
        else
            cmd="cross test --package hpcrypt-mac --target $target -- --nocapture ghash polyval"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-mac --features \"$features\" -- --nocapture ghash polyval"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-mac -- --nocapture ghash polyval"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package hpcrypt-mac --features \"$features\" -- --nocapture ghash polyval"
            else
                cmd="cargo test --package hpcrypt-mac -- --nocapture ghash polyval"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: hpcrypt-mac GHASH/POLYVAL with $config"
    else
        print_error "FAILED: hpcrypt-mac GHASH/POLYVAL with $config"
        failed=1
    fi

    # Test GHASH and POLYVAL from rfc-tests
    print_header "Running RFC test vectors for GHASH/POLYVAL with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package rfc-tests --target $target --features \"enable-mac-tests,$features\" --test ghash --test polyval -- --nocapture"
        else
            cmd="cross test --package rfc-tests --target $target --features enable-mac-tests --test ghash --test polyval -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package rfc-tests --features \"enable-mac-tests,$features\" --test ghash --test polyval -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package rfc-tests --features enable-mac-tests --test ghash --test polyval -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package rfc-tests --features \"enable-mac-tests,$features\" --test ghash --test polyval -- --nocapture"
            else
                cmd="cargo test --package rfc-tests --features enable-mac-tests --test ghash --test polyval -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: rfc-tests GHASH/POLYVAL with $config"
    else
        print_error "FAILED: rfc-tests GHASH/POLYVAL with $config"
        failed=1
    fi

    return $failed
}

# Run hash (Keccak) intrinsics tests for a specific configuration
# Tests both 1-way (single state) and 4-way (parallel) implementations
run_hash_tests() {
    local config="$1"
    local runner="cargo"
    local target=""
    local rustflags=""
    local features=""
    local failed=0

    case "$config" in
        portable)
            # No special flags, use default portable implementation
            ;;
        avx2)
            if [[ "$(uname -m)" != "x86_64" ]]; then
                print_warning "Skipping AVX2 tests: not on x86_64 architecture"
                return 0
            fi
            if ! check_avx2_support; then
                print_warning "Skipping AVX2 tests: CPU does not support AVX2"
                return 0
            fi
            rustflags="-C target-cpu=native"
            features="avx2"
            ;;
        neon)
            runner="cross"
            target="aarch64-unknown-linux-gnu"
            features="neon"
            if ! check_cross; then
                return 0
            fi
            ;;
        *)
            print_error "Unknown configuration: $config"
            return 1
            ;;
    esac

    # =========================================================================
    # Test 1a: 1-way Keccak intrinsics via CAVP SHA3/SHAKE tests
    # Tests keccak_f1600 (24-round) through Sha3_*, Shake* high-level APIs
    # Validates against official NIST FIPS 202 test vectors
    # =========================================================================
    print_header "Running CAVP SHA3/SHAKE tests (1-way keccak_f1600) with $config implementation"

    local cmd=""
    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package cavp-tests --target $target --features \"enable-hash-tests,$features\" --test sha3 -- --nocapture"
        else
            cmd="cross test --package cavp-tests --target $target --features enable-hash-tests --test sha3 -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package cavp-tests --features \"enable-hash-tests,$features\" --test sha3 -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package cavp-tests --features enable-hash-tests --test sha3 -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package cavp-tests --features \"enable-hash-tests,$features\" --test sha3 -- --nocapture"
            else
                cmd="cargo test --package cavp-tests --features enable-hash-tests --test sha3 -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: CAVP SHA3/SHAKE (1-way) with $config"
    else
        print_error "FAILED: CAVP SHA3/SHAKE (1-way) with $config"
        failed=1
    fi

    # =========================================================================
    # Test 1b: 1-way Keccak intrinsics via hpcrypt-hash sha3 unit tests
    # Tests keccak_f1600 through Sha3_*, Shake* APIs
    # Validates intrinsics output matches reference implementation
    # =========================================================================
    print_header "Running hpcrypt-hash SHA3 unit tests (1-way) with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package hpcrypt-hash --target $target --features \"std,$features\" --lib sha3 -- --nocapture"
        else
            cmd="cross test --package hpcrypt-hash --target $target --features std --lib sha3 -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features \"std,$features\" --lib sha3 -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features std --lib sha3 -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package hpcrypt-hash --features \"std,$features\" --lib sha3 -- --nocapture"
            else
                cmd="cargo test --package hpcrypt-hash --features std --lib sha3 -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: hpcrypt-hash SHA3 unit tests with $config"
    else
        print_error "FAILED: hpcrypt-hash SHA3 unit tests with $config"
        failed=1
    fi

    # =========================================================================
    # Test 2a: 4-way Keccak intrinsics via CAVP SHAKE x4 tests
    # Tests keccak_f1600_x4 through Shake128x4/Shake256x4 APIs
    # Validates against official NIST FIPS 202 test vectors
    # =========================================================================
    print_header "Running CAVP SHAKE x4 tests (4-way keccak_f1600_x4) with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package cavp-tests --target $target --features \"enable-hash-tests,$features\" --test shake_x4 -- --nocapture"
        else
            cmd="cross test --package cavp-tests --target $target --features enable-hash-tests --test shake_x4 -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package cavp-tests --features \"enable-hash-tests,$features\" --test shake_x4 -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package cavp-tests --features enable-hash-tests --test shake_x4 -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package cavp-tests --features \"enable-hash-tests,$features\" --test shake_x4 -- --nocapture"
            else
                cmd="cargo test --package cavp-tests --features enable-hash-tests --test shake_x4 -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: CAVP SHAKE x4 (4-way) with $config"
    else
        print_error "FAILED: CAVP SHAKE x4 (4-way) with $config"
        failed=1
    fi

    # =========================================================================
    # Test 2b: 4-way Keccak intrinsics via hpcrypt-hash shake_x4 unit tests
    # Validates 4-way output matches sequential 1-way output
    # =========================================================================
    print_header "Running hpcrypt-hash SHAKE x4 unit tests (4-way vs 1-way) with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package hpcrypt-hash --target $target --features \"std,$features\" --lib shake_x4 -- --nocapture"
        else
            cmd="cross test --package hpcrypt-hash --target $target --features std --lib shake_x4 -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features \"std,$features\" --lib shake_x4 -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features std --lib shake_x4 -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package hpcrypt-hash --features \"std,$features\" --lib shake_x4 -- --nocapture"
            else
                cmd="cargo test --package hpcrypt-hash --features std --lib shake_x4 -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: hpcrypt-hash SHAKE x4 unit tests with $config"
    else
        print_error "FAILED: hpcrypt-hash SHAKE x4 unit tests with $config"
        failed=1
    fi

    # =========================================================================
    # Test 3: Keccak intrinsics unit tests (1-way + 4-way vs reference impl)
    # Direct tests of keccak_f1600_avx2/neon and keccak_f1600_x4 against
    # a pure Rust reference implementation
    # =========================================================================
    print_header "Running Keccak intrinsics unit tests (1-way + 4-way) with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package hpcrypt-hash --target $target --features \"std,$features\" --lib intrinsics -- --nocapture"
        else
            cmd="cross test --package hpcrypt-hash --target $target --features std --lib intrinsics -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features \"std,$features\" --lib intrinsics -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package hpcrypt-hash --features std --lib intrinsics -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package hpcrypt-hash --features \"std,$features\" --lib intrinsics -- --nocapture"
            else
                cmd="cargo test --package hpcrypt-hash --features std --lib intrinsics -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: Keccak intrinsics unit tests with $config"
    else
        print_error "FAILED: Keccak intrinsics unit tests with $config"
        failed=1
    fi

    # =========================================================================
    # Test 4: TurboSHAKE tests (1-way keccak_p12 - 12-round variant)
    # Tests keccak_p12 through TurboShake128/TurboShake256 high-level APIs
    # =========================================================================
    print_header "Running RFC TurboSHAKE tests (1-way keccak_p12) with $config implementation"

    if [[ "$runner" == "cross" ]]; then
        if [[ -n "$features" ]]; then
            cmd="cross test --package rfc-tests --target $target --features \"enable-hash-tests,$features\" --test turboshake -- --nocapture"
        else
            cmd="cross test --package rfc-tests --target $target --features enable-hash-tests --test turboshake -- --nocapture"
        fi
    else
        if [[ -n "$rustflags" ]]; then
            if [[ -n "$features" ]]; then
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package rfc-tests --features \"enable-hash-tests,$features\" --test turboshake -- --nocapture"
            else
                cmd="RUSTFLAGS=\"$rustflags\" cargo test --package rfc-tests --features enable-hash-tests --test turboshake -- --nocapture"
            fi
        else
            if [[ -n "$features" ]]; then
                cmd="cargo test --package rfc-tests --features \"enable-hash-tests,$features\" --test turboshake -- --nocapture"
            else
                cmd="cargo test --package rfc-tests --features enable-hash-tests --test turboshake -- --nocapture"
            fi
        fi
    fi

    echo "Command: $cmd"
    echo ""

    if eval "$cmd"; then
        print_success "PASSED: RFC TurboSHAKE (keccak_p12) with $config"
    else
        print_error "FAILED: RFC TurboSHAKE (keccak_p12) with $config"
        failed=1
    fi

    return $failed
}

# Run tests for a specific suite type and configuration
run_suite() {
    local suite="$1"
    local config="$2"
    local failed=0

    case "$suite" in
        pqc)
            if ! run_pqc_suites "$config"; then
                failed=1
            fi
            ;;
        mac)
            if ! run_mac_tests "$config"; then
                failed=1
            fi
            ;;
        hash)
            if ! run_hash_tests "$config"; then
                failed=1
            fi
            ;;
        all)
            if ! run_pqc_suites "$config"; then
                failed=1
            fi
            if ! run_mac_tests "$config"; then
                failed=1
            fi
            if ! run_hash_tests "$config"; then
                failed=1
            fi
            ;;
    esac

    return $failed
}

# Run all configurations for a suite
run_all_configs() {
    local suite="$1"
    local failed=0

    print_header "Running ALL configurations for $suite"

    # Portable (always runs)
    if ! run_suite "$suite" "portable"; then
        failed=1
    fi

    # AVX2 (only on x86_64 with support)
    if [[ "$(uname -m)" == "x86_64" ]]; then
        if ! run_suite "$suite" "avx2"; then
            failed=1
        fi
    else
        print_warning "Skipping AVX2: not on x86_64 architecture"
    fi

    # NEON via cross (if available)
    if check_cross; then
        if ! run_suite "$suite" "neon"; then
            failed=1
        fi
    fi

    return $failed
}

# Print usage
print_usage() {
    echo "Usage: $0 <suite> [config]"
    echo ""
    echo "Suites:"
    echo "  pqc   - Test PQC intrinsics (ML-KEM, ML-DSA)"
    echo "  mac   - Test MAC intrinsics (GHASH, POLYVAL)"
    echo "  hash  - Test hash intrinsics (Keccak/SHA-3 1-way and 4-way)"
    echo "  all   - Test all intrinsics"
    echo ""
    echo "Configurations:"
    echo "  portable  - Test with portable/scalar implementation"
    echo "  avx2      - Test with AVX2 intrinsics (x86_64 only)"
    echo "  neon      - Test with NEON intrinsics via cross/QEMU"
    echo "  all       - Run all applicable configurations (default)"
    echo ""
    echo "Examples:"
    echo "  $0 pqc              # Run PQC tests with all configs"
    echo "  $0 pqc avx2         # Run PQC tests with AVX2 only"
    echo "  $0 mac neon         # Run MAC tests with NEON only"
    echo "  $0 hash avx2        # Run hash tests with AVX2 only"
    echo "  $0 all              # Run all tests with all configs"
    echo ""
    echo "Test suites:"
    echo "  PQC:"
    echo "    - cavp-tests (NIST CAVP/ACVP test vectors for ML-KEM, ML-DSA)"
    echo "    - wycheproof-tests (Google Wycheproof test vectors)"
    echo "  MAC:"
    echo "    - GHASH (GCM authentication)"
    echo "    - POLYVAL (AES-GCM-SIV authentication)"
    echo "  Hash:"
    echo "    - 1-way: CAVP SHA3/SHAKE + hpcrypt-hash sha3 unit tests + RFC TurboSHAKE"
    echo "    - 4-way: CAVP SHAKE x4 + hpcrypt-hash x4 unit tests"
}

# Main
main() {
    local suite="${1:-}"
    local config="${2:-all}"
    local failed=0

    # Handle help
    if [[ "$suite" == "help" || "$suite" == "--help" || "$suite" == "-h" || -z "$suite" ]]; then
        print_usage
        exit 0
    fi

    # Validate suite
    case "$suite" in
        pqc|mac|hash|all)
            ;;
        *)
            print_error "Unknown suite: $suite"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac

    print_header "Intrinsics Test Suite"
    echo "Suite: $suite"
    echo "Config: $config"
    echo "Project root: $PROJECT_ROOT"
    echo "Architecture: $(uname -m)"
    echo ""

    case "$config" in
        portable|avx2|neon)
            if ! run_suite "$suite" "$config"; then
                failed=1
            fi
            ;;
        all)
            if ! run_all_configs "$suite"; then
                failed=1
            fi
            ;;
        help|--help|-h)
            print_usage
            exit 0
            ;;
        *)
            print_error "Unknown config: $config"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac

    echo ""
    if [[ $failed -eq 0 ]]; then
        print_header "ALL TESTS PASSED"
        exit 0
    else
        print_header "SOME TESTS FAILED"
        exit 1
    fi
}

main "$@"
