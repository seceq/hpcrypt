#!/bin/bash
#
# Test script for running PQC tests with different SIMD intrinsics configurations
#
# Usage:
#   ./tests/scripts/test-intrinsics.sh portable  # Test with scalar/portable implementation only
#   ./tests/scripts/test-intrinsics.sh avx2      # Test with AVX2 intrinsics (x86_64)
#   ./tests/scripts/test-intrinsics.sh neon      # Test with NEON intrinsics via cross/QEMU (aarch64)
#   ./tests/scripts/test-intrinsics.sh all       # Run all configurations
#
# Test suites:
#   CAVP tests (NIST official test vectors)
#   Wycheproof tests (Google's crypto test vectors)
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

# Run tests for a specific configuration
run_tests() {
    local config="$1"
    local test_suite="$2"
    local features=""
    local runner="cargo"
    local target=""

    case "$config" in
        portable)
            features="enable-pqc-tests"
            ;;
        avx2)
            features="enable-pqc-tests,avx2"
            # Check if we're on x86_64
            if [[ "$(uname -m)" != "x86_64" ]]; then
                print_warning "Skipping AVX2 tests: not on x86_64 architecture"
                return 0
            fi
            ;;
        neon)
            features="enable-pqc-tests,neon"
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
        cmd="cross test --package $test_suite --target $target --features \"$features\" -- --nocapture"
    else
        cmd="cargo test --package $test_suite --features \"$features\" -- --nocapture"
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

# Run all test suites for a configuration
run_all_suites() {
    local config="$1"
    local failed=0

    # CAVP tests
    if ! run_tests "$config" "cavp-tests"; then
        failed=1
    fi

    # Wycheproof tests
    if ! run_tests "$config" "wycheproof-tests"; then
        failed=1
    fi

    return $failed
}

# Main
main() {
    local mode="${1:-all}"
    local failed=0

    print_header "PQC Intrinsics Test Suite"
    echo "Mode: $mode"
    echo "Project root: $PROJECT_ROOT"
    echo ""

    case "$mode" in
        portable)
            if ! run_all_suites "portable"; then
                failed=1
            fi
            ;;
        avx2)
            if ! run_all_suites "avx2"; then
                failed=1
            fi
            ;;
        neon)
            if ! run_all_suites "neon"; then
                failed=1
            fi
            ;;
        all)
            print_header "Running ALL configurations"

            # Portable
            if ! run_all_suites "portable"; then
                failed=1
            fi

            # AVX2 (only on x86_64)
            if [[ "$(uname -m)" == "x86_64" ]]; then
                if ! run_all_suites "avx2"; then
                    failed=1
                fi
            fi

            # NEON via cross (if available)
            if check_cross; then
                if ! run_all_suites "neon"; then
                    failed=1
                fi
            fi
            ;;
        help|--help|-h)
            echo "Usage: $0 [portable|avx2|neon|all]"
            echo ""
            echo "Configurations:"
            echo "  portable  - Test with scalar/portable implementation"
            echo "  avx2      - Test with AVX2 intrinsics (x86_64 only)"
            echo "  neon      - Test with NEON intrinsics via cross/QEMU"
            echo "  all       - Run all applicable configurations"
            echo ""
            echo "Test suites included:"
            echo "  - cavp-tests (NIST CAVP/ACVP test vectors)"
            echo "  - wycheproof-tests (Google Wycheproof test vectors)"
            exit 0
            ;;
        *)
            print_error "Unknown mode: $mode"
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
