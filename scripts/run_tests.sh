#!/usr/bin/env bash
#
# run_tests.sh -- run all x87 test binaries under native Rosetta and the
# custom runtime_loader, checking self-reported PASS/FAIL output.
#
# Usage:
#   bash scripts/run_tests.sh                # build + test (both phases)
#   bash scripts/run_tests.sh --no-build     # skip build
#   bash scripts/run_tests.sh --native-only  # Phase 1 only (no runtime_loader)
#   bash scripts/run_tests.sh test_arith     # only run specific test(s)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
BIN="$BUILD_DIR/bin"
LOADER="$BIN/runtime_loader"

ALL_TESTS=(
    test_fldconst
    test_fld
    test_fld_m80fp
    test_fmul
    test_fild
    test_fcom
    test_fcomp_mem
    test_peephole
    test_arith
    test_compare_unary
    test_fld_fst
    test_peephole3
    test_peephole4
    test_peephole5
    test_peephole6
    test_deep_stack
    test_x87_full
    test_fstpt
    test_fxam
    test_peephole7
    test_fcom_nzcv
    test_store_forward
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DO_BUILD=1
NATIVE_ONLY=0
SELECTED_TESTS=()
for arg in "$@"; do
    if [[ "$arg" == "--no-build" ]]; then
        DO_BUILD=0
    elif [[ "$arg" == "--native-only" ]]; then
        NATIVE_ONLY=1
    else
        SELECTED_TESTS+=("$arg")
    fi
done

if [[ ${#SELECTED_TESTS[@]} -gt 0 ]]; then
    TESTS=("${SELECTED_TESTS[@]}")
else
    TESTS=("${ALL_TESTS[@]}")
fi

if [[ $DO_BUILD -eq 1 ]]; then
    echo -e "${CYAN}Building...${NC}"
    cmake --build "$BUILD_DIR" --parallel 2>&1 | tail -3
    echo ""
fi

# Strip runtime-internal noise lines before checking output
filter_runtime_lines() {
    grep -v -E 'RosettaRuntimex87 built|Installing JIT|JIT Translation Hook|try_fuse_|CORE_LOG'
}

TOTAL=0
PASSED=0
FAILED=0
ERRORS=0

check_output() {
    local name="$1"
    local out="$2"
    TOTAL=$((TOTAL + 1))
    if echo "$out" | grep -qE 'FAIL'; then
        echo -e "${RED}FAIL${NC}  $name"
        FAILED=$((FAILED + 1))
        echo "$out" | grep -E 'FAIL' | head -10 | sed 's/^/      /'
    else
        echo -e "${GREEN}PASS${NC}  $name"
        PASSED=$((PASSED + 1))
    fi
}

# ── Phase 1: native Rosetta ───────────────────────────────────────────────────
echo -e "${BOLD}=== Phase 1: native Rosetta ===${NC}"

for t in "${TESTS[@]}"; do
    BINARY="$BIN/$t"
    if [[ ! -x "$BINARY" ]]; then
        echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    OUT=$("$BINARY" 2>/dev/null || true)
    check_output "$t" "$OUT"
done

# ── Phase 2: runtime_loader ───────────────────────────────────────────────────
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 2: runtime_loader ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$("$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

echo ""
echo "================================================================"
echo -e "Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${ERRORS} skipped${NC} / ${TOTAL} total"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
