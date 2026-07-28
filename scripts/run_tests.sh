#!/usr/bin/env bash
#
# run_tests.sh -- run all x87 test binaries under native Rosetta and the
# custom runtime_loader, checking self-reported PASS/FAIL output.
#
# Phases:
#   1. Native Rosetta (baseline)
#   2. runtime_loader (IR + fusions enabled, default config)
#   3. runtime_loader with ROSETTA_X87_DISABLE_IR=1 (direct translator only)
#   4. runtime_loader with ROSETTA_X87_DISABLE_IR=1 + ROSETTA_X87_DISABLE_ALL_FUSIONS=1
#   5. runtime_loader with ROSETTA_X87_RUN_BRIDGE=1 + ROSETTA_X87_EXTENDED_FPR_SCRATCH=1
#   6. runtime_loader with ROSETTA_X87_TRANSPARENT_INT=1 + ROSETTA_X87_BRIDGE_CARRY=1
#      + ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 + ROSETTA_X87_CONST_PROMOTE=1
#      + ROSETTA_X87_F32_NARROW=1  (the full opt-in stack)
#   7. runtime_loader with ROSETTA_X87_RUNTIME_KEEPALIVE=1 + the full opt-in stack
#   8. runtime_loader with ROSETTA_X87_DISABLE_ALL_OPS=1 + ROSETTA_X87_DISABLE_ALL_FUSIONS=1
#      + ROSETTA_X87_DISABLE_IR=1  (runtime routines only — pure X87.cpp coverage)
#
# Usage:
#   bash scripts/run_tests.sh                # build + test (all phases)
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
    test_fprem
    test_stackops
    test_peephole7
    test_fcom_nzcv
    test_arithp_fstp
    test_arith_faddp
    test_fstp_fld
    test_fistt
    test_tag_batch
    test_fld_arith_arithp_fma
    test_readst_elide
    test_fxch
    test_fxch_initial
    test_fldcw
    test_fcomi
    test_frndint
    test_fistp_multi
    test_fcmov
    test_ficom
    test_rc_recache
    test_fstpt_gs
    test_ir_deferred
    test_mem_cse
    test_fstsw_topdelta
    test_transparent_flags
    test_ir_algebra
    test_addr_fold
    test_const_promote
    test_f32_raw
    test_decoder_fcomp_st
    test_decoder_arpl
    test_ir_gpr_pressure
    test_int_regbase
    test_run_breaks
    test_transparent_int
    test_ir_fpr_pressure
    test_sse_whitelist
    test_bridge_pressure
    test_addr32
    test_keepalive
    test_fcos
    test_trig
    test_trig_ir
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
    elif echo "$out" | grep -qE 'SKIP'; then
        # Test self-reported SKIP (e.g. an opcode unsupported in this env, like
        # the 32-bit ARPL / DC-D8 tests under native Rosetta). Not a pass.
        echo -e "${YELLOW}SKIP${NC}  $name"
        ERRORS=$((ERRORS + 1))
        echo "$out" | grep -E 'SKIP' | head -1 | sed 's/^/      /'
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

# ── Phase 3: runtime_loader, IR disabled ─────────────────────────────────────
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 3: runtime_loader (IR disabled) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_DISABLE_IR=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 4: runtime_loader, IR disabled + all fusions disabled ──────────────
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 4: runtime_loader (IR disabled, fusions disabled) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_DISABLE_IR=1 ROSETTA_X87_DISABLE_ALL_FUSIONS=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 5: runtime_loader, candidate default-on flags ──────────────────────
# Exercises the opt-in flags that are candidates for default-on (run bridging
# + extended FPR scratch pool) so regressions in those paths are caught by
# the standard suite, not only by a game soak test.
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 5: runtime_loader (RUN_BRIDGE + EXTENDED_FPR_SCRATCH) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_RUN_BRIDGE=1 ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 6: runtime_loader, TRANSPARENT_INT ──────────────────────────────────
# Inlined guest integer instructions inside IR runs (implies RUN_BRIDGE).
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 6: runtime_loader (TRANSPARENT_INT + BRIDGE_CARRY + EXTENDED_FPR_SCRATCH) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_TRANSPARENT_INT=1 ROSETTA_X87_TRANSPARENT_FLAGS=1 ROSETTA_X87_BRIDGE_CARRY=1 ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 ROSETTA_X87_CONST_PROMOTE=1 ROSETTA_X87_F32_NARROW=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 7: runtime_loader, RUNTIME_KEEPALIVE (OPT-KA) ──────────────────────
# Keeps the pinned x87 cache alive across runtime-routine transcendentals
# (fsin/fcos/…), stacked on the full opt-in set so the keepalive prologue is
# exercised with carried pins and bridged gaps in play.
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 7: runtime_loader (RUNTIME_KEEPALIVE + full opt-in stack) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_RUNTIME_KEEPALIVE=1 ROSETTA_X87_TRANSPARENT_INT=1 ROSETTA_X87_TRANSPARENT_FLAGS=1 ROSETTA_X87_BRIDGE_CARRY=1 ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 ROSETTA_X87_CONST_PROMOTE=1 ROSETTA_X87_F32_NARROW=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 8: runtime_loader, all custom translation disabled ─────────────────
# Apple's stock codegen BL-ing into the hooked x87_* runtime routines — the
# purest exercise of the X87.cpp implementations (no custom singular
# translators, fusions, or IR inlining masking them). DISABLE_IR is redundant
# with ALL_OPS disabled but kept explicit.  The in-blob fast stubs are also
# disabled so the classic C handlers actually run (fast routing is
# independent of the translation flags).
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 8: runtime_loader (runtime routines only, custom translation disabled) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_ALL_FUSIONS=1 ROSETTA_X87_DISABLE_IR=1 \
              ROSETTA_X87_DISABLE_FCOS_FAST=1 ROSETTA_X87_DISABLE_FSIN_FAST=1 \
              ROSETTA_X87_DISABLE_FSINCOS_FAST=1 ROSETTA_X87_DISABLE_FPTAN_FAST=1 \
              ROSETTA_X87_DISABLE_FXAM_FAST=1 ROSETTA_X87_DISABLE_FXTRACT_FAST=1 \
              ROSETTA_X87_DISABLE_FPREM_FAST=1 ROSETTA_X87_DISABLE_FPREM1_FAST=1 \
              "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
        check_output "$t" "$OUT"
    done
fi

# ── Phase 9: runtime_loader, TRIG_IR (OPT-TI) ────────────────────────────────
# FCOS as a value call: IR runs keep ST(0) in an FPR across the BL to
# _stub_fcos_val.  Stacked on KEEPALIVE + EXTENDED_FPR_SCRATCH so the
# extended pool includes v16 and the run-level v16 exclusion is exercised.
if [[ $NATIVE_ONLY -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}=== Phase 9: runtime_loader (TRIG_IR + KEEPALIVE + EXTENDED_FPR_SCRATCH) ===${NC}"

    for t in "${TESTS[@]}"; do
        BINARY="$BIN/$t"
        if [[ ! -x "$BINARY" ]]; then
            echo -e "${YELLOW}SKIP${NC}  $t  (binary not found)"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        OUT=$(ROSETTA_X87_TRIG_IR=1 ROSETTA_X87_RUNTIME_KEEPALIVE=1 ROSETTA_X87_EXTENDED_FPR_SCRATCH=1 "$LOADER" "$BINARY" 2>/dev/null | filter_runtime_lines || true)
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
