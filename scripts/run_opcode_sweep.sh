#!/usr/bin/env bash
#
# run_opcode_sweep.sh -- Systematically enable opcode translations and find failures.
#
# Phase 1 — Single: enable one opcode at a time (all others + all fusions disabled).
#   Identifies which individual opcodes have broken translations.
#
# Phase 2 — Cumulative: enable opcodes one-by-one in order, growing the enabled set.
#   Identifies which opcode, when added to the already-working set, causes a failure.
#   With --stop-on-fail: stops as soon as a new failure is introduced.
#
# Usage:
#   bash scripts/run_opcode_sweep.sh                   # both phases, with build
#   bash scripts/run_opcode_sweep.sh --no-build        # skip cmake build
#   bash scripts/run_opcode_sweep.sh --phase1-only     # single-opcode phase only
#   bash scripts/run_opcode_sweep.sh --phase2-only     # cumulative phase only
#   bash scripts/run_opcode_sweep.sh --stop-on-fail    # stop cumulative at first new failure
#   bash scripts/run_opcode_sweep.sh --timeout 30      # kill+retry tests that hang > 30s

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
    test_peephole6
    test_deep_stack
    test_x87_full
    test_fstpt
    test_peephole7
)

ALL_OPCODES=(
    fldz fld1 fldl2e fldl2t fldlg2 fldln2 fldpi
    fld fild
    fadd faddp fiadd
    fsub fsubr fsubp fsubrp
    fdiv fdivr fdivp fdivrp
    fmul fmulp
    fst fst_stack fstp fstp_stack
    fstsw
    fcom fcomp fcompp fucom fucomp fucompp
    fxch fchs fabs fsqrt
    fistp fidiv fimul fisub fidivr frndint
    fcomi fcomip fucomi fucomip
    ftst fist fisubr
    fcmovb fcmovbe fcmove fcmovnb fcmovnbe fcmovne fcmovu fcmovnu
)

# Per-opcode test mapping
declare -A OPCODE_TESTS
OPCODE_TESTS[fldz]="test_fld_fst test_fldconst test_x87_full test_peephole6 test_peephole7"
OPCODE_TESTS[fld1]="test_fld_fst test_fldconst test_x87_full test_peephole4 test_peephole6 test_peephole7"
OPCODE_TESTS[fldl2e]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldl2t]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldlg2]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldln2]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldpi]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fld]="test_fld_fst test_fld test_fld_m80fp test_x87_full test_deep_stack test_peephole6 test_fstpt test_peephole7"
OPCODE_TESTS[fild]="test_fld_fst test_fild test_x87_full test_peephole4 test_peephole6 test_peephole7"
OPCODE_TESTS[fst]="test_fld_fst test_x87_full"
OPCODE_TESTS[fst_stack]="test_fld_fst test_x87_full"
OPCODE_TESTS[fstp]="test_fld_fst test_fcomp_mem test_x87_full test_fstpt test_peephole7"
OPCODE_TESTS[fstp_stack]="test_fld_fst test_x87_full"
OPCODE_TESTS[fist]="test_compare_unary test_x87_full"
OPCODE_TESTS[fistp]="test_fld_fst test_x87_full"
OPCODE_TESTS[fstsw]="test_fcom test_x87_full test_peephole6 test_peephole7"
OPCODE_TESTS[fadd]="test_arith test_deep_stack test_peephole6"
OPCODE_TESTS[faddp]="test_arith test_deep_stack test_peephole6 test_peephole7"
OPCODE_TESTS[fiadd]="test_arith"
OPCODE_TESTS[fsub]="test_arith test_fcomp_mem test_deep_stack test_peephole6"
OPCODE_TESTS[fsubr]="test_arith test_peephole4"
OPCODE_TESTS[fsubp]="test_arith test_peephole7"
OPCODE_TESTS[fsubrp]="test_arith test_peephole6 test_peephole7"
OPCODE_TESTS[fmul]="test_arith test_fmul test_deep_stack test_peephole6"
OPCODE_TESTS[fmulp]="test_arith test_deep_stack test_peephole6 test_peephole7"
OPCODE_TESTS[fimul]="test_arith"
OPCODE_TESTS[fdiv]="test_arith test_deep_stack test_peephole4"
OPCODE_TESTS[fdivr]="test_arith test_peephole4"
OPCODE_TESTS[fdivp]="test_arith"
OPCODE_TESTS[fdivrp]="test_arith"
OPCODE_TESTS[fidiv]="test_arith"
OPCODE_TESTS[fidivr]="test_arith"
OPCODE_TESTS[fisub]="test_arith"
OPCODE_TESTS[fisubr]="test_arith test_x87_full"
OPCODE_TESTS[frndint]="test_compare_unary test_x87_full"
OPCODE_TESTS[fcom]="test_fcom test_fcomp_mem test_x87_full test_deep_stack test_peephole4"
OPCODE_TESTS[fcomp]="test_fcom test_fcomp_mem test_x87_full test_deep_stack test_peephole6 test_peephole7"
OPCODE_TESTS[fcompp]="test_fcom test_x87_full"
OPCODE_TESTS[fucom]="test_fcom test_x87_full test_deep_stack test_peephole4"
OPCODE_TESTS[fucomp]="test_fcom test_x87_full test_deep_stack test_peephole6"
OPCODE_TESTS[fucompp]="test_fcom test_x87_full"
OPCODE_TESTS[fcomi]="test_compare_unary test_x87_full"
OPCODE_TESTS[fcomip]="test_compare_unary test_x87_full"
OPCODE_TESTS[fucomi]="test_compare_unary test_x87_full"
OPCODE_TESTS[fucomip]="test_compare_unary test_x87_full"
OPCODE_TESTS[ftst]="test_compare_unary test_x87_full"
OPCODE_TESTS[fchs]="test_compare_unary test_x87_full"
OPCODE_TESTS[fabs]="test_compare_unary test_x87_full"
OPCODE_TESTS[fsqrt]="test_compare_unary test_x87_full"
OPCODE_TESTS[fxch]="test_fld_fst test_x87_full test_deep_stack test_peephole4"
OPCODE_TESTS[fcmovb]="test_x87_full test_deep_stack"
OPCODE_TESTS[fcmovbe]="test_x87_full"
OPCODE_TESTS[fcmove]="test_x87_full test_deep_stack"
OPCODE_TESTS[fcmovnb]="test_x87_full test_deep_stack"
OPCODE_TESTS[fcmovnbe]="test_x87_full"
OPCODE_TESTS[fcmovne]="test_x87_full test_deep_stack"
OPCODE_TESTS[fcmovu]="test_x87_full"
OPCODE_TESTS[fcmovnu]="test_x87_full"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Parse args
DO_BUILD=1
RUN_PHASE1=1
RUN_PHASE2=1
STOP_ON_FAIL=0
STOPPED=0
TIMEOUT_SECS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    DO_BUILD=0 ;;
        --phase1-only) RUN_PHASE2=0 ;;
        --phase2-only) RUN_PHASE1=0 ;;
        --stop-on-fail) STOP_ON_FAIL=1 ;;
        --timeout)     shift; TIMEOUT_SECS="$1" ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ $DO_BUILD -eq 1 ]]; then
    echo -e "${CYAN}Building...${NC}"
    cmake --build "$BUILD_DIR" --parallel 2>&1 | tail -3
    echo ""
fi

filter_runtime_lines() {
    grep -v -E 'RosettaRuntimex87 built|Installing JIT|JIT Translation Hook|try_fuse_|CORE_LOG'
}

TOTAL=0
PASSED=0
FAILED=0
ERRORS=0

run_one_test() {
    local config_name="$1"
    local envvars="$2"
    local binary_name="$3"
    local binary="$BIN/$binary_name"

    TOTAL=$(( TOTAL + 1 ))

    if [[ ! -x "$binary" ]]; then
        echo -e "  ${YELLOW}SKIP${NC}  $binary_name  (binary not found)"
        ERRORS=$(( ERRORS + 1 ))
        return
    fi

    local attempt=0
    local timed_out=0
    local tmpout
    tmpout=$(mktemp)

    while (( attempt < 2 )); do
        attempt=$(( attempt + 1 ))
        timed_out=0

        if [[ $TIMEOUT_SECS -gt 0 ]]; then
            local rc=0
            # shellcheck disable=SC2086
            gtimeout "$TIMEOUT_SECS" env $envvars "$LOADER" "$binary" > "$tmpout" 2>/dev/null || rc=$?
            if [[ $rc -eq 124 ]]; then timed_out=1; fi
        else
            # shellcheck disable=SC2086
            env $envvars "$LOADER" "$binary" > "$tmpout" 2>/dev/null || true
        fi

        if [[ $timed_out -eq 1 && $attempt -eq 1 ]]; then
            echo -e "  ${YELLOW}TIMEOUT${NC}  $binary_name  [$config_name] — retrying..."
            continue
        fi
        break
    done

    OUT=$(filter_runtime_lines < "$tmpout" || true)
    rm -f "$tmpout"

    if [[ $timed_out -eq 1 ]]; then
        echo -e "  ${RED}TIMEOUT${NC}  $binary_name  [$config_name] — timed out on retry"
        FAILED=$(( FAILED + 1 ))
        return
    fi

    if echo "$OUT" | grep -qE 'FAIL'; then
        echo -e "  ${RED}FAIL${NC}  $binary_name  [$config_name]"
        FAILED=$(( FAILED + 1 ))
        echo "$OUT" | grep -E 'FAIL' | head -10 | sed 's/^/        /'
    else
        echo -e "  ${GREEN}PASS${NC}  $binary_name"
        PASSED=$(( PASSED + 1 ))
    fi
}

run_config() {
    local section="$1"
    local name="$2"
    local envvars="$3"
    local -a tests=("${@:4}")

    echo -e "${BOLD}=== [$section] $name ===${NC}"
    for t in "${tests[@]}"; do
        run_one_test "$name" "$envvars" "$t"
    done
    echo ""
}

# All opcodes except those in the named array, comma-separated
opcodes_except_set() {
    local -n _enabled_set="$1"
    printf '%s\n' "${ALL_OPCODES[@]}" \
        | grep -vFx "$(printf '%s\n' "${_enabled_set[@]}")" \
        | paste -s -d ',' -
}

echo -e "${CYAN}Opcode sweep: enable translations one at a time, then cumulatively${NC}"
echo "================================================================"
echo ""

# ── Baseline ─────────────────────────────────────────────────────────────────
run_config sweep baseline \
    "ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_ALL_FUSIONS=1" \
    "${ALL_TESTS[@]}"

# ── Phase 1 — Single opcode ───────────────────────────────────────────────────
if [[ $RUN_PHASE1 -eq 1 ]]; then
    echo -e "${BOLD}━━━ Phase 1: single opcode (enable one, disable all others + fusions) ━━━${NC}"
    echo ""
    for op in "${ALL_OPCODES[@]}"; do
        single=("$op")
        others=$(opcodes_except_set single || true)
        tests_str="${OPCODE_TESTS[$op]:-test_x87_full}"
        # shellcheck disable=SC2086
        read -ra op_tests <<< "$tests_str"
        prev_failed=$FAILED
        run_config sweep "single:$op" \
            "ROSETTA_X87_DISABLE_ALL_FUSIONS=1 ROSETTA_X87_DISABLE_OPS=$others" \
            "${op_tests[@]}"
        if [[ $STOP_ON_FAIL -eq 1 && $FAILED -gt $prev_failed ]]; then
            echo -e "${RED}STOPPED: opcode '$op' has failure(s)${NC}"
            STOPPED=1
            break
        fi
    done
fi

# ── Phase 2 — Cumulative ──────────────────────────────────────────────────────
if [[ $RUN_PHASE2 -eq 1 && $STOPPED -eq 0 ]]; then
    echo -e "${BOLD}━━━ Phase 2: cumulative (grow enabled set one opcode at a time) ━━━${NC}"
    echo ""
    enabled=()
    for op in "${ALL_OPCODES[@]}"; do
        enabled+=("$op")
        prev_failed=$FAILED

        # Build label: first 3 ops then "..." to keep it readable
        if [[ ${#enabled[@]} -le 3 ]]; then
            label=$(IFS=+; echo "${enabled[*]}")
        else
            label="${enabled[0]}+${enabled[1]}+${enabled[2]}+...(${#enabled[@]})"
        fi

        others=$(opcodes_except_set enabled || true)
        if [[ -z "$others" ]]; then
            # All opcodes enabled — no DISABLE_OPS needed
            run_config sweep "cumul:$label" \
                "ROSETTA_X87_DISABLE_ALL_FUSIONS=1" \
                "${ALL_TESTS[@]}"
        else
            run_config sweep "cumul:$label" \
                "ROSETTA_X87_DISABLE_ALL_FUSIONS=1 ROSETTA_X87_DISABLE_OPS=$others" \
                "${ALL_TESTS[@]}"
        fi

        if [[ $STOP_ON_FAIL -eq 1 && $FAILED -gt $prev_failed ]]; then
            echo -e "${RED}STOPPED: adding '$op' introduced new failure(s)${NC}"
            STOPPED=1
            break
        fi
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "================================================================"
echo -e "Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${ERRORS} skipped${NC} / ${TOTAL} total"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
