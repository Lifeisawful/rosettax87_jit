#!/usr/bin/env bash
#
# run_fusion_sweep.sh -- Systematically test fusion translations and their interaction with opcodes.
#
# Phase 1 — Single: enable one fusion at a time (all opcodes + all other fusions disabled).
#   Identifies which individual fusions have broken translations.
#
# Phase 2 — Cumulative: enable fusions one-by-one in order (all opcodes disabled).
#   Identifies which fusion, when added to the already-working set, causes a failure.
#
# Phase 3 — Matrix: for each fusion, sweep each opcode individually.
#   Identifies fusion×opcode interaction bugs (7 fusions × 58 opcodes = 406 configs).
#
# Phase 4 — All fusions + single opcode: all fusions enabled, one opcode at a time.
#   Equivalent to run_opcode_sweep phase 1 with full fusion set active (production config).
#
# Usage:
#   bash scripts/run_fusion_sweep.sh                   # all phases, with build
#   bash scripts/run_fusion_sweep.sh --no-build        # skip cmake build
#   bash scripts/run_fusion_sweep.sh --phase1-only     # single-fusion phase only
#   bash scripts/run_fusion_sweep.sh --phase2-only     # cumulative-fusion phase only
#   bash scripts/run_fusion_sweep.sh --phase3-only     # fusion×opcode matrix only
#   bash scripts/run_fusion_sweep.sh --phase4-only     # all-fusions + single-opcode only
#   bash scripts/run_fusion_sweep.sh --stop-on-fail    # stop cumulative at first new failure
#   bash scripts/run_fusion_sweep.sh --timeout 30      # kill+retry tests that hang > 30s
#   bash scripts/run_fusion_sweep.sh --all-tests        # run all tests (not just fusion-relevant) in sweep phases

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
    test_deep_stack
    test_x87_full
    test_fstpt
)

ALL_FUSIONS=(
    fld_arithp
    fld_fstp
    fld_arith_fstp
    fld_fcomp_fstsw
    fxch_arithp
    fxch_fstp
    fcom_fstsw
    fld_fcompp_fstsw
    fld_fld_fucompp
)

# Tests that exercise fusion patterns
FUSION_TESTS=(test_peephole3 test_peephole4 test_peephole5 test_peephole6 test_peephole test_arith test_fcomp_mem test_x87_full)

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
OPCODE_TESTS[fldz]="test_fld_fst test_fldconst test_x87_full test_peephole6"
OPCODE_TESTS[fld1]="test_fld_fst test_fldconst test_x87_full test_peephole4 test_peephole6"
OPCODE_TESTS[fldl2e]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldl2t]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldlg2]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldln2]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fldpi]="test_fld_fst test_fldconst test_x87_full test_peephole4"
OPCODE_TESTS[fld]="test_fld_fst test_fld test_fld_m80fp test_x87_full test_deep_stack test_peephole6 test_fstpt"
OPCODE_TESTS[fild]="test_fld_fst test_fild test_x87_full test_peephole4 test_peephole6"
OPCODE_TESTS[fst]="test_fld_fst test_x87_full"
OPCODE_TESTS[fst_stack]="test_fld_fst test_x87_full"
OPCODE_TESTS[fstp]="test_fld_fst test_fcomp_mem test_x87_full test_fstpt"
OPCODE_TESTS[fstp_stack]="test_fld_fst test_x87_full"
OPCODE_TESTS[fist]="test_compare_unary test_x87_full"
OPCODE_TESTS[fistp]="test_fld_fst test_x87_full"
OPCODE_TESTS[fstsw]="test_fcom test_x87_full test_peephole6"
OPCODE_TESTS[fadd]="test_arith test_deep_stack test_peephole6"
OPCODE_TESTS[faddp]="test_arith test_deep_stack test_peephole6"
OPCODE_TESTS[fiadd]="test_arith"
OPCODE_TESTS[fsub]="test_arith test_fcomp_mem test_deep_stack test_peephole6"
OPCODE_TESTS[fsubr]="test_arith test_peephole4"
OPCODE_TESTS[fsubp]="test_arith"
OPCODE_TESTS[fsubrp]="test_arith test_peephole6"
OPCODE_TESTS[fmul]="test_arith test_fmul test_deep_stack test_peephole6"
OPCODE_TESTS[fmulp]="test_arith test_deep_stack test_peephole6"
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
OPCODE_TESTS[fcomp]="test_fcom test_fcomp_mem test_x87_full test_deep_stack test_peephole6"
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
RUN_PHASE3=1
RUN_PHASE4=1
STOP_ON_FAIL=0
STOPPED=0
TIMEOUT_SECS=0
ALL_TESTS_IN_SWEEPS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    DO_BUILD=0 ;;
        --phase1-only) RUN_PHASE2=0; RUN_PHASE3=0; RUN_PHASE4=0 ;;
        --phase2-only) RUN_PHASE1=0; RUN_PHASE3=0; RUN_PHASE4=0 ;;
        --phase3-only) RUN_PHASE1=0; RUN_PHASE2=0; RUN_PHASE4=0 ;;
        --phase4-only) RUN_PHASE1=0; RUN_PHASE2=0; RUN_PHASE3=0 ;;
        --stop-on-fail) STOP_ON_FAIL=1 ;;
        --timeout)     shift; TIMEOUT_SECS="$1" ;;
        --all-tests)   ALL_TESTS_IN_SWEEPS=1 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ $ALL_TESTS_IN_SWEEPS -eq 1 ]]; then
    SWEEP_TESTS=("${ALL_TESTS[@]}")
else
    SWEEP_TESTS=("${SWEEP_TESTS[@]}")
fi

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

# All fusions except those in the named array, comma-separated
fusions_except_set() {
    local -n _enabled_set="$1"
    printf '%s\n' "${ALL_FUSIONS[@]}" \
        | grep -vFx "$(printf '%s\n' "${_enabled_set[@]}")" \
        | paste -s -d ',' -
}

# All opcodes except those in the named array, comma-separated
opcodes_except_set() {
    local -n _enabled_set="$1"
    printf '%s\n' "${ALL_OPCODES[@]}" \
        | grep -vFx "$(printf '%s\n' "${_enabled_set[@]}")" \
        | paste -s -d ',' -
}

echo -e "${CYAN}Fusion sweep: test fusions in isolation, cumulatively, and against each opcode${NC}"
echo "================================================================"
echo ""

# ── Baseline ─────────────────────────────────────────────────────────────────
run_config sweep baseline \
    "ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_ALL_FUSIONS=1" \
    "${ALL_TESTS[@]}"

# ── Phase 1 — Single fusion ───────────────────────────────────────────────────
if [[ $RUN_PHASE1 -eq 1 ]]; then
    echo -e "${BOLD}━━━ Phase 1: single fusion (enable one, disable all ops + other fusions) ━━━${NC}"
    echo ""
    for f in "${ALL_FUSIONS[@]}"; do
        single=("$f")
        others=$(fusions_except_set single || true)
        prev_failed=$FAILED
        run_config sweep "single:$f" \
            "ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_FUSIONS=$others" \
            "${SWEEP_TESTS[@]}"
        if [[ $STOP_ON_FAIL -eq 1 && $FAILED -gt $prev_failed ]]; then
            echo -e "${RED}STOPPED: fusion '$f' has failure(s)${NC}"
            STOPPED=1
            break
        fi
    done
fi

# ── Phase 2 — Cumulative fusions ─────────────────────────────────────────────
if [[ $RUN_PHASE2 -eq 1 && $STOPPED -eq 0 ]]; then
    echo -e "${BOLD}━━━ Phase 2: cumulative fusions (grow enabled set, all opcodes disabled) ━━━${NC}"
    echo ""
    enabled=()
    for f in "${ALL_FUSIONS[@]}"; do
        enabled+=("$f")
        prev_failed=$FAILED

        if [[ ${#enabled[@]} -le 3 ]]; then
            label=$(IFS=+; echo "${enabled[*]}")
        else
            label="${enabled[0]}+${enabled[1]}+${enabled[2]}+...(${#enabled[@]})"
        fi

        others=$(fusions_except_set enabled || true)
        if [[ -z "$others" ]]; then
            run_config sweep "cumul:$label" \
                "ROSETTA_X87_DISABLE_ALL_OPS=1" \
                "${SWEEP_TESTS[@]}"
        else
            run_config sweep "cumul:$label" \
                "ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_FUSIONS=$others" \
                "${SWEEP_TESTS[@]}"
        fi

        if [[ $STOP_ON_FAIL -eq 1 && $FAILED -gt $prev_failed ]]; then
            echo -e "${RED}STOPPED: adding '$f' introduced new failure(s)${NC}"
            STOPPED=1
            break
        fi
    done
fi

# ── Phase 3 — Fusion × opcode matrix ─────────────────────────────────────────
if [[ $RUN_PHASE3 -eq 1 && $STOPPED -eq 0 ]]; then
    echo -e "${BOLD}━━━ Phase 3: fusion×opcode matrix (one fusion + one opcode at a time) ━━━${NC}"
    echo ""
    for f in "${ALL_FUSIONS[@]}"; do
        single_f=("$f")
        other_fusions=$(fusions_except_set single_f || true)
        for op in "${ALL_OPCODES[@]}"; do
            single_op=("$op")
            other_ops=$(opcodes_except_set single_op || true)
            tests_str="${OPCODE_TESTS[$op]:-test_x87_full}"
            # shellcheck disable=SC2086
            read -ra op_tests <<< "$tests_str"
            run_config sweep "f:$f+op:$op" \
                "ROSETTA_X87_DISABLE_OPS=$other_ops ROSETTA_X87_DISABLE_FUSIONS=$other_fusions" \
                "${op_tests[@]}"
        done
    done
fi

# ── Phase 4 — All fusions + single opcode ─────────────────────────────────────
if [[ $RUN_PHASE4 -eq 1 && $STOPPED -eq 0 ]]; then
    echo -e "${BOLD}━━━ Phase 4: all fusions enabled, one opcode at a time ━━━${NC}"
    echo ""
    for op in "${ALL_OPCODES[@]}"; do
        single_op=("$op")
        other_ops=$(opcodes_except_set single_op || true)
        tests_str="${OPCODE_TESTS[$op]:-test_x87_full}"
        # shellcheck disable=SC2086
        read -ra op_tests <<< "$tests_str"
        run_config sweep "allfusions+op:$op" \
            "ROSETTA_X87_DISABLE_OPS=$other_ops" \
            "${op_tests[@]}"
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "================================================================"
echo -e "Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${YELLOW}${ERRORS} skipped${NC} / ${TOTAL} total"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
