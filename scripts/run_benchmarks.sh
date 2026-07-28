#!/usr/bin/env bash
#
# run_benchmarks.sh -- Run x87 benchmarks in 3 configurations and print a comparison table.
#
# Configurations:
#   1. Native Rosetta    — binary run directly (baseline)
#   2. Loader disabled   — runtime_loader + ROSETTA_X87_DISABLE_ALL_OPS=1 ROSETTA_X87_DISABLE_ALL_FUSIONS=1
#   3. Loader optimized  — runtime_loader with default JIT optimizations plus
#                          every opt-in perf flag from the game launch stack
#                          (see OPTIMIZED_FLAGS below), including the
#                          accepted-fidelity F32_ARITH and FAST_RECIP_DIV.
#                          FAST_ROUND (nearest-only, unsafe under FLDCW) is
#                          excluded here and measured in its own section.
#
# Usage:
#   bash scripts/run_benchmarks.sh              # build + run
#   bash scripts/run_benchmarks.sh --no-build   # skip cmake build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
BIN="$BUILD_DIR/bin"
LOADER="$BIN/runtime_loader"

ALL_BENCHMARKS=(
    bench_constants
    bench_load
    bench_add
    bench_sub
    bench_mul
    bench_div
    bench_store
    bench_compare
    bench_unary
    bench_fcmov
    bench_fusion_fld_arithp
    bench_fusion_fld_fstp
    bench_fusion_fld_arith_fstp
    bench_fusion_fld_fcomp_fstsw
    bench_fusion_fxch_arithp
    bench_fusion_fxch_fstp
    bench_fusion_fcom_fstsw
    bench_fusion_arithp_fstp
    bench_fusion_arith_fstp
    bench_fusion_arith_faddp
    bench_fusion_fld_arith_arithp
    bench_fstp_fld
    bench_round
    bench_fistt
    bench_tag_batch
    bench_fistp_multi
    bench_mem_cse
    bench_addr_fold
    bench_f32
    bench_fcos
    bench_trig
    bench_trig_run
    bench_interleaved_mov
    bench_const_promote
)

# Opt-in performance flags enabled for the "Loader optimized" (JIT) column —
# kept in lockstep with the game launch stack (and run_tests.sh phase 10):
# the bit-exact set plus the accepted-fidelity F32_ARITH (f32 chain
# intermediates; game profile is f32-dominant) and FAST_RECIP_DIV (≤1 ulp on
# constant divides). FAST_ROUND (nearest-only, breaks FLDCW rounding modes)
# is excluded; it has its own comparison section at the bottom of this script.
OPTIMIZED_FLAGS=(
    ROSETTA_X87_EXTENDED_FPR_SCRATCH=1
    ROSETTA_X87_RUN_BRIDGE=1
    ROSETTA_X87_TRANSPARENT_FLAGS=1
    ROSETTA_X87_TRANSPARENT_PUSHPOP=1
    ROSETTA_X87_TRANSPARENT_INT=1
    ROSETTA_X87_BRIDGE_CARRY=1
    ROSETTA_X87_F32_ARITH=1
    ROSETTA_X87_RUNTIME_KEEPALIVE=1
    ROSETTA_X87_CONST_PROMOTE=1
    ROSETTA_X87_F32_NARROW=1
    ROSETTA_X87_TRIG_IR=1
    ROSETTA_X87_FAST_RECIP_DIV=1
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DO_BUILD=1
for arg in "$@"; do
    if [[ "$arg" == "--no-build" ]]; then
        DO_BUILD=0
    fi
done

if [[ $DO_BUILD -eq 1 ]]; then
    echo -e "${CYAN}Building...${NC}"
    cmake --build "$BUILD_DIR" --parallel 2>&1 | tail -3
    echo ""
fi

# Strip runtime-internal noise lines before checking output (same filter as run_tests.sh)
filter_runtime_lines() {
    grep -v -E 'RosettaRuntimex87 built|Installing JIT|JIT Translation Hook|try_fuse_|CORE_LOG' || true
}

# Run a benchmark binary, optionally through the loader with env vars.
# Usage: run_bench <binary> <use_loader: 0|1> [env_var=val ...]
run_bench() {
    local binary="$1"
    local use_loader="$2"
    shift 2
    if [[ $use_loader -eq 0 ]]; then
        "$binary" 2>/dev/null || true
    else
        env "$@" "$LOADER" "$binary" 2>/dev/null | filter_runtime_lines
    fi
}

# Collect results: associative arrays keyed by "bench.func_name"
declare -A NATIVE
declare -A DISABLED
declare -A OPTIMIZED

echo -e "${BOLD}Running benchmarks...${NC}"
echo ""

for bench in "${ALL_BENCHMARKS[@]}"; do
    binary="$BIN/$bench"
    if [[ ! -x "$binary" ]]; then
        echo -e "${YELLOW}SKIP${NC}  $bench  (binary not found)"
        continue
    fi

    echo -ne "  ${bench} ... "

    while IFS=' ' read -r keyword name ticks; do
        [[ "$keyword" == "BENCH" ]] || continue
        NATIVE["$bench.$name"]="$ticks"
    done < <(run_bench "$binary" 0)

    while IFS=' ' read -r keyword name ticks; do
        [[ "$keyword" == "BENCH" ]] || continue
        DISABLED["$bench.$name"]="$ticks"
    done < <(run_bench "$binary" 1 \
        ROSETTA_X87_DISABLE_ALL_OPS=1 \
        ROSETTA_X87_DISABLE_ALL_FUSIONS=1)

    while IFS=' ' read -r keyword name ticks; do
        [[ "$keyword" == "BENCH" ]] || continue
        OPTIMIZED["$bench.$name"]="$ticks"
    done < <(run_bench "$binary" 1 "${OPTIMIZED_FLAGS[@]}")

    echo -e "${GREEN}done${NC}"
done

echo ""

# ── Legend ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}Columns:${NC}"
echo "  native    — binary run directly under Rosetta (no loader)"
echo "  runtime   — runtime_loader, all JIT optimizations disabled (helper-library-only)"
echo "  JIT       — runtime_loader with full JIT optimizations enabled"
echo "  rt_gain   — speedup of JIT over runtime baseline"
echo "  nat_gain  — speedup of JIT over native Rosetta"
echo ""

# ── Print comparison table ─────────────────────────────────────────────────────
COL_NAME=42
COL_NUM=10
COL_SPD=9
DIVIDER=$(printf '─%.0s' $(seq 1 $((COL_NAME + COL_NUM*3 + COL_SPD*2 + 12))))

printf "${BOLD}%-${COL_NAME}s %${COL_NUM}s %${COL_NUM}s %${COL_NUM}s %${COL_SPD}s %${COL_SPD}s${NC}\n" \
    "benchmark" "native" "runtime" "JIT" "rt_gain" "nat_gain"
echo "$DIVIDER"

total_vs_off_pct=0
total_vs_native_pct=0
total_count=0

for bench in "${ALL_BENCHMARKS[@]}"; do
    binary="$BIN/$bench"
    [[ -x "$binary" ]] || continue

    # Gather all func names for this bench from NATIVE keys
    bench_printed_header=0
    for key in "${!NATIVE[@]}"; do
        [[ "$key" == "$bench."* ]] || continue
        func_name="${key#"$bench."}"

        native_ticks="${NATIVE[$key]:-0}"
        disabled_ticks="${DISABLED[$bench.$func_name]:-0}"
        optimized_ticks="${OPTIMIZED[$bench.$func_name]:-0}"

        # Speedup vs disabled: disabled/optimized
        if [[ $optimized_ticks -gt 0 && $disabled_ticks -gt 0 ]]; then
            vs_off_int=$(( disabled_ticks / optimized_ticks ))
            vs_off_frac=$(( (disabled_ticks * 100 / optimized_ticks) % 100 ))
            vs_off_pct=$(( disabled_ticks * 100 / optimized_ticks ))
        else
            vs_off_int=0; vs_off_frac=0; vs_off_pct=0
        fi

        # Speedup vs native: native/optimized
        if [[ $optimized_ticks -gt 0 && $native_ticks -gt 0 ]]; then
            vs_nat_int=$(( native_ticks / optimized_ticks ))
            vs_nat_frac=$(( (native_ticks * 100 / optimized_ticks) % 100 ))
            vs_nat_pct=$(( native_ticks * 100 / optimized_ticks ))
        else
            vs_nat_int=0; vs_nat_frac=0; vs_nat_pct=0
        fi

        # Color for vs_off: green > 1.10x, yellow 0.90–1.10x, red < 0.90x
        if   [[ $vs_off_pct -ge 110 ]]; then spd_color="$GREEN"
        elif [[ $vs_off_pct -ge 90  ]]; then spd_color="$YELLOW"
        else                                  spd_color="$RED"
        fi

        short_bench="${bench#bench_}"
        label="${short_bench}/${func_name}"
        vs_off_str="${vs_off_int}.$(printf '%02d' $vs_off_frac)x"
        vs_nat_str="${vs_nat_int}.$(printf '%02d' $vs_nat_frac)x"

        printf "%-${COL_NAME}s %${COL_NUM}s %${COL_NUM}s %${COL_NUM}s ${spd_color}%${COL_SPD}s${NC} %${COL_SPD}s\n" \
            "$label" \
            "$native_ticks" \
            "$disabled_ticks" \
            "$optimized_ticks" \
            "$vs_off_str" \
            "$vs_nat_str"

        total_vs_off_pct=$(( total_vs_off_pct + vs_off_pct ))
        total_vs_native_pct=$(( total_vs_native_pct + vs_nat_pct ))
        total_count=$(( total_count + 1 ))
    done
done

echo "$DIVIDER"

# Summary
if [[ $total_count -gt 0 ]]; then
    avg_vs_off_int=$(( total_vs_off_pct / total_count / 100 ))
    avg_vs_off_frac=$(( (total_vs_off_pct / total_count) % 100 ))
    avg_vs_nat_int=$(( total_vs_native_pct / total_count / 100 ))
    avg_vs_nat_frac=$(( (total_vs_native_pct / total_count) % 100 ))

    echo ""
    echo -e "${BOLD}Summary (${total_count} benchmarks)${NC}"
    echo -e "  Avg rt_gain  (JIT vs runtime):   ${GREEN}${avg_vs_off_int}.$(printf '%02d' $avg_vs_off_frac)x${NC}"
    echo -e "  Avg nat_gain (JIT vs native):    ${GREEN}${avg_vs_nat_int}.$(printf '%02d' $avg_vs_nat_frac)x${NC}"
fi

# ── ROSETTA_X87_FAST_ROUND comparison ─────────────────────────────────────────
# bench_round exercises FISTP/FIST/FRNDINT with all four rounding modes.
# Compare JIT with the full RC dispatch chain (default) vs. single-instruction
# fast path (ROSETTA_X87_FAST_ROUND=1, nearest-only, ~27% faster).
#
# WARNING: FAST_ROUND=1 is incorrect for code that uses FLDCW to set non-default
# rounding modes (e.g. Lua, floor-based coordinate math). Only use it when you
# have verified the target binary never changes the x87 rounding mode.
ROUND_BIN="$BIN/bench_round"
if [[ -x "$ROUND_BIN" ]]; then
    echo ""
    echo -e "${BOLD}ROSETTA_X87_FAST_ROUND comparison${NC}  (bench_round)"
    echo -e "  ${YELLOW}NOTE: ROSETTA_X87_FAST_ROUND=1 is unsafe for code using FLDCW (e.g. Lua).${NC}"
    echo ""

    declare -A ROUND_DEFAULT
    declare -A ROUND_FAST

    while IFS=' ' read -r keyword name ticks; do
        [[ "$keyword" == "BENCH" ]] || continue
        ROUND_DEFAULT["$name"]="$ticks"
    done < <(run_bench "$ROUND_BIN" 1 "${OPTIMIZED_FLAGS[@]}")

    while IFS=' ' read -r keyword name ticks; do
        [[ "$keyword" == "BENCH" ]] || continue
        ROUND_FAST["$name"]="$ticks"
    done < <(run_bench "$ROUND_BIN" 1 "${OPTIMIZED_FLAGS[@]}" ROSETTA_X87_FAST_ROUND=1)

    DIVIDER2=$(printf '─%.0s' $(seq 1 $((COL_NAME + COL_NUM*2 + COL_SPD + 8))))
    printf "${BOLD}%-${COL_NAME}s %${COL_NUM}s %${COL_NUM}s %${COL_SPD}s${NC}\n" \
        "bench_round/func" "JIT" "fast_round" "speedup"
    echo "$DIVIDER2"

    for name in "${!ROUND_DEFAULT[@]}"; do
        def_ticks="${ROUND_DEFAULT[$name]:-0}"
        fast_ticks="${ROUND_FAST[$name]:-0}"

        if [[ $fast_ticks -gt 0 && $def_ticks -gt 0 ]]; then
            spd_pct=$(( def_ticks * 100 / fast_ticks ))
            spd_int=$(( spd_pct / 100 ))
            spd_frac=$(( spd_pct % 100 ))
        else
            spd_int=0; spd_frac=0; spd_pct=0
        fi

        if   [[ $spd_pct -ge 110 ]]; then spd_color="$GREEN"
        elif [[ $spd_pct -ge 90  ]]; then spd_color="$YELLOW"
        else                               spd_color="$RED"
        fi

        printf "%-${COL_NAME}s %${COL_NUM}s %${COL_NUM}s ${spd_color}%${COL_SPD}s${NC}\n" \
            "round/$name" "$def_ticks" "$fast_ticks" \
            "${spd_int}.$(printf '%02d' $spd_frac)x"
    done

    echo "$DIVIDER2"
fi
