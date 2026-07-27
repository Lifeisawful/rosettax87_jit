#!/bin/bash
# audit_trig_value_clobbers.sh <path-to-libRuntimeRosettax87>
#
# The TRIG_VAL_HUGE / TRIG_VAL_HUGE2 fallback paths in runtime_entry.S save
# only the vector registers the C trig-value fallbacks ACTUALLY clobber, not
# the AAPCS worst case.  Deliberately unsaved registers must therefore never
# be touched by the fallbacks (openlibm fully inlined, no outgoing calls):
#   - x87_trig_{cos,sin,tan}_value (TRIG_VAL_HUGE saves q0-q7, q17-q23):
#     must not touch v8-v15 or v24-v31.  v8-v15 are guest xmm8-15 and AAPCS
#     only preserves their LOW 64 bits, so any use silently corrupts guest
#     xmm upper halves (the fscale-d4/d5 bug class).
#   - x87_trig_sincos_value (TRIG_VAL_HUGE2 saves everything except the
#     dead v16/v17): its dual kernel uses callee-saved d8-d15 and is
#     SLP-vectorized into v24+, so only the call/x18 rules apply.
# This script fails the build if a compiler/codegen change widens a clobber
# set, adds an outgoing call, or touches x18.  If it fires: either add the
# missing str/ldr q slots in the right huge macro or fix the codegen.
set -euo pipefail

BIN="${1:?usage: audit_trig_value_clobbers.sh <libRuntimeRosettax87>}"

SYMS=(_x87_trig_cos_value _x87_trig_sin_value _x87_trig_tan_value _x87_trig_sincos_value)
# Per-symbol forbidden vector registers (regex alternation of register numbers)
forbidden_for() {
    case "$1" in
        _x87_trig_sincos_value) echo '' ;;                             # all saved
        *)                      echo '8|9|1[0-5]|2[4-9]|3[01]' ;;      # v8-v15, v24-v31
    esac
}

# nm -n: sorted by address; the end of each function is the next symbol.
NM=$(nm -n "$BIN" | awk '$2 ~ /^[tT]$/ {print $1, $3}')

fail=0
for sym in "${SYMS[@]}"; do
    start=$(echo "$NM" | awk -v s="$sym" '$2 == s {print $1}')
    if [ -z "$start" ]; then
        echo "audit_trig_value_clobbers: symbol $sym not found in $BIN" >&2
        fail=1
        continue
    fi
    end=$(echo "$NM" | awk -v a="$start" 'found {print $1; exit} $1 == a {found=1}')
    dis=$(objdump -d --start-address="0x$start" --stop-address="0x$end" "$BIN" \
          | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*[0-9a-f]+[[:space:]]*//')

    # Forbidden vector registers in any width form (b/h/s/d/q/v).
    forb=$(forbidden_for "$sym")
    bad=""
    if [ -n "$forb" ]; then
        bad=$(echo "$dis" | grep -nE "\\b[bhsdqv](${forb})\\b" || true)
    fi
    if [ -n "$bad" ]; then
        echo "audit_trig_value_clobbers: $sym touches unsaved vector regs (see TRIG_VAL_HUGE*):" >&2
        echo "$bad" | head -5 >&2
        fail=1
    fi

    # Outgoing calls would put callee clobbers outside this audit.
    bad=$(echo "$dis" | grep -nE '^\s*(bl|blr)\b' || true)
    if [ -n "$bad" ]; then
        echo "audit_trig_value_clobbers: $sym makes outgoing calls (clobbers unauditable):" >&2
        echo "$bad" | head -5 >&2
        fail=1
    fi

    # x18 is the guest context pointer.
    bad=$(echo "$dis" | grep -nE '\b[xw]18\b' || true)
    if [ -n "$bad" ]; then
        echo "audit_trig_value_clobbers: $sym touches x18 (guest context pointer):" >&2
        echo "$bad" | head -5 >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "audit_trig_value_clobbers: FAILED for $BIN" >&2
    exit 1
fi
echo "audit_trig_value_clobbers: OK (fallback clobbers within the TRIG_VAL_HUGE* save sets, no calls, no x18)"
