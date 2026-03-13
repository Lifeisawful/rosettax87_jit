#!/usr/bin/env bash
# inspect_function.sh — Extract a named x86_64 function from a test binary,
# translate it to AArch64 via aotinvoke, and disassemble the result.
#
# Usage:
#   scripts/inspect_function.sh <binary> <symbol> [options]
#
# Options:
#   --opcode <op>          Enable only this opcode (disable all others + all fusions)
#   --fusion <f>           Enable only this fusion (disable all others + all ops)
#   --disable-all-ops      ROSETTA_X87_DISABLE_ALL_OPS=1
#   --disable-all-fusions  ROSETTA_X87_DISABLE_ALL_FUSIONS=1
#   --env VAR=VAL          Pass arbitrary env var to aotinvoke (repeatable)
#
# Examples:
#   scripts/inspect_function.sh build/bin/test_x87_full do_fcmov --opcode fcmovu
#   scripts/inspect_function.sh build/bin/test_x87_full do_fcmov --disable-all-ops
#   scripts/inspect_function.sh build/bin/test_peephole3 _test_f7_fld_reg_fadd_fstp_reg

set -euo pipefail

BINARY="${1:?Usage: $0 <binary> <symbol_name> [options]}"
SYMBOL="${2:?Usage: $0 <binary> <symbol_name> [options]}"
shift 2

# Resolve aotinvoke relative to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AOTINVOKE="$REPO_ROOT/build/bin/aotinvoke"

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

ALL_FUSIONS=(
    fld_arithp
    fld_fstp
    fld_arith_fstp
    fld_fcomp_fstsw
    fxch_arithp
    fxch_fstp
    fcom_fstsw
)

# ---- parse optional arguments ------------------------------------------------
EXTRA_ENV=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --opcode)
            op="$2"; shift 2
            others=$(printf '%s\n' "${ALL_OPCODES[@]}" | grep -vFx "$op" | paste -s -d ',' -)
            EXTRA_ENV+=("ROSETTA_X87_DISABLE_ALL_FUSIONS=1")
            [[ -n "$others" ]] && EXTRA_ENV+=("ROSETTA_X87_DISABLE_OPS=$others")
            ;;
        --fusion)
            f="$2"; shift 2
            others=$(printf '%s\n' "${ALL_FUSIONS[@]}" | grep -vFx "$f" | paste -s -d ',' -)
            EXTRA_ENV+=("ROSETTA_X87_DISABLE_ALL_OPS=1")
            [[ -n "$others" ]] && EXTRA_ENV+=("ROSETTA_X87_DISABLE_FUSIONS=$others")
            ;;
        --disable-all-ops)     EXTRA_ENV+=("ROSETTA_X87_DISABLE_ALL_OPS=1");     shift ;;
        --disable-all-fusions) EXTRA_ENV+=("ROSETTA_X87_DISABLE_ALL_FUSIONS=1"); shift ;;
        --env)                 EXTRA_ENV+=("$2"); shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---- sanity checks ----------------------------------------------------------
if ! command -v aarch64-elf-objdump &>/dev/null; then
    echo "Error: aarch64-elf-objdump not found on PATH" >&2
    exit 1
fi
if [[ ! -x "$AOTINVOKE" ]]; then
    echo "Error: aotinvoke not found at $AOTINVOKE — run the build first" >&2
    exit 1
fi
if [[ ! -f "$BINARY" ]]; then
    echo "Error: binary '$BINARY' not found" >&2
    exit 1
fi

# Normalise symbol: macOS nm always emits leading '_'
if [[ "$SYMBOL" != _* ]]; then
    SYMBOL="_$SYMBOL"
fi

# ---- 1. Resolve symbol address and size via nm -n ----------------------------
# nm -n: symbols sorted by address; format: "<addr> <type> <name>"
# We look only at text symbols (T or t = defined in text section).
NM_OUT=$(nm -n "$BINARY" | awk '$2 ~ /[Tt]/')

SYM_ADDR_HEX=$(awk -v sym="$SYMBOL" '$3 == sym { print $1; exit }' <<< "$NM_OUT")
if [[ -z "$SYM_ADDR_HEX" ]]; then
    echo "Error: symbol '$SYMBOL' not found in '$BINARY'" >&2
    echo "" >&2
    echo "Available text symbols:" >&2
    awk '{ print "  " $3 }' <<< "$NM_OUT" >&2
    exit 1
fi
SYM_ADDR=$(( 16#$SYM_ADDR_HEX ))

# Next text symbol gives the end address (last symbol falls back to section end)
NEXT_ADDR_HEX=$(awk -v sym="$SYMBOL" 'found { print $1; exit } $3 == sym { found=1 }' <<< "$NM_OUT")

# ---- 2. Parse __TEXT.__text section info from otool -l ----------------------
# Fields we need:
#   addr   <hex>   — section vmaddr
#   size   <hex>   — section size
#   offset <dec>   — file offset (decimal in otool output)
read -r SECT_VMADDR_HEX SECT_FILEOFF SECT_SIZE_HEX <<< "$(
    otool -l "$BINARY" | awk '
        /sectname __text/  { in_text=1; next }
        in_text && /segname __TEXT/ { in_seg=1; next }
        in_seg && $1 == "addr"   { addr   = $2 }
        in_seg && $1 == "size"   { sz     = $2 }
        in_seg && $1 == "offset" { off    = $2 }
        in_seg && $1 == "flags"  { print addr, off, sz; in_text=0; in_seg=0 }
    '
)"

SECT_VMADDR=$(( SECT_VMADDR_HEX ))    # bash handles 0x prefix natively
SECT_SIZE=$(( SECT_SIZE_HEX ))
SECT_END=$(( SECT_VMADDR + SECT_SIZE ))

if [[ -n "$NEXT_ADDR_HEX" ]]; then
    END_ADDR=$(( 16#$NEXT_ADDR_HEX ))
else
    # Last symbol in the section — use section end as upper bound
    END_ADDR=$SECT_END
fi

FN_SIZE=$(( END_ADDR - SYM_ADDR ))
FILE_POS=$(( SECT_FILEOFF + SYM_ADDR - SECT_VMADDR ))

printf "Symbol:      %s\n"   "$SYMBOL"
printf "VMAddr:      0x%x\n" "$SYM_ADDR"
printf "Size:        %d bytes\n" "$FN_SIZE"
printf "File offset: %d\n"  "$FILE_POS"
if [[ ${#EXTRA_ENV[@]} -gt 0 ]]; then
    printf "Env:         %s\n" "${EXTRA_ENV[*]}"
fi
printf "\n"

# ---- 3. Extract raw x86_64 bytes with dd ------------------------------------
WORK=$(mktemp -d /tmp/aot_inspect.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

EXTRACTED="$WORK/extracted.bin"
TRANSLATED="$WORK/translated.bin"

dd if="$BINARY" bs=1 skip="$FILE_POS" count="$FN_SIZE" of="$EXTRACTED" 2>/dev/null

# ---- 4. Translate to AArch64 via aotinvoke ----------------------------------
echo "=== x86 IR: $SYMBOL ==="
env "${EXTRA_ENV[@]}" "$AOTINVOKE" "$EXTRACTED" "$TRANSLATED" --verbose
echo ""

# ---- 5. Disassemble ---------------------------------------------------------
echo "=== AArch64 disassembly: $SYMBOL ==="
aarch64-elf-objdump -D -b binary -m aarch64 "$TRANSLATED"
