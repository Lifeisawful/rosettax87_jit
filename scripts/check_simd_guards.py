#!/usr/bin/env python3
"""Static SIMD-clobber audit of the runtime dylib.

Two invariants, both learned the hard way (fscale d4/d5 cutscene bug; trig
v16-v24 clobbers found during the Oblivion RUN_BRIDGE freeze hunt 2026-07-19):

1. Runtime routines guarded by the narrow guards (SIMDGuard = q0-q3,
   SIMDGuardAndX0X7 = q0-q3 + x0-x7) must not write ANY vector register above
   v3 — directly or via calls within the dylib. Guest XMM0-7 live in q0-q7,
   and Rosetta keeps cached XMM scalars in temporary FPRs (v16+) plus the
   full-width q8-q15 across routine BLs. Routines that need more registers
   must use SIMDGuardFull / SIMDGuardFullAndX0X7 (which save v0-v31).

2. Translation-path code (everything reachable from the lazy-translation
   hook: Translator, X87Cache, X87IR, X87BridgeDemand, ...) runs on the guest
   thread with live guest vector state and NO guard, so it must contain no
   SIMD instructions at all. The only exceptions are the hook_safe_* helpers
   (rosetta_core/include/rosetta_core/HookSafeFP.h), whose asm blocks
   save/restore the exact registers they use; the functions they inline into
   are whitelisted here.

Usage: scripts/check_simd_guards.py [path-to-libRuntimeRosettax87]
Exit code 0 = clean, 1 = violation found.
"""

import bisect
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DYLIB = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "build/bin/libRuntimeRosettax87"
X87_CPP = REPO / "rosetta_runtime/src/X87.cpp"

# Functions allowed to contain SIMD in the translation path: the HookSafeFP.h
# asm helpers (self-contained save/restore) and, if the compiler inlines them,
# their callers. (try_const_promote's f32 widening is now pure-integer —
# widen_f32_to_f64_bits — so it needs no entry; pass_const_arith calls
# hook_safe_recip_bits, which the "hook_safe_" prefix covers.)
HOOK_SAFE_WHITELIST = ("hook_safe_",)

# Source files scanned for SIMDGuardFull-protected translation-path functions.
# A translation-path symbol whose source takes `SIMDGuardFull simdGuard;` may
# contain SIMD as long as its TRANSITIVE clobber set stays within the guard's
# q0-q7 save range (verified below). A SIMD-containing symbol whose every
# dylib-internal caller is such a guarded function is also accepted (e.g.
# abi_info_for_runtime_routines_address, only reachable under a guard).
GUARDED_SRC = (
    REPO / "rosetta_runtime/src/TranslationCacheAbi.cpp",
    REPO / "rosetta_runtime/src/ExecutableHeap.cpp",
    REPO / "rosetta_runtime/src/Library.cpp",
)
FUNC_DEF_RE = re.compile(r"^\w[\w:*&<> ]*?\b(\w+)\(", re.M)
GUARD_STMT_RE = re.compile(r"^    SIMDGuardFull simdGuard;", re.M)

# Symbol substrings marking translation-path code (invariant 2).
TRANSLATION_MARKERS = (
    "Translator", "X87Cache", "X87IR", "hook_translate", "_GLOBAL__N_1",
    "gap_gpr_demand", "lookahead", "bridge_family", "opcode_host",
    "compute_mem_operand", "CustomTranslationHook", "decode_substitute",
    "hook_safe_",
)

INS_RE = re.compile(r"^\s*[0-9a-f]+\s+([\w.]+)\s+(.*)$")
VREG_RE = re.compile(r"(?:^|[ ,\[{])(?:v|q|d|s|h|b)(\d+)\b")


def main() -> int:
    if not DYLIB.exists():
        print(f"SKIP: {DYLIB} not built")
        return 0

    nm = subprocess.run(["nm", str(DYLIB)], capture_output=True, text=True).stdout
    syms = sorted(
        (int(p[0], 16), p[2])
        for p in (l.split() for l in nm.splitlines())
        if len(p) == 3 and p[1] in ("t", "T")
    )
    addrs = [a for a, _ in syms]
    local_syms = {
        p[2]
        for p in (l.split() for l in nm.splitlines())
        if len(p) == 3 and p[1] == "t"
    }

    def sym_at(a: int) -> str:
        i = bisect.bisect_right(addrs, a) - 1
        return syms[i][1] if i >= 0 else "?"

    dis = subprocess.run(["otool", "-tv", str(DYLIB)], capture_output=True, text=True).stdout
    cur = None
    writes: dict[str, set] = {}   # symbol -> v-regs written (any width token)
    calls: dict[str, set] = {}    # symbol -> BL/tail-B targets (dylib-internal)
    referenced: set = set()       # symbols whose ADDRESS is taken (adrp+add)
    adrp_page: dict[str, int] = {}  # per-symbol: last adrp page per register
    simd_any: dict[str, int] = {} # symbol -> count of SIMD-touching instrs
    for line in dis.splitlines():
        if line.startswith("_"):
            cur = line.rstrip(":")
            adrp_page = {}
            continue
        m = INS_RE.match(line)
        if not m or cur is None:
            continue
        op, ops = m.groups()
        if op in ("bl", "b"):
            t = ops.strip()
            if t.startswith("0x"):
                target = sym_at(int(t, 16))
                # a same-symbol `b` is an internal loop/branch, not a call
                if op == "bl" or target != cur:
                    calls.setdefault(cur, set()).add(target)
        # address-taking: adrp Xn, N ; 0xPAGE  followed by  add Xd, Xn, #off
        if op == "adrp":
            pm = re.match(r"(\w+),.*;\s*(0x[0-9a-f]+)", ops)
            if pm:
                adrp_page[pm.group(1)] = int(pm.group(2), 16)
        elif op == "add":
            am = re.match(r"\w+, (\w+), #(0x[0-9a-f]+|\d+)$", ops)
            if am and am.group(1) in adrp_page:
                referenced.add(sym_at(adrp_page[am.group(1)] + int(am.group(2), 0)))
        toks = VREG_RE.findall(" " + ops)
        if toks:
            simd_any[cur] = simd_any.get(cur, 0) + 1
        # register writes: first operand of non-store ops, plus load targets
        dst = ops.split(",")[0].strip()
        md = re.match(r"^(?:v|q|d|s|h|b)(\d+)", dst)
        wrote = []
        if md and not op.startswith(("fcmp", "cmp", "str", "stp", "stur")):
            wrote.append(int(md.group(1)))
        if op in ("ldr", "ldp", "ldur"):
            wrote += [int(n) for _, n in re.findall(r"(?:^|,\s*)((?:q|d|s|v)(\d+))", ops)[:2]]
        for n in wrote:
            writes.setdefault(cur, set()).add(n)

    # transitive closure of writes over dylib-internal calls
    memo: dict[str, frozenset] = {}

    def clobbers(sym: str, stack=()) -> frozenset:
        if sym in memo:
            return memo[sym]
        if sym in stack:
            return frozenset()
        r = set(writes.get(sym, set()))
        for c in calls.get(sym, set()):
            r |= clobbers(c, stack + (sym,))
        memo[sym] = frozenset(r)
        return memo[sym]

    # guard type per routine, from source
    src = X87_CPP.read_text()
    guards = dict(
        re.findall(r"void (x87_\w+)\([^)]*\) \{\n(?:[^\n]*\n)*?    (SIMDGuard\w*) simdGuard;", src)
    )

    failed = False

    # Invariant 1: narrow-guard routines write nothing above v3
    for sym_addr, sym in syms:
        m = re.match(r"__Z\d+(x87_\w+?)P8X87State", sym)
        if not m:
            continue
        name = m.group(1)
        if guards.get(name) not in ("SIMDGuard", "SIMDGuardAndX0X7"):
            continue
        # exclude the guard's own q0-q3 save/restore (regs 0-3 are fine anyway)
        bad = sorted(r for r in clobbers(sym) if r > 3)
        if bad:
            print(f"FAIL  {name} ({guards[name]}) writes v{bad} — needs SIMDGuardFull")
            failed = True

    # SIMDGuardFull-protected functions outside X87.cpp (see GUARDED_SRC):
    # for each guard statement, attribute it to the nearest preceding
    # function definition in the same file.
    full_guarded: set = set()
    for f in GUARDED_SRC:
        text = f.read_text()
        for gm in GUARD_STMT_RE.finditer(text):
            defs = [d for d in FUNC_DEF_RE.finditer(text, 0, gm.start())]
            if defs:
                full_guarded.add(defs[-1].group(1))

    # reverse call map, for the callee-of-guarded exemption
    callers: dict[str, set] = {}
    for c, tgts in calls.items():
        for t in tgts:
            callers.setdefault(t, set()).add(c)

    def guard_name(sym: str) -> str | None:
        return next((n for n in full_guarded if n in sym), None)

    # Invariant 2: translation-path symbols contain no SIMD at all, unless
    # SIMDGuardFull-protected (clobbers must fit the guard's q0-q7) or only
    # reachable from such protected functions.
    for sym, count in sorted(simd_any.items()):
        if not any(t in sym for t in TRANSLATION_MARKERS):
            continue
        if any(w in sym for w in HOOK_SAFE_WHITELIST):
            continue
        name = guard_name(sym)
        if name:
            bad = sorted(r for r in clobbers(sym) if r > 7)
            if bad:
                print(f"FAIL  {name} (SIMDGuardFull) transitively writes v{bad} — "
                      f"exceeds the guard's q0-q7 save range")
                failed = True
            continue
        callers_of = callers.get(sym, set())
        if callers_of and all(guard_name(c) for c in callers_of):
            bad = sorted(r for r in clobbers(sym) if r > 7)
            if bad:
                print(f"FAIL  {sym} (guarded callers) writes v{bad} — "
                      f"exceeds the callers' q0-q7 save range")
                failed = True
            continue
        # Local (nm `t`) symbol with no bl/b callers and no adrp+add address
        # reference: an out-of-line copy the compiler kept after inlining
        # every call site (e.g. abi_info_for_runtime_routines_address, whose
        # guarded callers all inline it). Statically unreachable — report,
        # don't fail. External (`T`) symbols never take this exit: they can
        # be called from outside the dylib.
        if sym not in callers and sym not in referenced and sym in local_syms:
            print(f"note  {sym}: SIMD in dead out-of-line copy (no callers, "
                  f"address never taken) — not counted")
            continue
        print(f"FAIL  translation-path symbol {sym} contains {count} SIMD instruction(s)")
        failed = True

    if failed:
        return 1
    print(f"PASS  SIMD guard audit: {len(guards)} guarded routines, "
          f"{sum(1 for s, _ in simd_any.items() if any(t in s for t in TRANSLATION_MARKERS))} "
          f"whitelisted translation-path SIMD sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
