/*
 * test_fstsw_topdelta.c — FStsw top_delta snapshot vs. optimizer node-ID
 * collision.
 *
 * FStsw carries two small metadata values (destination register index and the
 * top_delta snapshot for TOP patching).  When these lived in inputs[1]/[2],
 * every optimizer loop that walks inputs[] treated them as node references:
 * pass_const_arith's fold_to could REWRITE the top_delta snapshot whenever an
 * identity-folded node's ID collided with it, corrupting the TOP field
 * (bits 13:11) of the FNSTSW AX result.
 *
 * Repro shape (one IR run must start mid-stack, so the two outer loads are
 * separated from it by a non-consumable instruction):
 *
 *   fld A ; fld B            ; earlier run
 *   xchg %ebx,%ebx           ; run break (not x87, not transparent-int)
 *   fld1                     ; node 0 = ConstOne, push
 *   fmulp %st(1)             ; node 1 = ReadSt(B), node 2 = FMul(n1, ConstOne)
 *   fcompp                   ; node 3 = ReadSt(A), node 4 = FCmp, pops 2
 *   fnstsw %ax               ; top_delta snapshot = +2  ==  FMul node ID 2
 *
 * The FMul-by-one identity fold (keep = node 1) rewrote the snapshot 2 -> 1,
 * so AX reported TOP = entry_top + 1 (= 7) instead of the architectural 0.
 *
 * Build: clang -arch x86_64 -O0 -o test_fstsw_topdelta test_fstsw_topdelta.c
 */
#include <stdio.h>
#include <stdint.h>

static int failures = 0;

static void check(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* TOP = SW bits 13:11; CC mask C3|C2|C0 = 0x4500. */

/* fold at node id == top_delta snapshot (+2 via fcompp). */
static uint16_t fold_collision_fcompp(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "xchg %%ebx, %%ebx\n"   /* run break: next run enters mid-stack */
        "fld1\n"
        "fmulp %%st(1)\n"       /* B * 1.0 — identity-folded */
        "fcompp\n"              /* compare B vs A, pop both */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "ebx");
    return sw;
}

/* Same shape with fcomp+fstp (snapshot +2 reached differently) and a
 * divide-by-one fold — exercises the FDiv identity path. */
static uint16_t fold_collision_fdiv(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "xchg %%ebx, %%ebx\n"
        "fld1\n"
        /* FDIVP ST(1),ST — st1 = st1/1.0, identity-folded. Raw encoding:
         * AT&T fdivp mnemonics assemble reversed (the classic gas quirk). */
        ".byte 0xDE, 0xF9\n"
        "fcompp\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "ebx");
    return sw;
}

/* Control: no foldable node — TOP patching alone (never failed). */
static uint16_t no_fold_control(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "xchg %%ebx, %%ebx\n"
        "fcompp\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "ebx");
    return sw;
}

int main(void) {
    /* Stack is balanced (all pops) -> architectural TOP after = 0. */
    uint16_t sw;

    sw = fold_collision_fcompp(1.5, 2.5);
    check("fmulp-by-1 fold vs fcompp snapshot: TOP field", sw & 0x3800, 0x0000);
    check("fmulp-by-1 fold vs fcompp snapshot: CC (2.5 > 1.5)", sw & 0x4500, 0x0000);

    sw = fold_collision_fcompp(2.5, 1.5);
    check("fmulp-by-1 fold, CC LT (1.5 < 2.5)", sw & 0x4500, 0x0100);

    sw = fold_collision_fdiv(1.5, 2.5);
    check("fdivp-by-1 fold vs fcompp snapshot: TOP field", sw & 0x3800, 0x0000);
    check("fdivp-by-1 fold vs fcompp snapshot: CC (2.5 > 1.5)", sw & 0x4500, 0x0000);

    sw = no_fold_control(1.5, 2.5);
    check("control (no fold): TOP field", sw & 0x3800, 0x0000);
    check("control (no fold): CC (2.5 > 1.5)", sw & 0x4500, 0x0000);

    if (failures == 0)
        printf("ALL TESTS PASSED (7 tests)\n");
    else
        printf("%d TESTS FAILED\n", failures);
    return failures != 0;
}
