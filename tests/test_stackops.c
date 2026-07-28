/*
 * test_stackops.c — Tests for FFREE / FINCSTP / FDECSTP, now translated
 * inline (run-cache members; ROSETTA_X87_DISABLE_STACKOPS=1 or
 * ROSETTA_X87_DISABLE_ALL_OPS=1 reverts to Rosetta's own translation and
 * the classic runtime handlers).
 *
 * Observation channels that work under BOTH native Rosetta and this runtime:
 *   - fnstsw: TOP field (bits 11-13) proves fincstp/fdecstp moved TOP;
 *     C1 (0x0200) must be cleared by both.
 *   - fxam: classifies ST(0) from the real tag word — kEmpty (C3|C0=0x4100)
 *     proves ffree wrote the tag.  (Native sets C1 on empty; accept both.)
 *   - values that survive round trips through freed/reused slots.
 *
 * Build: clang -arch x86_64 -O0 -o test_stackops test_stackops.c -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16_either(const char *name, uint16_t got, uint16_t a, uint16_t b) {
    if (got != a && got != b) {
        printf("FAIL  %-56s  got=0x%04x  expected=0x%04x or 0x%04x\n", name, got, a, b);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_bits(const char *name, double got, double expected) {
    if (memcmp(&got, &expected, sizeof(double)) != 0) {
        printf("FAIL  %-56s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

#define TOP_OF(sw) (((sw) >> 11) & 7)

/* ── primitives ─────────────────────────────────────────────────────────── */

/* TOP field before / after / after-undo of FINCSTP+FDECSTP, from an
 * empty-stack baseline (fninit → TOP = 0). */
__attribute__((noinline)) static void incdec_tops(uint16_t sw[4]) {
    __asm__ volatile(
        "fninit\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "fincstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        "fincstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 4(%0)\n\t"
        "fdecstp\n\t"
        "fdecstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 6(%0)\n\t"
        :
        : "r"(sw)
        : "ax", "memory", "st");
}

/* FDECSTP wraps 0 → 7. */
__attribute__((noinline)) static void dec_wrap_tops(uint16_t sw[2]) {
    __asm__ volatile(
        "fninit\n\t"
        "fdecstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "fincstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        :
        : "r"(sw)
        : "ax", "memory", "st");
}

/* 8 × FINCSTP wraps TOP all the way around. */
__attribute__((noinline)) static uint16_t inc8_top(void) {
    uint16_t sw;
    __asm__ volatile(
        "fninit\n\t"
        "fincstp\n\t" "fincstp\n\t" "fincstp\n\t" "fincstp\n\t"
        "fincstp\n\t" "fincstp\n\t" "fincstp\n\t" "fincstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %0\n\t"
        : "=m"(sw)
        :
        : "ax", "st");
    return sw;
}

/* C1 must be cleared by fincstp/fdecstp: set C1 via FXAM on a negative
 * value (C1 = sign), then check it's gone after the stack op. */
__attribute__((noinline)) static void c1_clear(uint16_t sw[2]) {
    double neg = -1.5;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %1\n\t"
        "fxam\n\t"                /* sets C1 (sign of -1.5) */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "fincstp\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        "fdecstp\n\t"
        "fstp  %%st(0)\n\t"
        :
        : "r"(sw), "m"(neg)
        : "ax", "memory", "st");
}

/* FFREE ST(0): fxam must report empty afterwards. */
__attribute__((noinline)) static void ffree_st0(uint16_t sw[2]) {
    double v = 2.5;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %1\n\t"
        "fxam\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "ffree %%st(0)\n\t"
        "fxam\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        "fincstp\n\t"             /* discard the freed slot from the view */
        :
        : "r"(sw), "m"(v)
        : "ax", "memory", "st");
}

/* FFREE ST(2) frees the right slot: st0/st1 stay usable, st2 turns empty
 * (observed by rotating it into ST(0) with fincstp×2 and FXAMing). */
__attribute__((noinline)) static void ffree_st2(uint16_t sw[3], double out[2]) {
    double a = 1.25, b = 2.5, c = 4.75;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"            /* st2 = a (after two more pushes) */
        "fldl  %3\n\t"            /* st1 = b */
        "fldl  %4\n\t"            /* st0 = c */
        "ffree %%st(2)\n\t"       /* frees the slot holding a */
        "fxam\n\t"                /* st0 = c: still valid/normal */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%1)\n\t"
        "fincstp\n\t"
        "fincstp\n\t"             /* logical view now starts at old st2 */
        "fxam\n\t"                /* freed slot → empty */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%1)\n\t"
        "fdecstp\n\t"
        "fdecstp\n\t"
        "fstpl 0(%0)\n\t"         /* c back out */
        "fstpl 8(%0)\n\t"         /* b back out */
        "fincstp\n\t"             /* skip the freed slot (fstp of empty would
                                     push garbage through the classic path) */
        :
        : "r"(out), "r"(sw), "m"(a), "m"(b), "m"(c)
        : "ax", "memory", "st", "st(1)", "st(2)");
    (void)sw;
}

/* Freed slot is immediately reusable by a push. */
__attribute__((noinline)) static double ffree_reuse(void) {
    double v = 3.5, w = 7.25, r;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %1\n\t"
        "ffree %%st(0)\n\t"
        "fincstp\n\t"             /* net effect: discard without fstp */
        "fldl  %2\n\t"            /* reuses the freed physical slot */
        "fstpl %0\n\t"
        : "=m"(r)
        : "m"(v), "m"(w)
        : "ax", "st");
    return r;
}

/* The WoW/vendor idiom: x87 loop results discarded with ffree×4 between
 * x87-dense blocks; everything afterwards must still compute correctly. */
__attribute__((noinline)) static double wow_idiom(void) {
    double a = 1.5, b = 2.5, c = 3.5, d = 4.5, out;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %1\n\t"
        "fldl  %2\n\t"
        "fldl  %3\n\t"
        "fldl  %4\n\t"
        "ffree %%st(3)\n\t"
        "ffree %%st(2)\n\t"
        "ffree %%st(1)\n\t"
        "ffree %%st(0)\n\t"
        "fincstp\n\t" "fincstp\n\t" "fincstp\n\t" "fincstp\n\t"
        "fldl  %1\n\t"            /* fresh work after the frees */
        "fldl  %2\n\t"
        "faddp %%st(0), %%st(1)\n\t"
        "fstpl %0\n\t"
        : "=m"(out)
        : "m"(a), "m"(b), "m"(c), "m"(d)
        : "ax", "st", "st(1)", "st(2)", "st(3)");
    return out;
}

/* Deferred-state hazards: ffree/fincstp inside an active x87 run right
 * after pushes (deferred push tags + deferred TOP) and an FXCH (perm). */
__attribute__((noinline)) static void hazard_push_ffree(uint16_t sw[1], double out[1]) {
    double a = 1.5, b = 2.25;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"            /* push a           (deferred tag valid) */
        "fldl  %3\n\t"            /* push b           (deferred tag valid) */
        "ffree %%st(0)\n\t"       /* free b's slot — must beat the deferred
                                     tag-valid flush */
        "fincstp\n\t"
        "fxam\n\t"                /* st0 = a: valid normal */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%1)\n\t"
        "fstpl 0(%0)\n\t"         /* a back out */
        :
        : "r"(out), "r"(sw), "m"(a), "m"(b)
        : "ax", "memory", "st", "st(1)");
}

__attribute__((noinline)) static void hazard_fxch_ffree(uint16_t sw[2], double out[1]) {
    double a = 1.5, b = 2.25;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"            /* st1 = a */
        "fldl  %3\n\t"            /* st0 = b */
        "fxch  %%st(1)\n\t"       /* st0 = a, st1 = b (deferred perm) */
        "ffree %%st(1)\n\t"       /* frees the slot logically holding b */
        "fxam\n\t"                /* st0 = a: valid */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%1)\n\t"
        "fstpl 0(%0)\n\t"         /* pops a */
        "fxam\n\t"                /* st0 now the freed slot: empty */
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%1)\n\t"
        "fincstp\n\t"
        :
        : "r"(out), "r"(sw), "m"(a), "m"(b)
        : "ax", "memory", "st", "st(1)");
}

/* fincstp between a push and a pop: TOP bookkeeping must survive mixing
 * deferred push/pop with explicit TOP rotation. */
__attribute__((noinline)) static double hazard_inc_between(void) {
    double a = 5.5, r;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %1\n\t"            /* TOP=7, st0 = a */
        "fincstp\n\t"             /* TOP=0, a now at st(7) */
        "fdecstp\n\t"             /* TOP=7 again */
        "fstpl %0\n\t"            /* a back out */
        : "=m"(r)
        : "m"(a)
        : "ax", "st");
    return r;
}

int main(void) {
    /* fincstp / fdecstp TOP movement */
    {
        uint16_t sw[4];
        incdec_tops(sw);
        check_u16("fninit TOP=0", TOP_OF(sw[0]), 0);
        check_u16("fincstp TOP=1", TOP_OF(sw[1]), 1);
        check_u16("fincstp TOP=2", TOP_OF(sw[2]), 2);
        check_u16("fdecstp x2 TOP=0", TOP_OF(sw[3]), 0);
    }
    {
        uint16_t sw[2];
        dec_wrap_tops(sw);
        check_u16("fdecstp wraps 0->7", TOP_OF(sw[0]), 7);
        check_u16("fincstp back 7->0", TOP_OF(sw[1]), 0);
    }
    check_u16("fincstp x8 wraps to 0", TOP_OF(inc8_top()), 0);

    /* C1 clearing */
    {
        uint16_t sw[2];
        c1_clear(sw);
        check_u16("fxam(-1.5) set C1", sw[0] & 0x0200, 0x0200);
        check_u16("fincstp cleared C1", sw[1] & 0x0200, 0);
    }

    /* ffree tag effects via fxam (native sets C1 on empty — accept both) */
    {
        uint16_t sw[2];
        ffree_st0(sw);
        check_u16("before ffree: st0 normal", sw[0] & 0x4500, 0x0400);
        check_u16_either("after ffree st(0): empty", sw[1] & 0x4700, 0x4100, 0x4300);
    }
    {
        uint16_t sw[3];
        double out[2] = {0, 0};
        ffree_st2(sw, out);
        check_u16("ffree st(2): st0 still normal", sw[0] & 0x4500, 0x0400);
        check_u16_either("ffree st(2): slot empty", sw[1] & 0x4700, 0x4100, 0x4300);
        check_bits("ffree st(2): st0 value intact", out[0], 4.75);
        check_bits("ffree st(2): st1 value intact", out[1], 2.5);
    }
    check_bits("freed slot reusable by push", ffree_reuse(), 7.25);

    /* the vendor/CRT idiom */
    check_bits("wow idiom (ffree x4 + fincstp x4)", wow_idiom(), 1.5 + 2.5);

    /* deferred-state hazards inside runs */
    {
        uint16_t sw[1];
        double out[1] = {0};
        hazard_push_ffree(sw, out);
        check_u16("push+push+ffree: st0 normal", sw[0] & 0x4500, 0x0400);
        check_bits("push+push+ffree: value intact", out[0], 1.5);
    }
    {
        uint16_t sw[2];
        double out[1] = {0};
        hazard_fxch_ffree(sw, out);
        check_u16("fxch+ffree: st0 normal", sw[0] & 0x4500, 0x0400);
        check_bits("fxch+ffree: kept value is a", out[0], 1.5);
        check_u16_either("fxch+ffree: freed slot empty", sw[1] & 0x4700, 0x4100, 0x4300);
    }
    check_bits("fincstp/fdecstp around a value", hazard_inc_between(), 5.5);

    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
