/*
 * test_trig_status_word.c — status_word ordering across trig/pow value calls.
 *
 * Two related mechanisms, both in the IR run pipeline:
 *
 * 1. FCOM+FSTSW fusion guard.  pass_fcom_fstsw_fusion keeps a compare's packed
 *    CC in a GPR and lets the paired FSTSW store the whole halfword, skipping
 *    one LDRH.  Its "nothing modifies CC in between" scan originally looked
 *    only for another FCmp/FTst — but every trig/pow value call clears C1 (|C2)
 *    in status_word at its own program position.  With a call between the
 *    compare and the FSTSW, the fused store re-imposed the COMPARE's C1/C2 on
 *    top of the call's clear.
 *
 *    Visible whenever the compare left C2 set, i.e. it was UNORDERED (a NaN
 *    operand sets C3=C2=C0=1).  An in-range fcos then clears C2, so the
 *    architectural result has C3=1, C2=0, C0=1; the fused store reported
 *    C2=1.  Ordered compares leave C2=0 either way and never showed it.
 *
 * 2. OPT-TS dead-clear elimination.  A call's C1|C2 RMW is dropped when a later
 *    node in the same run overwrites the whole halfword before anything reads
 *    it (see X87IRLower.cpp).  A bare FNSTSW reads status_word back, so the
 *    clear must survive in exactly the shapes below — these cases pin that.
 *    ROSETTA_X87_DISABLE_TRIG_SW_SINK=1 is the A/B lever; every expectation
 *    here must hold with it both set and unset.
 *
 * Requires ROSETTA_X87_TRIG_IR=1 to exercise the IR value-call path; the
 * classic stub path is correct by construction and the test passes there too.
 *
 * Build: clang -arch x86_64 -O0 -o test_trig_status_word test_trig_status_word.c
 */
#include <stdio.h>
#include <stdint.h>

static int failures = 0;

static void check(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-58s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* CC bits: C3 = 0x4000, C2 = 0x0400, C1 = 0x0200, C0 = 0x0100.
 *
 * C1 is deliberately EXCLUDED from the mask. On real x87 (and under native
 * Rosetta) C1 is the precision-exception roundup bit, so fcos(0.5) leaves
 * C1 = 1; both of this project's trig paths — the classic fast stubs and the
 * TRIG_IR value calls — clear it unconditionally, matching the "exceptions are
 * unmodeled" stance the rest of the pipeline takes (verified: native 0x3a20 vs
 * ours 0x3800 for a bare `fcos; fnstsw`, identical with and without TRIG_IR).
 * That divergence is pre-existing and orthogonal to what this test pins; the
 * mask keeps these cases meaningful under native Rosetta (phase 1) too. */
#define CC_MASK 0x4500

/* Unordered compare, then an in-range fcos, then FNSTSW.
 * fcomp sets C3=C2=C0=1 (NaN); fcos clears C1|C2 and leaves C0/C3 alone. */
static uint16_t fcom_cos_fstsw(double a, double nan_val) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"          /* st0 = a                     */
        "fldl %2\n"          /* st0 = NaN, st1 = a          */
        "fcomp %%st(1)\n"    /* unordered: C3=C2=C0=1; pop  */
        "fcos\n"             /* clears C1|C2 (a in range)   */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(nan_val) : "ax", "st");
    return sw;
}

/* Same, with fsincos (also a C1|C2 clear, and it pushes). */
static uint16_t fcom_sincos_fstsw(double a, double nan_val) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fcomp %%st(1)\n"    /* unordered: C3=C2=C0=1; pop  */
        "fsincos\n"          /* clears C1|C2; pushes cos    */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(nan_val) : "ax", "st");
    return sw;
}

/* Same, with fptan (C1|C2 clear, pushes the architectural 1.0). */
static uint16_t fcom_ptan_fstsw(double a, double nan_val) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fcomp %%st(1)\n"
        "fptan\n"            /* clears C1|C2; pushes 1.0    */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(nan_val) : "ax", "st");
    return sw;
}

/* fyl2x clears C1 only — C2 from the unordered compare must SURVIVE. */
static uint16_t fcom_yl2x_fstsw(double a, double b, double nan_val) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"          /* st0 = a                          */
        "fldl %2\n"          /* st0 = b,   st1 = a               */
        "fldl %3\n"          /* st0 = NaN, st1 = b, st2 = a      */
        "fcomp %%st(1)\n"    /* unordered: C3=C2=C0=1; pop       */
        "fyl2x\n"            /* st1*log2(st0); clears C1; pops   */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b), "m"(nan_val) : "ax", "st");
    return sw;
}

/* Control: ordered compare + fcos.  C2 is 0 from both sides, so this passed
 * even with the fusion bug — it pins that the guard did not break the
 * ordinary case. */
static uint16_t fcom_cos_fstsw_ordered(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fcomp %%st(1)\n"    /* ordered: b vs a             */
        "fcos\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "st");
    return sw;
}

/* Control: no call between compare and FSTSW — the fusion this guard protects
 * must still happen and still be correct. */
static uint16_t fcom_fstsw_fused(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fcomp %%st(1)\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax", "st");
    return sw;
}

int main(void) {
    const double nan_val = __builtin_nan("");
    uint16_t sw;

    /* Unordered compare (C3|C2|C0) followed by a C1|C2-clearing call:
     * C2 must come from the CALL (0), not from the compare (1). */
    sw = fcom_cos_fstsw(0.5, nan_val);
    check("fcomp(unordered); fcos; fnstsw -> C2 cleared by fcos",
          sw & CC_MASK, 0x4100);

    sw = fcom_sincos_fstsw(0.5, nan_val);
    check("fcomp(unordered); fsincos; fnstsw -> C2 cleared by fsincos",
          sw & CC_MASK, 0x4100);

    sw = fcom_ptan_fstsw(0.5, nan_val);
    check("fcomp(unordered); fptan; fnstsw -> C2 cleared by fptan",
          sw & CC_MASK, 0x4100);

    /* fyl2x clears C1 only, so the compare's C2 must still be there. */
    sw = fcom_yl2x_fstsw(2.0, 3.0, nan_val);
    check("fcomp(unordered); fyl2x; fnstsw -> C2 survives (C1-only clear)",
          sw & CC_MASK, 0x4500);

    /* Ordered controls. */
    sw = fcom_cos_fstsw_ordered(1.5, 2.5);
    check("fcomp(2.5 > 1.5); fcos; fnstsw -> CC clear",
          sw & CC_MASK, 0x0000);

    sw = fcom_cos_fstsw_ordered(2.5, 1.5);
    check("fcomp(1.5 < 2.5); fcos; fnstsw -> C0",
          sw & CC_MASK, 0x0100);

    /* Fusion still active and correct with nothing in between. */
    sw = fcom_fstsw_fused(1.5, 2.5);
    check("fcomp(2.5 > 1.5); fnstsw (fused) -> CC clear",
          sw & CC_MASK, 0x0000);

    sw = fcom_fstsw_fused(2.5, 1.5);
    check("fcomp(1.5 < 2.5); fnstsw (fused) -> C0",
          sw & CC_MASK, 0x0100);

    sw = fcom_fstsw_fused(nan_val, 1.5);
    check("fcomp(unordered); fnstsw (fused) -> C3|C2|C0",
          sw & CC_MASK, 0x4500);

    if (failures == 0)
        printf("ALL TESTS PASSED (9 tests)\n");
    else
        printf("%d TESTS FAILED\n", failures);
    return failures != 0;
}
