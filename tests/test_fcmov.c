/*
 * test_fcmov.c -- validate FCMOV via the IR pipeline (FCSel)
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_fcmov test_fcmov.c
 *
 * Tests the canonical FCOMI+FCMOV+FSTP pattern that the IR should consume
 * as a single run (FComI + FCSel + store/epilogue).
 *
 * Section A: Basic FCMOV variants with FCOMI (IR path: FComI + FCSel)
 * Section B: Chained FCMOVs after a single FCOMI
 * Section C: FCOMIP (popping compare) + FCMOV
 * Section D: FCMOV with equal values / edge cases
 */

#include <stdint.h>
#include <stdio.h>

static int failures = 0;

static void check_d(const char *name, double got, double expected) {
    if (got != expected) {
        printf("FAIL  %-70s  got=%f  expected=%f\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ── Section A: FCOMI + FCMOV + FSTP (canonical 3-instruction pattern) ──── */

/*
 * FCMOVNBE: move if not below or equal (CF=0 and ZF=0, i.e. above).
 * Branchless max: result = (ST(0) > ST(1)) ? ST(1) : ST(0)
 *
 * With ST(0)=5.0, ST(1)=3.0:  5.0 > 3.0, FCMOVNBE fires → ST(0)=ST(1)=3.0?
 * No — FCMOVNBE copies ST(1) to ST(0) when condition is true (above).
 * FCOMI sets CF=0 ZF=0 when ST(0) > ST(1), so FCMOVNBE triggers.
 *
 * Actually: FCMOVNBE ST(0),ST(1) means: if NOT (below or equal), ST(0) = ST(1).
 * FCOMI 5.0 vs 3.0 → above → FCMOVNBE fires → ST(0) = 3.0 (was ST(1)).
 */
static void test_fcmovnbe_fires(void) {
    double a = 5.0, b = 3.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"           /* push b=3.0; ST(0)=3.0                */
        "fldl  %1\n\t"           /* push a=5.0; ST(0)=5.0 ST(1)=3.0     */
        "fcomi %%st(1)\n\t"      /* compare: 5.0 > 3.0 → CF=0 ZF=0     */
        "fcmovnbe %%st(1), %%st\n\t" /* above → ST(0) = ST(1) = 3.0     */
        "fstp  %%st(1)\n\t"      /* store result, pop                    */
        "fstpl %0\n"             /* read ST(0) = 3.0                     */
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovnbe fires (5.0 > 3.0): result=3.0", result, 3.0);
}

/* FCMOVNBE does NOT fire when ST(0) < ST(1) → ST(0) unchanged. */
static void test_fcmovnbe_no_fire(void) {
    double a = 2.0, b = 7.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"           /* push b=7.0; ST(0)=7.0                */
        "fldl  %1\n\t"           /* push a=2.0; ST(0)=2.0 ST(1)=7.0     */
        "fcomi %%st(1)\n\t"      /* compare: 2.0 < 7.0 → CF=1           */
        "fcmovnbe %%st(1), %%st\n\t" /* not above → ST(0) stays 2.0      */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovnbe no-fire (2.0 < 7.0): result=2.0", result, 2.0);
}

/* FCMOVB: move if below (CF=1). */
static void test_fcmovb_fires(void) {
    double a = 1.0, b = 4.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=1.0 ST(1)=4.0 */
        "fcomi %%st(1)\n\t"      /* 1.0 < 4.0 → CF=1    */
        "fcmovb %%st(1), %%st\n\t" /* below → ST(0) = 4.0  */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovb fires (1.0 < 4.0): result=4.0", result, 4.0);
}

static void test_fcmovb_no_fire(void) {
    double a = 6.0, b = 2.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=6.0 ST(1)=2.0 */
        "fcomi %%st(1)\n\t"      /* 6.0 > 2.0 → CF=0    */
        "fcmovb %%st(1), %%st\n\t" /* not below → stays    */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovb no-fire (6.0 > 2.0): result=6.0", result, 6.0);
}

/* FCMOVE: move if equal (ZF=1). */
static void test_fcmove_fires(void) {
    double a = 3.0, b = 3.0, c = 9.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"           /* push c=9.0                            */
        "fldl  %2\n\t"           /* push b=3.0; ST(0)=3.0 ST(1)=9.0      */
        "fldl  %1\n\t"           /* push a=3.0; ST(0)=3.0 ST(1)=3.0 ST(2)=9.0 */
        "fcomi %%st(1)\n\t"      /* 3.0 == 3.0 → ZF=1                    */
        "fcmove %%st(2), %%st\n\t" /* equal → ST(0) = ST(2) = 9.0         */
        "fstp  %%st(1)\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("A/fcmove fires (3.0 == 3.0): result=9.0", result, 9.0);
}

/* FCMOVNE: move if not equal (ZF=0). */
static void test_fcmovne_fires(void) {
    double a = 5.0, b = 3.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=5.0 ST(1)=3.0 */
        "fcomi %%st(1)\n\t"      /* 5.0 != 3.0 → ZF=0   */
        "fcmovne %%st(1), %%st\n\t" /* not equal → ST(0) = 3.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovne fires (5.0 != 3.0): result=3.0", result, 3.0);
}

/* FCMOVBE: move if below or equal (CF=1 or ZF=1). */
static void test_fcmovbe_fires_below(void) {
    double a = 1.0, b = 4.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=1.0 ST(1)=4.0 */
        "fcomi %%st(1)\n\t"      /* 1.0 < 4.0 → CF=1    */
        "fcmovbe %%st(1), %%st\n\t" /* below → ST(0) = 4.0  */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovbe fires below (1.0 < 4.0): result=4.0", result, 4.0);
}

static void test_fcmovbe_fires_equal(void) {
    double a = 4.0, b = 4.0, c = 8.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=4.0 ST(1)=4.0 ST(2)=8.0 */
        "fcomi %%st(1)\n\t"      /* 4.0 == 4.0 → ZF=1              */
        "fcmovbe %%st(2), %%st\n\t" /* equal → ST(0) = 8.0           */
        "fstp  %%st(1)\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("A/fcmovbe fires equal (4.0 == 4.0): result=8.0", result, 8.0);
}

/* FCMOVNB: move if not below (CF=0). */
static void test_fcmovnb_fires(void) {
    double a = 5.0, b = 3.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=5.0 ST(1)=3.0 */
        "fcomi %%st(1)\n\t"      /* 5.0 > 3.0 → CF=0    */
        "fcmovnb %%st(1), %%st\n\t" /* not below → ST(0) = 3.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovnb fires (5.0 > 3.0): result=3.0", result, 3.0);
}

/* FCMOVU: move if unordered (PF=1, i.e. NaN involved). */
static void test_fcmovu_fires(void) {
    double a = __builtin_nan(""), b = 1.0, c = 42.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=NaN ST(1)=1.0 ST(2)=42.0 */
        "fcomi %%st(1)\n\t"      /* NaN vs 1.0 → unordered PF=1    */
        "fcmovu %%st(2), %%st\n\t" /* unordered → ST(0) = 42.0      */
        "fstp  %%st(1)\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("A/fcmovu fires (NaN unordered): result=42.0", result, 42.0);
}

/* FCMOVNU: move if not unordered (PF=0). */
static void test_fcmovnu_fires(void) {
    double a = 5.0, b = 3.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=5.0 ST(1)=3.0 */
        "fcomi %%st(1)\n\t"      /* ordered → PF=0      */
        "fcmovnu %%st(1), %%st\n\t" /* not unordered → ST(0) = 3.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("A/fcmovnu fires (ordered): result=3.0", result, 3.0);
}

/* ── Section B: Chained FCMOVs after a single FCOMI ──────────────────────── */

/*
 * Pattern: FCOMI; FCMOVB; FCMOVNBE
 * Both read the same NZCV. Only one should fire.
 *
 * ST(0)=1.0, ST(1)=5.0, ST(2)=9.0
 * FCOMI: 1.0 < 5.0 → CF=1, ZF=0
 * FCMOVB fires: ST(0) = ST(1) = 5.0
 * FCMOVNBE: condition not met (CF=1) → ST(0) stays 5.0
 */
static void test_chained_fcmov(void) {
    double a = 1.0, b = 5.0, c = 9.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"           /* push c=9.0                         */
        "fldl  %2\n\t"           /* push b=5.0                         */
        "fldl  %1\n\t"           /* push a=1.0; ST(0)=1 ST(1)=5 ST(2)=9 */
        "fcomi %%st(1)\n\t"      /* 1.0 < 5.0 → CF=1, ZF=0            */
        "fcmovb  %%st(1), %%st\n\t" /* below → ST(0) = 5.0              */
        "fcmovnbe %%st(2), %%st\n\t" /* not above → no change          */
        "fstp  %%st(1)\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("B/chained (1<5): fcmovb fires, fcmovnbe no-fire: result=5.0", result, 5.0);
}

/*
 * Reverse: ST(0)=8.0 > ST(1)=2.0
 * FCMOVB: CF=0 → no fire
 * FCMOVNBE: CF=0 and ZF=0 → fires, ST(0) = ST(2) = 9.0
 */
static void test_chained_fcmov_reverse(void) {
    double a = 8.0, b = 2.0, c = 9.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=8 ST(1)=2 ST(2)=9 */
        "fcomi %%st(1)\n\t"      /* 8.0 > 2.0 → CF=0, ZF=0  */
        "fcmovb  %%st(1), %%st\n\t" /* not below → no change  */
        "fcmovnbe %%st(2), %%st\n\t" /* above → ST(0) = 9.0    */
        "fstp  %%st(1)\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("B/chained (8>2): fcmovb no-fire, fcmovnbe fires: result=9.0", result, 9.0);
}

/* ── Section C: FCOMIP (popping compare) + FCMOV ─────────────────────────── */

/*
 * FCOMIP pops ST(0) after comparing, then FCMOV reads the same NZCV.
 * push 9.0, push 3.0, push 1.0 → ST(0)=1.0 ST(1)=3.0 ST(2)=9.0
 * FCOMIP ST(1): 1.0 < 3.0 → CF=1, pop → ST(0)=3.0 ST(1)=9.0
 * FCMOVB ST(1): below → ST(0) = ST(1) = 9.0
 */
static void test_fcomip_fcmov(void) {
    double a = 1.0, b = 3.0, c = 9.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %3\n\t"           /* push c=9.0 */
        "fldl  %2\n\t"           /* push b=3.0 */
        "fldl  %1\n\t"           /* push a=1.0; ST(0)=1 ST(1)=3 ST(2)=9 */
        "fcomip %%st(1)\n\t"     /* 1<3 CF=1, pop → ST(0)=3 ST(1)=9     */
        "fcmovb %%st(1), %%st\n\t" /* below → ST(0) = 9.0                */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b), "=m" (c)
        : "m" (a), "m" (b), "m" (c)
        : "cc", "st"
    );
    check_d("C/fcomip+fcmovb (1<3, pop, below): result=9.0", result, 9.0);
}

/* ── Section D: Branchless min/max (real-world game pattern) ─────────────── */

/*
 * Branchless max(a, b):
 *   FLD b; FLD a; FCOMI ST(1); FCMOVB ST(1); FSTP ST(1)
 * Result: max value in ST(0), then stored.
 *
 * When a > b: FCMOVB doesn't fire, ST(0)=a (the max).
 * When a < b: FCMOVB fires, ST(0)=b (the max).
 */
static void test_branchless_max(void) {
    double a = 10.0, b = 20.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"           /* push b=20.0 */
        "fldl  %1\n\t"           /* push a=10.0; ST(0)=10.0 ST(1)=20.0 */
        "fcomi %%st(1)\n\t"      /* 10.0 < 20.0 → CF=1                 */
        "fcmovb %%st(1), %%st\n\t" /* below → ST(0) = 20.0 (the max)   */
        "fstp  %%st(1)\n\t"      /* pop ST(1)                           */
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("D/branchless max(10, 20) = 20.0", result, 20.0);

    a = 30.0; b = 15.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=30.0 ST(1)=15.0 */
        "fcomi %%st(1)\n\t"      /* 30.0 > 15.0 → CF=0    */
        "fcmovb %%st(1), %%st\n\t" /* not below → stays 30.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("D/branchless max(30, 15) = 30.0", result, 30.0);
}

/*
 * Branchless min(a, b):
 *   FLD b; FLD a; FCOMI ST(1); FCMOVNB ST(1); FSTP ST(1)
 * FCMOVNB: move if not below (CF=0), i.e. when a >= b → take b.
 */
static void test_branchless_min(void) {
    double a = 10.0, b = 20.0;
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=10.0 ST(1)=20.0 */
        "fcomi %%st(1)\n\t"      /* 10.0 < 20.0 → CF=1    */
        "fcmovnb %%st(1), %%st\n\t" /* CF=1 → not "not below" → stays 10.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("D/branchless min(10, 20) = 10.0", result, 10.0);

    a = 30.0; b = 15.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"           /* ST(0)=30.0 ST(1)=15.0     */
        "fcomi %%st(1)\n\t"      /* 30.0 > 15.0 → CF=0        */
        "fcmovnb %%st(1), %%st\n\t" /* not below → ST(0) = 15.0 */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b)
        : "cc", "st"
    );
    check_d("D/branchless min(30, 15) = 15.0", result, 15.0);
}

/* ── Section E: guest CMP/TEST as the FCMOV flag source (GuestCmpF) ─────── */
/*
 * No FCOMI anywhere: the flags come from an integer cmp/test between the
 * x87 loads and the FCMOV — the exact shape of branchless-select loops.
 * With TRANSPARENT_FLAGS the IR consumes the cmp/test as a GuestCmpF node
 * (SUBS/ANDS) and keeps the whole thing one run; without it, the run splits
 * and the classic paths handle it. Results must be identical either way.
 * The trailing `xor %%edx,%%edx` kills PF/AF inside the block so the
 * consumption gate (PF/AF-dead via flag_liveness) can pass in production,
 * mirroring real loops where the counter update follows the select.
 */
static void test_cmp_imm_fcmov(const char *name, int lhs, double a, double b,
                               double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"           /* ST(0)=b                     */
        "fldl  %1\n\t"           /* ST(0)=a ST(1)=b             */
        "cmpl  $5, %5\n\t"       /* CF = (lhs <u 5)             */
        "fcmovb %%st(1), %%st\n\t" /* below → ST(0)=b           */
        "xorl  %%edx, %%edx\n\t" /* full flag definer: PF/AF die here */
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

static void test_cmp_reg_fcmov(const char *name, int lhs, int rhs, double a,
                               double b, double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "cmpl  %6, %5\n\t"       /* CF = (lhs <u rhs)           */
        "fcmovnb %%st(1), %%st\n\t" /* not-below → ST(0)=b      */
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs), "r" (rhs)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

static void test_test_self_fcmov(const char *name, int val, double a, double b,
                                 double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "testl %5, %5\n\t"       /* ZF = (val == 0)             */
        "fcmove %%st(1), %%st\n\t" /* zero → ST(0)=b            */
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (val)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

static void test_test_imm_fcmov(const char *name, int val, double a, double b,
                                double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "testl $0x4500, %5\n\t"  /* non-bitmask imm: scratch ANDS path */
        "fcmovne %%st(1), %%st\n\t" /* any bit set → ST(0)=b    */
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (val)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

static void test_cmp_big_imm_fcmov(const char *name, int lhs, double a,
                                   double b, double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "cmpl  $0x123456, %5\n\t" /* fits no imm12 form: scratch SUBS  */
        "fcmovb %%st(1), %%st\n\t"
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

static void test_cmp_neg_imm_fcmov(const char *name, int lhs, double a,
                                   double b, double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "cmpl  $-16, %5\n\t"     /* negative imm: CMN alias path       */
        "fcmovb %%st(1), %%st\n\t" /* CF = (lhs <u 0xFFFFFFF0)         */
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

/* No flag-killer before block end: PF/AF stay live out of the cmp, so the
 * IR must DECLINE the cmp (conservative) and still produce correct results
 * through the split-run path. */
static void test_cmp_fcmov_no_killer(const char *name, int lhs, double a,
                                     double b, double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "cmpl  $5, %5\n\t"
        "fcmovb %%st(1), %%st\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs)
        : "cc", "st"
    );
    check_d(name, result, expected);
}

/* fcomi THEN cmp: the cmp's flags must win (the FComI pack is dead). */
static void test_fcomi_then_cmp_fcmov(const char *name, int lhs, double a,
                                      double b, double expected) {
    double result = 0.0;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "fcomi %%st(1)\n\t"      /* flags from a vs b — then overwritten */
        "cmpl  $5, %5\n\t"
        "fcmovb %%st(1), %%st\n\t" /* must test lhs<5, NOT a vs b        */
        "xorl  %%edx, %%edx\n\t"
        "fstp  %%st(1)\n\t"
        "fstpl %0\n"
        : "=m" (result), "=m" (a), "=m" (b)
        : "m" (a), "m" (b), "r" (lhs)
        : "cc", "st", "edx"
    );
    check_d(name, result, expected);
}

/* ── Section F: fcomp/fnstsw/test — the classic compare-branch idiom ────── */
/*
 * `fcompp; fnstsw %ax; test {ax,ah,al}, imm; jcc` — the dominant x87
 * compare shape in 32-bit game code. With TRANSPARENT_FLAGS the sub-32
 * test-imm forms are consumed as GuestCmpF (shifted ANDS), keeping the run
 * alive through the test and letting the compares elide their NZCV
 * save/restore (the consumed test proves the flags dead). The trailing
 * `xorl %%edx,%%edx` at the join kills PF so the consumption gate can pass.
 */
static void check_i(const char *name, int got, int expected) {
    if (got != expected) {
        printf("FAIL  %-70s  got=%d  expected=%d\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* testw $0x4500, %ax: ZF=1 iff C0=C2=C3=0 iff ST(0) > ST(1) ordered. */
static void test_fnstsw_testw_gt(const char *name, double x, double y,
                                 int expected) {
    int r;
    __asm__ volatile (
        "fldl  %2\n\t"           /* y                         */
        "fldl  %1\n\t"           /* x; ST(0)=x ST(1)=y        */
        "fcompp\n\t"             /* compare x vs y, pop both  */
        "fnstsw %%ax\n\t"
        "testw $0x4500, %%ax\n\t"
        "jz    1f\n\t"
        "movl  $0, %0\n\t"       /* not greater               */
        "jmp   2f\n"
        "1:\n\t"
        "movl  $1, %0\n"         /* greater                   */
        "2:\n\t"
        "xorl  %%edx, %%edx\n"
        : "=r" (r), "=m" (x), "=m" (y)
        : "m" (x), "m" (y)
        : "cc", "st", "ax", "edx"
    );
    check_i(name, r, expected);
}

/* test %ah, $0x45 — the sahf-free byte variant of the same predicate.
 * The fldz/fstp after the test keeps the run window open THROUGH it, so
 * this variant exercises the mid-run GuestCmpF consumption of the sub-32
 * test (x87 ops between the test and the jcc don't touch EFLAGS). */
static void test_fnstsw_testb_ah(const char *name, double x, double y,
                                 int expected) {
    int r;
    double dummy;
    __asm__ volatile (
        "fldl  %3\n\t"
        "fldl  %1\n\t"
        "fcompp\n\t"
        "fnstsw %%ax\n\t"
        "testb $0x45, %%ah\n\t"
        "fldz\n\t"
        "fstpl %2\n\t"
        "jz    1f\n\t"
        "movl  $0, %0\n\t"
        "jmp   2f\n"
        "1:\n\t"
        "movl  $1, %0\n"
        "2:\n\t"
        "xorl  %%edx, %%edx\n"
        : "=r" (r), "=m" (x), "=m" (dummy), "=m" (y)
        : "m" (x), "m" (y)
        : "cc", "st", "ax", "edx"
    );
    check_i(name, r, expected);
}

/* testw $0x4000, %ax: ZF=0 iff C3 set iff equal (or unordered's C3=0 no). */
static void test_fnstsw_testw_eq(const char *name, double x, double y,
                                 int expected) {
    int r;
    __asm__ volatile (
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "fcompp\n\t"
        "fnstsw %%ax\n\t"
        "testw $0x4000, %%ax\n\t"
        "jnz   1f\n\t"
        "movl  $0, %0\n\t"       /* C3=0: not equal           */
        "jmp   2f\n"
        "1:\n\t"
        "movl  $1, %0\n"         /* C3=1: equal               */
        "2:\n\t"
        "xorl  %%edx, %%edx\n"
        : "=r" (r), "=m" (x), "=m" (y)
        : "m" (x), "m" (y)
        : "cc", "st", "ax", "edx"
    );
    check_i(name, r, expected);
}

/* test %al low-byte form: fnstsw's low byte is exception flags — cleared
 * with FNCLEX first (earlier sections' NaN FCOMIs leave sticky IE on real
 * hardware; the JIT doesn't model exceptions) — so test $0xFF, %al must
 * take the ZF=1 arm. Checks the r8lo shift path. */
static void test_fnstsw_testb_al(const char *name) {
    int r;
    double x = 1.0, y = 2.0;
    __asm__ volatile (
        "fnclex\n\t"
        "fldl  %2\n\t"
        "fldl  %1\n\t"
        "fcompp\n\t"
        "fnstsw %%ax\n\t"
        "testb $0xFF, %%al\n\t"
        "jz    1f\n\t"
        "movl  $0, %0\n\t"
        "jmp   2f\n"
        "1:\n\t"
        "movl  $1, %0\n"
        "2:\n\t"
        "xorl  %%edx, %%edx\n"
        : "=r" (r), "=m" (x), "=m" (y)
        : "m" (x), "m" (y)
        : "cc", "st", "ax", "edx"
    );
    check_i(name, r, 1);
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    /* Section A: all 8 FCMOV variants */
    test_fcmovnbe_fires();
    test_fcmovnbe_no_fire();
    test_fcmovb_fires();
    test_fcmovb_no_fire();
    test_fcmove_fires();
    test_fcmovne_fires();
    test_fcmovbe_fires_below();
    test_fcmovbe_fires_equal();
    test_fcmovnb_fires();
    test_fcmovu_fires();
    test_fcmovnu_fires();

    /* Section B: chained FCMOVs */
    test_chained_fcmov();
    test_chained_fcmov_reverse();

    /* Section C: FCOMIP + FCMOV */
    test_fcomip_fcmov();

    /* Section D: real-world patterns */
    test_branchless_max();
    test_branchless_min();

    /* Section E: guest CMP/TEST as the FCMOV flag source (GuestCmpF) */
    test_cmp_imm_fcmov("E/cmp $5, 3: below -> b", 3, 7.0, 9.0, 9.0);
    test_cmp_imm_fcmov("E/cmp $5, 8: not below -> a", 8, 7.0, 9.0, 7.0);
    test_cmp_reg_fcmov("E/cmp r,r 9 vs 4: nb fires -> b", 9, 4, 7.0, 9.0, 9.0);
    test_cmp_reg_fcmov("E/cmp r,r 2 vs 4: nb holds -> a", 2, 4, 7.0, 9.0, 7.0);
    test_test_self_fcmov("E/test r,r zero: e fires -> b", 0, 7.0, 9.0, 9.0);
    test_test_self_fcmov("E/test r,r nonzero: e holds -> a", 3, 7.0, 9.0, 7.0);
    test_test_imm_fcmov("E/test $0x4500 hit: ne fires -> b", 0x400, 7.0, 9.0, 9.0);
    test_test_imm_fcmov("E/test $0x4500 miss: ne holds -> a", 0xBA, 7.0, 9.0, 7.0);
    test_cmp_big_imm_fcmov("E/cmp $0x123456, 5: below -> b", 5, 7.0, 9.0, 9.0);
    test_cmp_neg_imm_fcmov("E/cmp $-16, 5: below -> b", 5, 7.0, 9.0, 9.0);
    test_cmp_neg_imm_fcmov("E/cmp $-16, -8: not below -> a", -8, 7.0, 9.0, 7.0);
    test_cmp_fcmov_no_killer("E/no flag killer: below -> b", 3, 7.0, 9.0, 9.0);
    test_cmp_fcmov_no_killer("E/no flag killer: not below -> a", 8, 7.0, 9.0, 7.0);
    test_fcomi_then_cmp_fcmov("E/fcomi then cmp: cmp wins -> b", 3, 7.0, 9.0, 9.0);
    test_fcomi_then_cmp_fcmov("E/fcomi then cmp: cmp wins -> a", 8, 7.0, 9.0, 7.0);

    /* Section F: fcomp/fnstsw/test idiom (sub-32 GuestCmpF widths) */
    test_fnstsw_testw_gt("F/testw 0x4500: 5>3 -> greater", 5.0, 3.0, 1);
    test_fnstsw_testw_gt("F/testw 0x4500: 2<9 -> not greater", 2.0, 9.0, 0);
    test_fnstsw_testw_gt("F/testw 0x4500: 4==4 -> not greater", 4.0, 4.0, 0);
    test_fnstsw_testw_gt("F/testw 0x4500: NaN -> not greater",
                         __builtin_nan(""), 1.0, 0);
    test_fnstsw_testb_ah("F/test ah,0x45: 5>3 -> greater", 5.0, 3.0, 1);
    test_fnstsw_testb_ah("F/test ah,0x45: 2<9 -> not greater", 2.0, 9.0, 0);
    test_fnstsw_testw_eq("F/testw 0x4000: 4==4 -> equal", 4.0, 4.0, 1);
    test_fnstsw_testw_eq("F/testw 0x4000: 5>3 -> not equal", 5.0, 3.0, 0);
    test_fnstsw_testw_eq("F/testw 0x4000: 2<9 -> not equal", 2.0, 9.0, 0);
    test_fnstsw_testb_al("F/test al,0xFF: exception byte clear");

    if (failures == 0)
        printf("\nAll tests passed.\n");
    else
        printf("\n%d test(s) FAILED.\n", failures);

    return failures ? 1 : 0;
}
