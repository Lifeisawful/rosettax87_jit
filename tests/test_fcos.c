/*
 * test_fcos.c — focused unit test for x87 FCOS.
 *
 * Written as a guard rail for a fast/slow-path split inside _stub_fcos
 * (rosetta_runtime/src/runtime_entry.S).  A hand-written fast path is very easy
 * to get right for cos(0.5) and very easy to get WRONG for everything else, so
 * this pins down the four things such a path actually breaks:
 *
 *   1. Argument reduction.  A polynomial is only valid on ~[-pi/4, pi/4]; the
 *      quadrant selector (n mod 4) and the number of pi/2 terms used in the
 *      reduction decide whether 1e3, 1e10 and 1e15 still come out right.
 *   2. Evenness.  cos(-x) must be BIT-IDENTICAL to cos(x).  Sign tricks in a
 *      fast path are the usual casualty, and this check needs no reference.
 *   3. Stack discipline.  FCOS neither pushes nor pops: ST(1) and TOP must be
 *      untouched, and C1 must be cleared.
 *   4. Mid-run coherence.  The fast path runs with the pinned x87 cache live
 *      (see test_keepalive.c), so FCOS is also exercised sandwiched inside an
 *      x87 run rather than only in isolation.
 *
 * Reference is the host libm with a relative tolerance: the runtime helper is
 * openlibm under the custom loader and Apple's under native Rosetta, and the
 * two may differ in the last ulps.  Bit-exactness is only demanded where the
 * value is exactly representable (cos(+-0) == 1.0) or where the property is
 * structural (evenness).
 *
 * INFO lines are observations, not assertions — they do not fail the run.  They
 * cover the FCOS out-of-range rule, which Intel specifies as
 *
 *      IF |ST(0)| < 2^63  THEN C2 := 0; ST(0) := cos(ST(0))
 *                         ELSE C2 := 1; ST(0) unchanged
 *
 * and which the current runtime helper (x87_fcos in X87.cpp) does NOT
 * implement — it clears C2 unconditionally and always computes.  They are
 * printed so a fast path that changes this behaviour is visible immediately.
 * Promote them to check_*() if you decide to implement the rule.
 *
 * Must pass under native Rosetta AND under the custom runtime_loader.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_fcos test_fcos.c
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

/* x87 status-word condition-code bits. */
#define SW_C0  0x0100u
#define SW_C1  0x0200u
#define SW_C2  0x0400u
#define SW_C3  0x4000u
#define SW_TOP 0x3800u

static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_tol(const char *name, double got, double expected) {
    double err = fabs(got - expected);
    double rel = err / (fabs(expected) > 1e-300 ? fabs(expected) : 1.0);
    if (rel > 1e-9 && err > 1e-12) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* For values that must match bit-for-bit. */
static void check_bits(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g (%016llx)  expected=%.17g (%016llx)\n", name, got,
               (unsigned long long)as_u64(got), expected,
               (unsigned long long)as_u64(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Explicit absolute tolerance, for large arguments where the two backends
 * legitimately disagree (see kArgsReduced). */
static void check_near(const char *name, double got, double expected, double tol) {
    double err = fabs(got - expected);
    if (!(err <= tol)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g  |err|=%.3g > %.3g\n", name, got, expected,
               err, tol);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_true(const char *name, int cond) {
    if (!cond) {
        printf("FAIL  %s\n", name);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void info_sw(const char *name, uint16_t sw, double st0) {
    printf("INFO  %-55s  C2=%u C1=%u sw=0x%04x  ST(0)=%.17g\n", name, (sw & SW_C2) ? 1u : 0u,
           (sw & SW_C1) ? 1u : 0u, sw, st0);
}

/* ---------------------------------------------------------------------------
 * FCOS primitives.  Every sequence is stack-balanced: whatever it pushes it
 * pops, so a leak would show up as a wrong guard value in the ST(1) tests.
 * ------------------------------------------------------------------------- */

/* fld x; fcos; fstp -> result, plus the status word as observed after FCOS. */
static double fcos_sw(double x, uint16_t *sw_out) {
    double r;
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n\t"
        "fcos\n\t"
        "fnstsw %%ax\n\t"
        "movw %%ax, %1\n\t"
        "fstpl %0\n"
        : "=m"(r), "=m"(sw)
        : "m"(x)
        : "ax");
    *sw_out = sw;
    return r;
}

static double fcos1(double x) {
    uint16_t sw;
    return fcos_sw(x, &sw);
}

/* FCOS must not disturb ST(1): push guard, push x, cos, pop both. */
static double fcos_keeps_st1(double x, double guard, double *guard_out) {
    double r, g;
    __asm__ volatile(
        "fldl %3\n\t"  /* ST0=guard              */
        "fldl %2\n\t"  /* ST0=x      ST1=guard   */
        "fcos\n\t"     /* ST0=cos(x) ST1=guard   */
        "fstpl %0\n\t"
        "fstpl %1\n"
        : "=m"(r), "=m"(g)
        : "m"(x), "m"(guard));
    *guard_out = g;
    return r;
}

/* FCOS mid-run: the ops after it reuse the pinned cache base/TOP. */
static double fcos_in_run(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"  /* ST0=b                */
        "fldl %2\n\t"  /* ST0=a  ST1=b         */
        "fcos\n\t"     /* ST0=cos(a)           */
        "fmulp\n\t"    /* ST0=cos(a)*b         */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(b), "m"(a));
    return r;
}

/* Two FCOS in one run, sharing the cache. */
static double fcos_twice_in_run(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"  /* ST0=b            */
        "fcos\n\t"     /* ST0=cos(b)       */
        "fldl %2\n\t"  /* ST0=a ST1=cos(b) */
        "fcos\n\t"     /* ST0=cos(a)       */
        "faddp\n\t"    /* cos(a)+cos(b)    */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(b), "m"(a));
    return r;
}

/* sin(x)^2 + cos(x)^2 == 1 — cross-checks FCOS against FSIN. */
static double pythagoras(double x) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"
        "fcos\n\t"
        "fmul %%st(0), %%st(0)\n\t"
        "fldl %1\n\t"
        "fsin\n\t"
        "fmul %%st(0), %%st(0)\n\t"
        "faddp\n\t"
        "fstpl %0\n"
        : "=m"(r)
        : "m"(x));
    return r;
}

/* Dependent chain — cos is contractive (|cos'| = |sin| < 1), so this converges
 * on the Dottie number and is numerically stable.  Catches a fast path that
 * corrupts state only when hit back-to-back. */
static double fcos_chain(double x, int n) {
    double r = x;
    for (int i = 0; i < n; i++) {
        double t;
        __asm__ volatile("fldl %1\n\t fcos\n\t fstpl %0\n" : "=m"(t) : "m"(r));
        r = t;
    }
    return r;
}

int main(void) {
    /* ---- exact values ------------------------------------------------- */
    check_bits("cos(+0.0) == 1.0", fcos1(0.0), 1.0);
    check_bits("cos(-0.0) == 1.0", fcos1(-0.0), 1.0);
    /* Underflow to 1.0: below ~2^-27 the result rounds to exactly 1.0. */
    check_bits("cos(2^-40) == 1.0", fcos1(0x1p-40), 1.0);
    check_bits("cos(-2^-40) == 1.0", fcos1(-0x1p-40), 1.0);
    check_bits("cos(5e-324) == 1.0 (denormal)", fcos1(5e-324), 1.0);

    /* ---- accuracy across all four quadrants ---------------------------
     * Arguments small enough that every backend agrees with the host libm to
     * ~1e-9 relative.  The ceiling is 1e8: real x87 FCOS reduces modulo a
     * finite pi (66 bits on hardware), which costs about |x| * 2^-66 radians of
     * argument error, i.e. ~1.4e-12 at 1e8 — still far inside the tolerance. */
    static const double kArgsExact[] = {
        1e-8, 0.1, 0.5, 0.75, 1.0,
        M_PI_4, M_PI_2, 3.0 * M_PI_4, M_PI, 1.5 * M_PI, 2.0 * M_PI,
        /* straddling pi/2, where cos is near zero and cancellation bites */
        M_PI_2 - 1e-9, M_PI_2 + 1e-9,
        2.0, 3.0, 4.0, 5.0, 6.0, 7.0,
        /* moderate: multi-term Cody-Waite reduction territory */
        100.0, 255.5, 1000.0, 12345.6789, 1e6, 1e8,
    };
    /* Large arguments.  Native Rosetta's FCOS reduces modulo a finite pi, like
     * the hardware it emulates, so its result drifts from a fully-reduced libm
     * cosine as |x| grows — measured: cos(1e15) differs by ~1.1e-6, and
     * cos(2^62) differs from the loader's openlibm result by ~4e-3.  openlibm
     * (custom loader) reduces exactly and matches libm.  Demanding agreement
     * would encode one backend's reduction as "the correct one", so these
     * assert only what BOTH must satisfy: evenness, |cos| <= 1, and the right
     * quadrant.  1e-2 is far above the reduction drift at these magnitudes and
     * far below a quadrant error, which is O(1). */
    static const double kArgsReduced[] = {1e10, 1e12, 1e15, 1e17};

    const int nexact = (int)(sizeof(kArgsExact) / sizeof(kArgsExact[0]));
    const int nreduced = (int)(sizeof(kArgsReduced) / sizeof(kArgsReduced[0]));

    for (int i = 0; i < nexact; i++) {
        char name[96];
        volatile double x = kArgsExact[i];
        snprintf(name, sizeof(name), "cos(%.17g)", kArgsExact[i]);
        check_tol(name, fcos1(x), cos(x));
    }
    for (int i = 0; i < nreduced; i++) {
        char name[96];
        volatile double x = kArgsReduced[i];
        snprintf(name, sizeof(name), "cos(%.17g) quadrant", kArgsReduced[i]);
        check_near(name, fcos1(x), cos(x), 1e-2);
    }

    /* ---- evenness: cos(-x) must be bit-identical to cos(x) ------------ */
    for (int i = 0; i < nexact + nreduced; i++) {
        char name[96];
        double a = (i < nexact) ? kArgsExact[i] : kArgsReduced[i - nexact];
        volatile double x = a;
        volatile double nx = -a;
        snprintf(name, sizeof(name), "cos(-x) == cos(x) for x=%.17g", a);
        check_bits(name, fcos1(nx), fcos1(x));
    }

    /* ---- range: |cos| must never exceed 1 ----------------------------- */
    {
        int in_range = 1;
        for (int i = 0; i < nexact + nreduced; i++) {
            volatile double x = (i < nexact) ? kArgsExact[i] : kArgsReduced[i - nexact];
            double c = fcos1(x);
            if (!(c >= -1.0 && c <= 1.0)) in_range = 0;
            volatile double nx = -x;
            c = fcos1(nx);
            if (!(c >= -1.0 && c <= 1.0)) in_range = 0;
        }
        check_true("every result within [-1, 1]", in_range);
    }

    /* ---- stack discipline: no push, no pop, C1 clear ------------------ */
    {
        double guard = 0.0;
        double r = fcos_keeps_st1(1.0, 12.5, &guard);
        check_tol("ST(1) guard intact across fcos", guard, 12.5);
        check_tol("fcos result with ST(1) live", r, cos(1.0));
    }
    {
        uint16_t sw = 0xFFFF;
        double r = fcos_sw(0.5, &sw);
        check_true("C2 cleared for in-range arg", (sw & SW_C2) == 0);
        /* C1 is NOT assertable: on FCOS it carries the precision-exception
         * round-up direction, and native Rosetta sets it (observed sw=0x3a22,
         * PE|C1) while the custom loader clears it (sw=0x3800).  Both are
         * defensible readings of the hardware, so this is reported only. */
        info_sw("C1 / status word for cos(0.5)", sw, r);
    }
    {
        /* TOP must be the same before and after. */
        uint16_t before, after;
        __asm__ volatile("fnstsw %%ax\n\t movw %%ax, %0\n" : "=m"(before) : : "ax");
        uint16_t sw;
        (void)fcos_sw(0.5, &sw);
        __asm__ volatile("fnstsw %%ax\n\t movw %%ax, %0\n" : "=m"(after) : : "ax");
        check_true("TOP unchanged across fcos", (before & SW_TOP) == (after & SW_TOP));
    }

    /* ---- mid-run coherence (pinned x87 cache live) -------------------- */
    check_tol("fcos in run: cos(0.5)*3", fcos_in_run(0.5, 3.0), cos(0.5) * 3.0);
    check_tol("fcos in run: cos(2.5)*-1.25", fcos_in_run(2.5, -1.25), cos(2.5) * -1.25);
    check_tol("fcos in run: cos(1e10)*2", fcos_in_run(1e10, 2.0), cos(1e10) * 2.0);
    check_tol("two fcos in one run", fcos_twice_in_run(0.3, 1.7), cos(0.3) + cos(1.7));

    /* ---- cross-check against fsin ------------------------------------- */
    check_tol("sin^2+cos^2 == 1 at x=0.5", pythagoras(0.5), 1.0);
    check_tol("sin^2+cos^2 == 1 at x=2.75", pythagoras(2.75), 1.0);
    check_tol("sin^2+cos^2 == 1 at x=1000", pythagoras(1000.0), 1.0);

    /* ---- back-to-back dependent chain --------------------------------- */
    {
        double expected = 0.7;
        for (int i = 0; i < 64; i++) expected = cos(expected);
        check_tol("64x dependent fcos chain", fcos_chain(0.7, 64), expected);
    }

    /* ---- INFO: FCOS out-of-range rule (see file header) --------------- */
    {
        /* 2^62: the largest power of two still strictly below the 2^63 limit. */
        uint16_t sw;
        volatile double x = 0x1p62;
        double r = fcos_sw(x, &sw);
        info_sw("in-range boundary 2^62", sw, r);

        /* 2^63 and above: Intel says C2=1 and ST(0) is left unchanged. */
        x = 0x1p63;
        r = fcos_sw(x, &sw);
        info_sw("out-of-range 2^63", sw, r);

        x = 1e19;
        r = fcos_sw(x, &sw);
        info_sw("out-of-range 1e19", sw, r);

        x = -1e19;
        r = fcos_sw(x, &sw);
        info_sw("out-of-range -1e19", sw, r);

        x = INFINITY;
        r = fcos_sw(x, &sw);
        info_sw("+inf", sw, r);

        x = -INFINITY;
        r = fcos_sw(x, &sw);
        info_sw("-inf", sw, r);

        x = NAN;
        r = fcos_sw(x, &sw);
        info_sw("qNaN", sw, r);
        check_true("cos(NaN) is NaN", isnan(r));
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
