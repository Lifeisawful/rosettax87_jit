/*
 * test_trig.c — focused unit tests for x87 FSIN, FSINCOS and FPTAN.
 *
 * Guard rail for the in-blob fast paths (_stub_fsin_fast / _stub_fsincos_fast /
 * _stub_fptan_fast in rosetta_runtime/src/runtime_entry.S), companion to
 * test_fcos.c.  Beyond the accuracy sweep it pins the things a hand-written
 * fast path actually breaks:
 *
 *   1. Stack discipline.  FSIN neither pushes nor pops; FSINCOS and FPTAN
 *      both PUSH one value (TOP decreases by one before the sequence pops it
 *      back).  Deeper stack slots must be untouched.
 *   2. Symmetry.  sin(-x) == -sin(x) and tan(-x) == -tan(x) BIT-IDENTICAL,
 *      and sin/tan of +-0 must return +-0 (the odd-polynomial kernels do not
 *      naturally preserve -0 — the tiny path must).
 *   3. FSINCOS coherence: its sine and cosine must satisfy sin^2+cos^2 == 1
 *      and match libm within tolerance for the same argument.
 *   4. FPTAN pushes exactly 1.0 (bit-exact) on top of the tangent, and the
 *      kernel's three shapes are all exercised: |x| < 0.6744 (plain
 *      polynomial), |x| >= 0.6744 (pi/4 substitution), and odd quadrants
 *      (-1/tan path, e.g. x=2.0).
 *   5. Mid-run coherence with the pinned x87 cache live.
 *
 * Reference is the host libm with a relative tolerance (backends differ in
 * the last ulps); large arguments assert only quadrant-level agreement, as in
 * test_fcos.c.  Must pass under native Rosetta AND the custom runtime_loader.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_trig test_trig.c
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define SW_C1  0x0200u
#define SW_C2  0x0400u
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

/* ---------------------------------------------------------------------------
 * Primitives.  Every sequence is stack-balanced.
 * ------------------------------------------------------------------------- */

static double fsin_sw(double x, uint16_t *sw_out) {
    double r;
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n\t"
        "fsin\n\t"
        "fnstsw %%ax\n\t"
        "movw %%ax, %1\n\t"
        "fstpl %0\n"
        : "=m"(r), "=m"(sw)
        : "m"(x)
        : "ax");
    *sw_out = sw;
    return r;
}

static double fsin1(double x) {
    uint16_t sw;
    return fsin_sw(x, &sw);
}

/* FSINCOS: ST0=cos, ST1=sin afterwards; pop cos first, then sin. */
static void fsincos1(double x, double *sin_out, double *cos_out) {
    double s, c;
    __asm__ volatile(
        "fldl %2\n\t"
        "fsincos\n\t"
        "fstpl %1\n\t"
        "fstpl %0\n"
        : "=m"(s), "=m"(c)
        : "m"(x));
    *sin_out = s;
    *cos_out = c;
}

/* FPTAN: ST0=1.0, ST1=tan afterwards. */
static void fptan1(double x, double *tan_out, double *one_out) {
    double t, o;
    __asm__ volatile(
        "fldl %2\n\t"
        "fptan\n\t"
        "fstpl %1\n\t"
        "fstpl %0\n"
        : "=m"(t), "=m"(o)
        : "m"(x));
    *tan_out = t;
    *one_out = o;
}

static double fptan_tan(double x) {
    double t, o;
    fptan1(x, &t, &o);
    return t;
}

/* Deeper stack slot must survive the push+pop pair of FSINCOS / FPTAN. */
static double fsincos_keeps_deep(double x, double guard, double *guard_out) {
    double s, c, g;
    __asm__ volatile(
        "fldl %4\n\t"     /* ST0=guard                          */
        "fldl %3\n\t"     /* ST0=x     ST1=guard                */
        "fsincos\n\t"     /* ST0=cos   ST1=sin   ST2=guard      */
        "fstpl %1\n\t"
        "fstpl %0\n\t"
        "fstpl %2\n"
        : "=m"(s), "=m"(c), "=m"(g)
        : "m"(x), "m"(guard));
    *guard_out = g;
    return s;
}

static double fptan_keeps_deep(double x, double guard, double *guard_out) {
    double t, o, g;
    __asm__ volatile(
        "fldl %4\n\t"
        "fldl %3\n\t"
        "fptan\n\t"       /* ST0=1.0  ST1=tan  ST2=guard */
        "fstpl %1\n\t"
        "fstpl %0\n\t"
        "fstpl %2\n"
        : "=m"(t), "=m"(o), "=m"(g)
        : "m"(x), "m"(guard));
    *guard_out = g;
    return t;
}

/* FSIN mid-run: following ops reuse the pinned cache. */
static double fsin_in_run(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"
        "fldl %2\n\t"
        "fsin\n\t"
        "fmulp\n\t"
        "fstpl %0\n"
        : "=m"(r)
        : "m"(b), "m"(a));
    return r;
}

/* FSINCOS mid-run: consume both results with cache-handled ops. */
static double fsincos_in_run(double a) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"
        "fsincos\n\t"  /* ST0=cos ST1=sin */
        "faddp\n\t"    /* sin+cos         */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(a));
    return r;
}

/* FPTAN mid-run: 1.0 + tan via faddp. */
static double fptan_in_run(double a) {
    double r;
    __asm__ volatile(
        "fldl %1\n\t"
        "fptan\n\t"    /* ST0=1.0 ST1=tan */
        "faddp\n\t"    /* tan+1.0         */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(a));
    return r;
}

static uint16_t read_sw(void) {
    uint16_t sw;
    __asm__ volatile("fnstsw %%ax\n\t movw %%ax, %0\n" : "=m"(sw) : : "ax");
    return sw;
}

int main(void) {
    /* Arguments where every backend must agree with libm to ~1e-9 relative.
     * (For tan, values near odd multiples of pi/2 are excluded: tan explodes
     * there and relative agreement between backends is not meaningful.) */
    static const double kArgs[] = {
        1e-8, 0.1, 0.5, 0.6, 0.7, 0.75, 1.0,      /* 0.7 > 0.6744: k_tan branch */
        M_PI_4, 2.0, 2.5, 3.0, M_PI, 4.0, 5.0, 6.0, 7.0,
        100.0, 255.5, 1000.0, 12345.6789, 1e6, 1e8,
    };
    static const double kArgsReduced[] = {1e10, 1e12, 1e15, 1e17};
    const int nargs = (int)(sizeof(kArgs) / sizeof(kArgs[0]));
    const int nreduced = (int)(sizeof(kArgsReduced) / sizeof(kArgsReduced[0]));

    /* ================= FSIN ================= */

    check_bits("sin(+0.0) == +0.0", fsin1(0.0), 0.0);
    check_bits("sin(-0.0) == -0.0", fsin1(-0.0), -0.0);
    check_bits("sin(2^-40) == 2^-40", fsin1(0x1p-40), 0x1p-40);
    check_bits("sin(-2^-40) == -2^-40", fsin1(-0x1p-40), -0x1p-40);
    check_bits("sin(5e-324) == 5e-324 (denormal)", fsin1(5e-324), 5e-324);

    for (int i = 0; i < nargs; i++) {
        char name[96];
        volatile double x = kArgs[i];
        snprintf(name, sizeof(name), "sin(%.17g)", kArgs[i]);
        check_tol(name, fsin1(x), sin(x));
    }
    for (int i = 0; i < nreduced; i++) {
        char name[96];
        volatile double x = kArgsReduced[i];
        snprintf(name, sizeof(name), "sin(%.17g) quadrant", kArgsReduced[i]);
        check_near(name, fsin1(x), sin(x), 1e-2);
    }
    for (int i = 0; i < nargs + nreduced; i++) {
        char name[96];
        double a = (i < nargs) ? kArgs[i] : kArgsReduced[i - nargs];
        volatile double x = a;
        volatile double nx = -a;
        snprintf(name, sizeof(name), "sin(-x) == -sin(x) for x=%.17g", a);
        check_bits(name, fsin1(nx), -fsin1(x));
    }
    {
        int in_range = 1;
        for (int i = 0; i < nargs + nreduced; i++) {
            volatile double x = (i < nargs) ? kArgs[i] : kArgsReduced[i - nargs];
            double s = fsin1(x);
            if (!(s >= -1.0 && s <= 1.0)) in_range = 0;
        }
        check_true("every fsin result within [-1, 1]", in_range);
    }
    {
        uint16_t before = read_sw(), sw;
        double r = fsin_sw(0.5, &sw);
        uint16_t after = read_sw();
        check_true("fsin: TOP unchanged", (before & SW_TOP) == (after & SW_TOP));
        check_true("fsin: C2 cleared for in-range arg", (sw & SW_C2) == 0);
        check_tol("fsin result with sw captured", r, sin(0.5));
    }
    check_tol("fsin in run: sin(0.5)*3", fsin_in_run(0.5, 3.0), sin(0.5) * 3.0);
    check_tol("fsin in run: sin(2.5)*-1.25", fsin_in_run(2.5, -1.25), sin(2.5) * -1.25);
    check_tol("fsin in run: sin(1e10)*2", fsin_in_run(1e10, 2.0), sin(1e10) * 2.0);

    /* ================= FSINCOS ================= */

    for (int i = 0; i < nargs; i++) {
        char name[96];
        volatile double x = kArgs[i];
        double s, c;
        fsincos1(x, &s, &c);
        snprintf(name, sizeof(name), "fsincos sin(%.17g)", kArgs[i]);
        check_tol(name, s, sin(x));
        snprintf(name, sizeof(name), "fsincos cos(%.17g)", kArgs[i]);
        check_tol(name, c, cos(x));
        snprintf(name, sizeof(name), "fsincos sin^2+cos^2 (%.17g)", kArgs[i]);
        check_tol(name, s * s + c * c, 1.0);
    }
    {
        double s, c;
        fsincos1(0.0, &s, &c);
        check_bits("fsincos(+0): sin == +0", s, 0.0);
        check_bits("fsincos(+0): cos == 1.0", c, 1.0);
        fsincos1(-0.0, &s, &c);
        check_bits("fsincos(-0): sin == -0", s, -0.0);
        check_bits("fsincos(-0): cos == 1.0", c, 1.0);
    }
    {
        /* bail path: huge argument must still satisfy the identity */
        volatile double x = 1e15;
        double s, c;
        fsincos1(x, &s, &c);
        check_tol("fsincos(1e15): sin^2+cos^2", s * s + c * c, 1.0);
        check_near("fsincos(1e15): sin quadrant", s, sin(x), 1e-2);
    }
    {
        uint16_t before = read_sw();
        double g = 0.0, s = fsincos_keeps_deep(0.8, 42.5, &g);
        uint16_t after = read_sw();
        check_tol("fsincos: deep guard intact", g, 42.5);
        check_tol("fsincos: sin with deep stack", s, sin(0.8));
        check_true("fsincos: TOP balanced after pops", (before & SW_TOP) == (after & SW_TOP));
    }
    check_tol("fsincos in run: sin+cos (0.5)", fsincos_in_run(0.5), sin(0.5) + cos(0.5));
    check_tol("fsincos in run: sin+cos (4.2)", fsincos_in_run(4.2), sin(4.2) + cos(4.2));

    /* ================= FPTAN ================= */

    for (int i = 0; i < nargs; i++) {
        char name[96];
        volatile double x = kArgs[i];
        snprintf(name, sizeof(name), "tan(%.17g)", kArgs[i]);
        check_tol(name, fptan_tan(x), tan(x));
    }
    {
        double t, o;
        fptan1(0.5, &t, &o);
        check_bits("fptan pushes exactly 1.0", o, 1.0);
        fptan1(2.0, &t, &o); /* odd quadrant: -1/tan kernel shape */
        check_bits("fptan pushes exactly 1.0 (odd quadrant)", o, 1.0);
        check_tol("fptan odd-quadrant value tan(2.0)", t, tan(2.0));
    }
    {
        double t, o;
        fptan1(0.0, &t, &o);
        check_bits("tan(+0) == +0", t, 0.0);
        fptan1(-0.0, &t, &o);
        check_bits("tan(-0) == -0", t, -0.0);
        fptan1(0x1p-40, &t, &o);
        check_bits("tan(2^-40) == 2^-40", t, 0x1p-40);
    }
    for (int i = 0; i < nargs; i++) {
        char name[96];
        double a = kArgs[i];
        volatile double x = a;
        volatile double nx = -a;
        snprintf(name, sizeof(name), "tan(-x) == -tan(x) for x=%.17g", a);
        check_bits(name, fptan_tan(nx), -fptan_tan(x));
    }
    {
        /* bail path parity: huge and special arguments */
        volatile double x = 1e15;
        check_near("tan(1e15) quadrant-level", fptan_tan(x), tan(x), 1e-1);
        volatile double qn = __builtin_nan("");
        check_true("tan(NaN) is NaN", isnan(fptan_tan(qn)));
    }
    {
        uint16_t before = read_sw();
        double g = 0.0, t = fptan_keeps_deep(0.8, -7.25, &g);
        uint16_t after = read_sw();
        check_tol("fptan: deep guard intact", g, -7.25);
        check_tol("fptan: tan with deep stack", t, tan(0.8));
        check_true("fptan: TOP balanced after pops", (before & SW_TOP) == (after & SW_TOP));
    }
    check_tol("fptan in run: tan(0.5)+1", fptan_in_run(0.5), tan(0.5) + 1.0);
    check_tol("fptan in run: tan(2.0)+1", fptan_in_run(2.0), tan(2.0) + 1.0);

    /* ================= cross-op ================= */

    /* fsincos must agree with the separate fsin to the last few ulps (they
     * share kernels on the fast path; allow tolerance for native Rosetta). */
    for (int i = 0; i < nargs; i += 4) {
        char name[96];
        volatile double x = kArgs[i];
        double s, c;
        fsincos1(x, &s, &c);
        snprintf(name, sizeof(name), "fsincos vs fsin at %.17g", kArgs[i]);
        check_tol(name, s, fsin1(x));
    }

    printf("================================\n");
    if (failures == 0) {
        printf("test_trig: ALL PASS\n");
        return 0;
    }
    printf("test_trig: %d FAILURES\n", failures);
    return 1;
}
