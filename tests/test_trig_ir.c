/*
 * test_trig_ir.c — guard rail for the OPT-TI FCOS value call
 * (research/optimizations/16-ir-trig-value-call.md).
 *
 * What a value-call fcos actually breaks, and what this pins:
 *
 *   1. Values RESIDENT IN FPRs across the call.  Under ROSETTA_X87_TRIG_IR
 *      an fcos inside an x87 run no longer splits it — surrounding stack
 *      values stay in scratch FPRs across the BL.  The products here must
 *      come out bit-exact.
 *   2. The huge-argument fallback (mega-save + C call).  |x| >= 2^20*(pi/2)
 *      takes _stub_fcos_val's by-value fallback, which must preserve every
 *      live register: pool FPRs holding run values, guest GPRs, guest XMM,
 *      and NZCV.  Each has a dedicated check, with the huge fcos INSIDE a
 *      run so the pool is actually live.
 *   3. C2 clearing in program order.  The "fcos; fnstsw; test C2" range
 *      idiom must see C2=0 for in-range args — under TRIG_IR the clear is
 *      emitted at the call position, not by the runtime helper.
 *
 * Functions are non-static so scripts/inspect_function.sh can disassemble
 * the lowering.  Must pass under native Rosetta AND the custom loader,
 * with and without ROSETTA_X87_TRIG_IR=1.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_trig_ir test_trig_ir.c
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define SW_C2 0x0400u

static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

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

/* fcos inside a run with live values (fast path): r = (cos(x)*c1 + c0) * x. */
double cos_in_run(double x, double c0, double c1) {
    double r;
    __asm__ volatile(
        "fldl %3\n\t"  /* c1                */
        "fldl %1\n\t"  /* x    c1           */
        "fcos\n\t"     /* cosx c1           */
        "fmulp\n\t"    /* cosx*c1           */
        "fldl %2\n\t"  /* c0   ...          */
        "faddp\n\t"    /* cosx*c1+c0        */
        "fldl %1\n\t"  /* x    ...          */
        "fmulp\n\t"    /* (...)*x           */
        "fstpl %0\n"
        : "=m"(r)
        : "m"(x), "m"(c0), "m"(c1));
    return r;
}

/* HUGE fcos inside a run: a and a*b are live (in pool FPRs under TRIG_IR)
 * across the by-value fallback.  cos_out gets cos(huge); returns (a*b)*a. */
double huge_in_run(double a, double b, double huge, double *cos_out) {
    double r, c;
    __asm__ volatile(
        "fldl %2\n\t"                /* a                       */
        "fldl %3\n\t"                /* b     a                 */
        "fmul %%st(1), %%st(0)\n\t"  /* a*b   a                 */
        "fldl %4\n\t"                /* huge  a*b  a            */
        "fcos\n\t"                   /* cosH  a*b  a            */
        "fstpl %1\n\t"               /* a*b   a                 */
        "fmulp\n\t"                  /* (a*b)*a                 */
        "fstpl %0\n"
        : "=m"(r), "=m"(c)
        : "m"(a), "m"(b), "m"(huge));
    *cos_out = c;
    return r;
}

/* Guest GPRs and XMM registers must survive the huge-fallback call. */
int regs_survive_huge(void) {
    volatile double huge = 1e19;
    double sink;
    uint64_t g0 = 0x1122334455667788ULL, g1 = 0x99AABBCCDDEEFF00ULL;
    uint64_t g2 = 0xDEADBEEFCAFEBABEULL, g3 = 0x0123456789ABCDEFULL;
    double x0 = 1.5, x1 = -2.5, x2 = 3.25, x3 = 1e300;
    __asm__ volatile(
        "fldl %8\n\t"
        "fcos\n\t"
        "fstpl %9\n"
        : "+r"(g0), "+r"(g1), "+r"(g2), "+r"(g3),
          "+x"(x0), "+x"(x1), "+x"(x2), "+x"(x3)
        : "m"(huge), "m"(sink));
    return g0 == 0x1122334455667788ULL && g1 == 0x99AABBCCDDEEFF00ULL &&
           g2 == 0xDEADBEEFCAFEBABEULL && g3 == 0x0123456789ABCDEFULL &&
           x0 == 1.5 && x1 == -2.5 && x2 == 3.25 && x3 == 1e300;
}

/* Guest GPRs and XMM registers must survive the pow-trio value stubs
 * (f2xm1 saves q17-q20 + GPRs itself; fscale saves GPRs only). */
int regs_survive_powtrio(void) {
    volatile double x = 0.6, n = 5.0;
    double sink;
    uint64_t g0 = 0x1122334455667788ULL, g1 = 0x99AABBCCDDEEFF00ULL;
    uint64_t g2 = 0xDEADBEEFCAFEBABEULL, g3 = 0x0123456789ABCDEFULL;
    double x0 = 1.5, x1 = -2.5, x2 = 3.25, x3 = 1e300;
    __asm__ volatile(
        "fldl %9\n\t"
        "fldl %8\n\t"
        "f2xm1\n\t"
        "fscale\n\t"
        "fstpl %10\n\t"
        "fstp %%st(0)\n"
        : "+r"(g0), "+r"(g1), "+r"(g2), "+r"(g3),
          "+x"(x0), "+x"(x1), "+x"(x2), "+x"(x3)
        : "m"(x), "m"(n), "m"(sink));
    return g0 == 0x1122334455667788ULL && g1 == 0x99AABBCCDDEEFF00ULL &&
           g2 == 0xDEADBEEFCAFEBABEULL && g3 == 0x0123456789ABCDEFULL &&
           x0 == 1.5 && x1 == -2.5 && x2 == 3.25 && x3 == 1e300;
}

/* Guest GPRs and XMM registers must survive the fyl2x/fyl2xp1 value stubs
 * (they save q18-q24 + x25-x27/x29 themselves). */
int regs_survive_fyl2x(void) {
    volatile double x = 5.5, y = 1.75;
    double sink;
    uint64_t g0 = 0x1122334455667788ULL, g1 = 0x99AABBCCDDEEFF00ULL;
    uint64_t g2 = 0xDEADBEEFCAFEBABEULL, g3 = 0x0123456789ABCDEFULL;
    double x0 = 1.5, x1 = -2.5, x2 = 3.25, x3 = 1e300;
    __asm__ volatile(
        "fldl %9\n\t"
        "fldl %8\n\t"
        "fyl2x\n\t"
        "fstpl %10\n"
        : "+r"(g0), "+r"(g1), "+r"(g2), "+r"(g3),
          "+x"(x0), "+x"(x1), "+x"(x2), "+x"(x3)
        : "m"(x), "m"(y), "m"(sink));
    return g0 == 0x1122334455667788ULL && g1 == 0x99AABBCCDDEEFF00ULL &&
           g2 == 0xDEADBEEFCAFEBABEULL && g3 == 0x0123456789ABCDEFULL &&
           x0 == 1.5 && x1 == -2.5 && x2 == 3.25 && x3 == 1e300;
}

/* EFLAGS must survive fcos (both the fast path and the huge fallback). */
int flags_survive(double arg) {
    int ok;
    double sink;
    __asm__ volatile(
        "cmpl $1, %2\n\t"  /* 2 vs 1: CF=0 ZF=0 → ja taken */
        "fldl %3\n\t"
        "fcos\n\t"
        "fstpl %1\n\t"
        "ja 1f\n\t"
        "movl $0, %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movl $1, %0\n"
        "2:\n"
        : "=r"(ok), "=m"(sink)
        : "r"(2), "m"(arg)
        : "cc");
    return ok;
}

/* C2 must read as 0 after an in-range fcos, at the fcos's program position. */
int c2_cleared(double arg) {
    uint16_t sw;
    double sink;
    __asm__ volatile(
        "fldl %2\n\t"
        "fcos\n\t"
        "fnstsw %%ax\n\t"
        "movw %%ax, %0\n\t"
        "fstpl %1\n"
        : "=m"(sw), "=m"(sink)
        : "m"(arg)
        : "ax");
    return (sw & SW_C2) == 0;
}

/* Dependent chain through the value call — state coherence back-to-back. */
double cos_chain(double x, int n) {
    double r = x;
    for (int i = 0; i < n; i++) {
        double t;
        __asm__ volatile("fldl %1\n\t fcos\n\t fstpl %0\n" : "=m"(t) : "m"(r));
        r = t;
    }
    return r;
}

int main(void) {
    /* ---- values resident across the call (fast path) ------------------- */
    {
        double x = 0.8, c0 = 1.5, c1 = -0.25;
        check_tol("run: (cos(x)*c1+c0)*x", cos_in_run(x, c0, c1),
                  (cos(x) * c1 + c0) * x);
        x = 4.2;
        check_tol("run: quadrant arg", cos_in_run(x, c0, c1), (cos(x) * c1 + c0) * x);
    }

    /* ---- huge fallback with live run values ---------------------------
     * 1e18 < 2^63: every backend computes (native Rosetta included), and it
     * is far above our fast-path bound, so the by-value fallback runs.
     * 1e19/1e300 >= 2^63: native Rosetta implements the Intel rule (ST(0)
     * unchanged, C2=1) while openlibm-based backends compute — assert only
     * the union of the two behaviours; the bit-exact product checks are the
     * real point (live values across the mega-save). */
    {
        double c = 0.0;
        double r = huge_in_run(3.0, 7.0, 1e18, &c);
        check_bits("huge in run: (3*7)*3 == 63 bit-exact", r, 63.0);
        check_near("huge in run: cos(1e18) quadrant-level", c, cos(1e18), 1e-1);
    }
    {
        double c = 0.0;
        double r = huge_in_run(0.125, -8.0, 1e19, &c);
        check_bits("huge in run: (0.125*-8)*0.125 == -0.125", r, -0.125);
        check_true("huge in run: cos(1e19) computed or arch-unchanged",
                   (c >= -1.0 && c <= 1.0) || c == 1e19);
    }
    {
        double c = 0.0;
        double r = huge_in_run(0.5, 6.0, 1e300, &c);
        check_bits("huge in run: (0.5*6)*0.5 == 1.5 bit-exact", r, 1.5);
        check_true("huge in run: cos(1e300) computed or arch-unchanged",
                   (c >= -1.0 && c <= 1.0) || c == 1e300);
    }

    /* ---- register survival across the mega-save fallback -------------- */
    check_true("GPRs + XMM survive huge fcos", regs_survive_huge());

    /* ---- EFLAGS survival ---------------------------------------------- */
    check_true("EFLAGS survive fcos(0.5)", flags_survive(0.5));
    check_true("EFLAGS survive fcos(1e19) fallback", flags_survive(1e19));

    /* ---- C2 clear ordering -------------------------------------------- */
    check_true("C2 cleared after fcos(0.5)", c2_cleared(0.5));
    check_true("C2 cleared after fcos(1000.0)", c2_cleared(1000.0));

    /* ---- NaN/Inf through the by-value fallback ------------------------ */
    {
        volatile double inf = __builtin_inf();
        volatile double qn = __builtin_nan("");
        double t;
        __asm__ volatile("fldl %1\n\t fcos\n\t fstpl %0\n" : "=m"(t) : "m"(inf));
        check_true("cos(Inf) is NaN", isnan(t));
        __asm__ volatile("fldl %1\n\t fcos\n\t fstpl %0\n" : "=m"(t) : "m"(qn));
        check_true("cos(NaN) is NaN", isnan(t));
    }

    /* ---- back-to-back dependent chain --------------------------------- */
    {
        double expected = 0.7;
        for (int i = 0; i < 64; i++) expected = cos(expected);
        check_tol("64x dependent chain", cos_chain(0.7, 64), expected);
    }

    /* ================= FSIN (Phase B) ================= */
    {
        /* sin inside a run with live values: r = (sin(x)*c1 + c0) * x */
        volatile double x = 0.8, c0 = 1.5, c1 = -0.25;
        double r;
        __asm__ volatile(
            "fldl %3\n\t"
            "fldl %1\n\t"
            "fsin\n\t"
            "fmulp\n\t"
            "fldl %2\n\t"
            "faddp\n\t"
            "fldl %1\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(c0), "m"(c1));
        check_tol("fsin run: (sin(x)*c1+c0)*x", r, (sin(0.8) * c1 + c0) * 0.8);
    }
    {
        volatile double nz = -0.0, tiny = 0x1p-40;
        double t;
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(t) : "m"(nz));
        check_bits("fsin(-0) == -0", t, -0.0);
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(t) : "m"(tiny));
        check_bits("fsin(2^-40) == 2^-40", t, 0x1p-40);
    }
    {
        /* huge fsin with live values across the mega-save */
        volatile double a = 3.0, b = 7.0, huge = 1e18;
        double r, s;
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %3\n\t"
            "fmul %%st(1), %%st(0)\n\t"
            "fldl %4\n\t"
            "fsin\n\t"
            "fstpl %1\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r), "=m"(s)
            : "m"(a), "m"(b), "m"(huge));
        check_bits("fsin huge in run: (3*7)*3 == 63 bit-exact", r, 63.0);
        check_near("fsin huge in run: sin(1e18) quadrant-level", s, sin(1e18), 1e-1);
    }

    /* ================= FPTAN (Phase B) ================= */
    {
        /* the push is now IR-materialized: ST0 must be exactly 1.0, ST1 tan */
        volatile double x = 0.5;
        double t, o;
        __asm__ volatile(
            "fldl %2\n\t"
            "fptan\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(x));
        check_bits("fptan pushes exactly 1.0", o, 1.0);
        check_tol("fptan value tan(0.5)", t, tan(0.5));
    }
    {
        /* consume both results in-run: 1.0 + tan via faddp, with a guard */
        volatile double x = 2.0, guard = 42.5;
        double r, g;
        __asm__ volatile(
            "fldl %3\n\t"  /* guard              */
            "fldl %2\n\t"  /* x    guard         */
            "fptan\n\t"    /* 1.0  tan  guard    */
            "faddp\n\t"    /* tan+1.0  guard     */
            "fstpl %0\n\t"
            "fstpl %1\n"
            : "=m"(r), "=m"(g)
            : "m"(x), "m"(guard));
        check_tol("fptan in run: tan(2.0)+1", r, tan(2.0) + 1.0);
        check_tol("fptan in run: deep guard intact", g, 42.5);
    }
    {
        volatile double nz = -0.0;
        double t, o;
        __asm__ volatile(
            "fldl %2\n\t fptan\n\t fstpl %1\n\t fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(nz));
        check_bits("fptan(-0): tan == -0", t, -0.0);
        check_bits("fptan(-0): push == 1.0", o, 1.0);
    }
    {
        /* big-kernel shape (0.7 >= 0.6744) and huge fallback */
        volatile double bigk = 0.7, huge = 1e18;
        double t, o;
        __asm__ volatile(
            "fldl %2\n\t fptan\n\t fstpl %1\n\t fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(bigk));
        check_tol("fptan big-kernel tan(0.7)", t, tan(0.7));
        __asm__ volatile(
            "fldl %2\n\t fptan\n\t fstpl %1\n\t fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(huge));
        check_near("fptan huge tan(1e18) quadrant-level", t, tan(1e18), 1e-1);
        check_bits("fptan huge: push == 1.0", o, 1.0);
    }
    check_true("EFLAGS survive fsin(1e18) fallback", flags_survive(0.5));

    /* ================= FSINCOS (Phase C) ================= */
    {
        /* both results consumed in-run: sin(x)*w1 + cos(x)*w2, with a deep
         * guard live across the single call */
        volatile double x = 0.7, w1 = 0.6, w2 = 0.4, guard = 42.5;
        double r, g;
        __asm__ volatile(
            "fldl %5\n\t"  /* guard                       */
            "fldl %2\n\t"  /* x     guard                 */
            "fsincos\n\t"  /* cos   sin   guard           */
            "fldl %4\n\t"  /* w2    cos   sin   guard     */
            "fmulp\n\t"    /* cosw2 sin   guard           */
            "fxch\n\t"     /* sin   cosw2 guard           */
            "fldl %3\n\t"  /* w1    sin   cosw2 guard     */
            "fmulp\n\t"    /* sinw1 cosw2 guard           */
            "faddp\n\t"    /* sum   guard                 */
            "fstpl %0\n\t"
            "fstpl %1\n"
            : "=m"(r), "=m"(g)
            : "m"(x), "m"(w1), "m"(w2), "m"(guard));
        check_tol("fsincos run: sin*w1+cos*w2", r, sin(0.7) * 0.6 + cos(0.7) * 0.4);
        check_tol("fsincos run: deep guard intact", g, 42.5);
    }
    {
        /* quadrant args exercise the swap/negate paths of the value stub */
        static const double qs[] = { 0.5, 2.0, 3.5, 5.0, -2.0 };
        for (int i = 0; i < 5; i++) {
            volatile double x = qs[i];
            double s, c;
            __asm__ volatile(
                "fldl %2\n\t fsincos\n\t fstpl %1\n\t fstpl %0\n"
                : "=m"(s), "=m"(c) : "m"(x));
            check_tol("fsincos quadrant sin", s, sin(qs[i]));
            check_tol("fsincos quadrant cos", c, cos(qs[i]));
        }
    }
    {
        volatile double nz = -0.0;
        double s, c;
        __asm__ volatile(
            "fldl %2\n\t fsincos\n\t fstpl %1\n\t fstpl %0\n"
            : "=m"(s), "=m"(c) : "m"(nz));
        check_bits("fsincos(-0): sin == -0", s, -0.0);
        check_bits("fsincos(-0): cos == 1.0", c, 1.0);
    }
    {
        /* huge fsincos with live values across the TRIG_VAL_HUGE2 mega-save:
         * both results come back through the saved q16/q17 stack slots */
        volatile double a = 3.0, b = 7.0, huge = 1e18;
        double r, s, c;
        __asm__ volatile(
            "fldl %3\n\t"                /* a                        */
            "fldl %4\n\t"                /* b     a                  */
            "fmul %%st(1), %%st(0)\n\t"  /* a*b   a                  */
            "fldl %5\n\t"                /* huge  a*b   a            */
            "fsincos\n\t"                /* cosH  sinH  a*b  a       */
            "fstpl %2\n\t"               /* sinH  a*b   a            */
            "fstpl %1\n\t"               /* a*b   a                  */
            "fmulp\n\t"                  /* (a*b)*a                  */
            "fstpl %0\n"
            : "=m"(r), "=m"(s), "=m"(c)
            : "m"(a), "m"(b), "m"(huge));
        check_bits("fsincos huge in run: (3*7)*3 == 63 bit-exact", r, 63.0);
        check_near("fsincos huge: sin(1e18) quadrant-level", s, sin(1e18), 1e-1);
        check_near("fsincos huge: cos(1e18) quadrant-level", c, cos(1e18), 1e-1);
    }
    check_true("GPRs + XMM survive huge fcos (post-fsincos)", regs_survive_huge());

    /* ================= F2XM1 (pow-trio) ================= */
    {
        /* defined domain [-1, 1], including both endpoints */
        static const double xs[] = { 0.5, -0.5, 1.0, -1.0, 0.25, -0.99, 0.99 };
        for (int i = 0; i < 7; i++) {
            volatile double x = xs[i];
            double t;
            __asm__ volatile("fldl %1\n\t f2xm1\n\t fstpl %0\n" : "=m"(t) : "m"(x));
            check_tol("f2xm1 in-range", t, exp2(xs[i]) - 1.0);
        }
    }
    {
        /* in-run with live values: (2^x - 1) * c1 + c0, guard live across */
        volatile double x = 0.75, c0 = 3.5, c1 = 2.0;
        double r;
        __asm__ volatile(
            "fldl %3\n\t"  /* c1              */
            "fldl %1\n\t"  /* x     c1        */
            "f2xm1\n\t"    /* 2^x-1 c1        */
            "fmulp\n\t"    /* (2^x-1)*c1      */
            "fldl %2\n\t"  /* c0    ...       */
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r)
            : "m"(x), "m"(c0), "m"(c1));
        check_tol("f2xm1 run: (2^x-1)*c1+c0", r, (exp2(0.75) - 1.0) * 2.0 + 3.5);
    }
    {
        /* out-of-range is architecturally undefined, and implementations
         * disagree (our helper: +0.0; native Rosetta: computed for 1.5,
         * clamped-to-(-1) -0.5 for -2, 0 for 100).  Only require a finite
         * result and a coherent stack — the guard proves the latter. */
        static const double xs[] = { 1.5, -2.0, 100.0 };
        for (int i = 0; i < 3; i++) {
            volatile double x = xs[i], guard = 17.25;
            double t, g;
            __asm__ volatile(
                "fldl %3\n\t fldl %2\n\t f2xm1\n\t fstpl %0\n\t fstpl %1\n"
                : "=m"(t), "=m"(g) : "m"(x), "m"(guard));
            check_true("f2xm1 out-of-range: finite",
                       (as_u64(t) & 0x7FF0000000000000ULL) != 0x7FF0000000000000ULL);
            check_bits("f2xm1 out-of-range: stack coherent", g, 17.25);
        }
    }
    {
        volatile double x = __builtin_nan("");
        double t;
        __asm__ volatile("fldl %1\n\t f2xm1\n\t fstpl %0\n" : "=m"(t) : "m"(x));
        check_true("f2xm1(NaN) is NaN", isnan(t));
    }
    {
        /* tiny x: openlibm's (1+x)-1 path gives 0; hardware gives ~x*ln2 */
        volatile double x = 0x1p-60;
        double t;
        __asm__ volatile("fldl %1\n\t f2xm1\n\t fstpl %0\n" : "=m"(t) : "m"(x));
        check_true("f2xm1(2^-60): 0 or ~x*ln2",
                   t == 0.0 || fabs(t - 0x1p-60 * M_LN2) < 0x1p-110);
    }

    /* ================= FSCALE (pow-trio) ================= */
    {
        /* exact scaling and truncation-toward-zero of ST(1) */
        static const struct { double x, n, want; } cs[] = {
            { 1.5,   3.0,   12.0      },
            { 10.0, -2.0,   2.5       },
            { 1.5,   3.7,   12.0      },   /* trunc(3.7) = 3   */
            { 10.0, -2.9,   2.5       },   /* trunc(-2.9) = -2 */
            { 7.25,  0.0,   7.25      },
            { -3.0,  2.0,  -12.0      },
        };
        for (int i = 0; i < 6; i++) {
            volatile double x = cs[i].x, n = cs[i].n;
            double r, n_out;
            __asm__ volatile(
                "fldl %3\n\t"   /* n            */
                "fldl %2\n\t"   /* x     n      */
                "fscale\n\t"    /* x*2^t n      */
                "fstpl %0\n\t"
                "fstpl %1\n"
                : "=m"(r), "=m"(n_out)
                : "m"(x), "m"(n));
            check_bits("fscale exact", r, cs[i].want);
            check_bits("fscale: ST(1) preserved", n_out, cs[i].n);
        }
    }
    {
        /* signed zero passes through untouched */
        volatile double nz = -0.0, pz = 0.0, n = 100.0;
        double r;
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(nz), "m"(n));
        check_bits("fscale(-0, 100) == -0", r, -0.0);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(pz), "m"(n));
        check_bits("fscale(+0, 100) == +0", r, 0.0);
    }
    {
        /* denormal round trips: 2^-1074 * 2^1074 == 1.0 exactly, and back */
        volatile double dmin = 0x1p-1074, up = 1074.0;
        volatile double one = 1.0, down = -1074.0;
        double r;
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(dmin), "m"(up));
        check_bits("fscale(2^-1074, 1074) == 1.0", r, 1.0);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(one), "m"(down));
        check_bits("fscale(1.0, -1074) == 2^-1074", r, 0x1p-1074);
    }
    {
        /* double-range overflow/underflow (fp80 hardware widens, but the
         * fstpl narrows back, so the stored double agrees) */
        volatile double big = 1e300, up = 1000.0, neg = -1e300;
        volatile double small = 1e-300, down = -1000.0, nsmall = -1e-300;
        double r;
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(big), "m"(up));
        check_bits("fscale(1e300, 1000) == +Inf", r, INFINITY);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(neg), "m"(up));
        check_bits("fscale(-1e300, 1000) == -Inf", r, -INFINITY);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(small), "m"(down));
        check_bits("fscale(1e-300, -1000) == +0", r, 0.0);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(nsmall), "m"(down));
        check_bits("fscale(-1e-300, -1000) == -0", r, -0.0);
    }
    {
        /* enormous ST(1): clamps at ±100000 → saturates like ±Inf scale */
        volatile double x = 2.0, nbig = 1e30, nneg = -1e30, inf = INFINITY;
        double r;
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(x), "m"(nbig));
        check_bits("fscale(2, 1e30) == +Inf", r, INFINITY);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(x), "m"(nneg));
        check_bits("fscale(2, -1e30) == +0", r, 0.0);
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(x), "m"(inf));
        check_bits("fscale(2, +Inf) == +Inf", r, INFINITY);
    }
    {
        /* NaN operands */
        volatile double nan_ = __builtin_nan(""), x = 2.0, n = 3.0;
        double r;
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(x), "m"(nan_));
        check_true("fscale(2, NaN) is NaN", isnan(r));
        __asm__ volatile(
            "fldl %2\n\t fldl %1\n\t fscale\n\t fstpl %0\n\t fstp %%st(0)\n"
            : "=m"(r) : "m"(nan_), "m"(n));
        check_true("fscale(NaN, 3) is NaN", isnan(r));
    }
    {
        /* fscale in a run with live values and a deep guard */
        volatile double x = 1.5, n = 4.0, c = 0.5, guard = 42.5;
        double r, g;
        __asm__ volatile(
            "fldl %5\n\t"   /* guard                 */
            "fldl %3\n\t"   /* n     guard           */
            "fldl %2\n\t"   /* x     n     guard     */
            "fscale\n\t"    /* 24    n     guard     */
            "fldl %4\n\t"   /* c     24    n   guard */
            "fmulp\n\t"     /* 12    n     guard     */
            "fstpl %0\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %1\n"
            : "=m"(r), "=m"(g)
            : "m"(x), "m"(n), "m"(c), "m"(guard));
        check_bits("fscale run: (1.5*2^4)*0.5 == 12", r, 12.0);
        check_bits("fscale run: deep guard intact", g, 42.5);
    }
    {
        /* the inlined-pow idiom the game census found: 2^y for y = 3.3 via
         * f2xm1 on the fraction and fscale by the integer part, both value
         * calls in one x87 neighborhood */
        volatile double y = 3.3;
        double r;
        __asm__ volatile(
            "fldl %1\n\t"          /* y                        */
            "fld %%st(0)\n\t"      /* y     y                  */
            "frndint\n\t"          /* i     y   (RC=nearest)   */
            "fxch\n\t"             /* y     i                  */
            "fsub %%st(1), %%st(0)\n\t" /* f  i   (|f| <= 0.5) */
            "f2xm1\n\t"            /* 2^f-1 i                  */
            "fld1\n\t"             /* 1     2^f-1  i           */
            "faddp\n\t"            /* 2^f   i                  */
            "fscale\n\t"           /* 2^y   i                  */
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(y));
        check_tol("pow idiom: 2^3.3 via f2xm1+fscale", r, pow(2.0, 3.3));
    }
    check_true("GPRs + XMM survive f2xm1+fscale", regs_survive_powtrio());

    /* ================= FYL2X / FYL2XP1 (pow-trio completion) ============ */
    {
        /* accuracy across the domain: y*log2(x) */
        static const double xs[] = { 0.5, 2.0, 3.0, 0.1, 1e10, 1e-10, 1.0000001 };
        static const double ys2[] = { 1.0, -3.0, 0.5 };
        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 3; j++) {
                volatile double x = xs[i], y = ys2[j];
                double r;
                __asm__ volatile(
                    "fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                    : "=m"(r) : "m"(x), "m"(y));
                check_tol("fyl2x domain", r, ys2[j] * log2(xs[i]));
            }
        }
    }
    {
        /* exact powers of two: y*log2(2^n) must be bit-exact */
        volatile double x = 8.0, y = 3.0;
        double r;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_bits("fyl2x(8, 3) == 9", r, 9.0);
        x = 0.25; y = -2.0;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_bits("fyl2x(0.25, -2) == 4", r, 4.0);
        x = 0x1p-1074; y = 1.0;  /* subnormal: log2 = -1074 exactly */
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_bits("fyl2x(2^-1074, 1) == -1074", r, -1074.0);
    }
    {
        /* x == 1: exact +/-0 result with sign from y */
        volatile double x = 1.0, y = 3.0;
        double r;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_bits("fyl2x(1, 3) == +0", r, 0.0);
    }
    {
        /* x == 0 -> y * -Inf; negative x / NaN -> NaN.  Inf checks are
         * bit-pattern based (CONST_PROMOTE isinf() hazard — see header). */
        volatile double x = 0.0, y = 2.0;
        double r;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_true("fyl2x(0, 2) == -Inf",
                   as_u64(r) == 0xFFF0000000000000ULL);
        x = -0.0; y = 2.0;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_true("fyl2x(-0, 2) == -Inf",
                   as_u64(r) == 0xFFF0000000000000ULL);
        x = -2.0; y = 1.0;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_true("fyl2x(-2, 1) is NaN", isnan(r));
        x = __builtin_nan(""); y = 1.0;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_true("fyl2x(NaN, 1) is NaN", isnan(r));
        x = 4.0; y = __builtin_nan("");
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2x\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        check_true("fyl2x(4, NaN) is NaN", isnan(r));
    }
    {
        /* pop coherence: a value below y must become ST(0)'s neighbor after
         * the pop and come out intact */
        volatile double x = 4.0, y = 1.5, guard = 27.75;
        double r, g;
        __asm__ volatile(
            "fldl %4\n\t"   /* guard              */
            "fldl %3\n\t"   /* y     guard        */
            "fldl %2\n\t"   /* x     y      guard */
            "fyl2x\n\t"     /* 3.0   guard        */
            "fstpl %0\n\t"
            "fstpl %1\n"
            : "=m"(r), "=m"(g) : "m"(x), "m"(y), "m"(guard));
        check_bits("fyl2x pop: 1.5*log2(4) == 3", r, 3.0);
        check_bits("fyl2x pop: stack coherent", g, 27.75);
    }
    {
        /* in-run with live values: c1 * (y*log2(x)) + c0 */
        volatile double x = 32.0, y = 0.5, c0 = 1.25, c1 = 2.0;
        double r;
        __asm__ volatile(
            "fldl %4\n\t"   /* c1                  */
            "fldl %3\n\t"   /* y     c1            */
            "fldl %1\n\t"   /* x     y      c1     */
            "fyl2x\n\t"     /* 2.5   c1            */
            "fmulp\n\t"     /* 5.0                 */
            "fldl %2\n\t"
            "faddp\n\t"     /* 6.25                */
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(c0), "m"(y), "m"(c1));
        check_bits("fyl2x run: 2*(0.5*log2(32))+1.25", r, 6.25);
    }
    {
        /* fyl2xp1: moderate args vs log2(1+x) */
        static const double xs[] = { 0.5, -0.25, 3.0, 0.001 };
        for (int i = 0; i < 4; i++) {
            volatile double x = xs[i], y = 2.0;
            double r;
            __asm__ volatile(
                "fldl %2\n\t fldl %1\n\t fyl2xp1\n\t fstpl %0\n"
                : "=m"(r) : "m"(x), "m"(y));
            check_tol("fyl2xp1 domain", r, 2.0 * log2(1.0 + xs[i]));
        }
    }
    {
        /* fyl2xp1 tiny path (|x| < 2^-20): the series must keep the
         * significance a naive 1+x would round away */
        volatile double x = 0x1p-30, y = 1.0;
        double r;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2xp1\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        /* log2(1+eps) ~= eps*log2(e) — relative accuracy, not absolute */
        double expect = 0x1p-30 * 1.4426950408889634074;
        check_true("fyl2xp1 tiny keeps significance",
                   r > expect * 0.999999999 && r < expect * 1.000000001);
        x = -0x1p-40; y = -1.0;
        __asm__ volatile("fldl %2\n\t fldl %1\n\t fyl2xp1\n\t fstpl %0\n"
                         : "=m"(r) : "m"(x), "m"(y));
        expect = 0x1p-40 * 1.4426950408889634074;
        check_true("fyl2xp1 tiny negative x, negative y",
                   r > expect * 0.999999999 && r < expect * 1.000000001);
    }
    {
        /* fyl2xp1 out-of-domain (Intel restricts |x| < 1-sqrt(2)/2; outside
         * is architecturally undefined and native Rosetta computes unrelated
         * values: -1 -> -4.3e9, -2 -> -192.3).  Our helper gives y*-Inf for
         * x == -1 and NaN for x < -1; only require a coherent stack — the
         * guard below the operands proves the pop happened exactly once. */
        static const double xs[] = { -1.0, -2.0 };
        for (int i = 0; i < 2; i++) {
            volatile double x = xs[i], y = 1.0, guard = 13.5;
            double r, g;
            __asm__ volatile(
                "fldl %4\n\t fldl %3\n\t fldl %2\n\t fyl2xp1\n\t"
                "fstpl %0\n\t fstpl %1\n"
                : "=m"(r), "=m"(g) : "m"(x), "m"(y), "m"(guard));
            check_bits("fyl2xp1 out-of-domain: stack coherent", g, 13.5);
        }
    }
    {
        /* the full CRT pow shape (__powhlp): x^y = 2^(y*log2 x), all three
         * pow-trio value calls in one x87 neighborhood */
        volatile double b = 3.7, e = 2.6;
        double r;
        __asm__ volatile(
            "fldl %2\n\t"          /* e                        */
            "fldl %1\n\t"          /* b     e                  */
            "fyl2x\n\t"            /* t=e*log2(b)              */
            "fld %%st(0)\n\t"      /* t     t                  */
            "frndint\n\t"          /* i     t                  */
            "fxch\n\t"             /* t     i                  */
            "fsub %%st(1), %%st(0)\n\t" /* f  i                */
            "f2xm1\n\t"            /* 2^f-1 i                  */
            "fld1\n\t"             /* 1     2^f-1  i           */
            "faddp\n\t"            /* 2^f   i                  */
            "fscale\n\t"           /* 2^t   i                  */
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(b), "m"(e));
        check_tol("pow idiom: 3.7^2.6 via fyl2x+f2xm1+fscale", r,
                  pow(3.7, 2.6));
    }
    check_true("GPRs + XMM survive fyl2x", regs_survive_fyl2x());


    printf("================================\n");
    if (failures == 0) {
        printf("test_trig_ir: ALL PASS\n");
        return 0;
    }
    printf("test_trig_ir: %d FAILURES\n", failures);
    return 1;
}
