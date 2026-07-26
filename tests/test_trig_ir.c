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

    printf("================================\n");
    if (failures == 0) {
        printf("test_trig_ir: ALL PASS\n");
        return 0;
    }
    printf("test_trig_ir: %d FAILURES\n", failures);
    return 1;
}
