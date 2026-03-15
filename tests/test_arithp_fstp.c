/*
 * test_arithp_fstp.c — Tests for ARITHp ST(1) + FSTP mem fusion.
 *
 * Covers: faddp+fstp, fsubp+fstp, fmulp+fstp, fdivp+fstp (m64 and m32),
 *         stack depth preservation, consecutive pairs.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_arithp_fstp test_arithp_fstp.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f32(const char *name, float got, float expected) {
    uint32_t gu, eu;
    memcpy(&gu, &got, 4);
    memcpy(&eu, &expected, 4);
    if (gu != eu) {
        printf("FAIL  %-55s  got=%.9g  expected=%.9g\n", name, (double)got, (double)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ==== faddp ST(1) + fstp m64 ==== */
static double faddp_fstp_m64(void) {
    double r;
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 3.0 */
        "fldl %2\n"         /* ST(0) = 7.0, ST(1) = 3.0 */
        "faddp\n"           /* ST(0) = 3.0 + 7.0 = 10.0 */
        "fstpl %0\n"        /* store 10.0, pop */
        : "=m"(r) : "m"((double){3.0}), "m"((double){7.0}));
    return r;
}

/* ==== fsubp ST(1) + fstp m64 ==== */
static double fsubp_fstp_m64(void) {
    double r;
    /* GAS fsubp → Intel fsubrp (DE E0+i): ST(1) = ST(0) - ST(1) */
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 10.0 */
        "fldl %2\n"         /* ST(0) = 3.0, ST(1) = 10.0 */
        "fsubp\n"           /* ST(0) = 3.0 - 10.0 = -7.0 */
        "fstpl %0\n"
        : "=m"(r) : "m"((double){10.0}), "m"((double){3.0}));
    return r;
}

/* ==== fmulp ST(1) + fstp m64 ==== */
static double fmulp_fstp_m64(void) {
    double r;
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 4.0 */
        "fldl %2\n"         /* ST(0) = 5.0, ST(1) = 4.0 */
        "fmulp\n"           /* ST(0) = 4.0 * 5.0 = 20.0 */
        "fstpl %0\n"
        : "=m"(r) : "m"((double){4.0}), "m"((double){5.0}));
    return r;
}

/* ==== fdivp ST(1) + fstp m64 ==== */
static double fdivp_fstp_m64(void) {
    double r;
    /* GAS fdivp → Intel fdivrp (DE F0+i): ST(1) = ST(0) / ST(1) */
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 20.0 */
        "fldl %2\n"         /* ST(0) = 4.0, ST(1) = 20.0 */
        "fdivp\n"           /* ST(0) = 4.0 / 20.0 = 0.2 */
        "fstpl %0\n"
        : "=m"(r) : "m"((double){20.0}), "m"((double){4.0}));
    return r;
}

/* ==== faddp ST(1) + fstp m32 (f32 store) ==== */
static float faddp_fstp_m32(void) {
    float r;
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 1.5 */
        "fldl %2\n"         /* ST(0) = 2.5, ST(1) = 1.5 */
        "faddp\n"           /* ST(0) = 4.0 */
        "fstps %0\n"        /* store as f32, pop */
        : "=m"(r) : "m"((double){1.5}), "m"((double){2.5}));
    return r;
}

/* ==== fmulp ST(1) + fstp m32 ==== */
static float fmulp_fstp_m32(void) {
    float r;
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 3.0 */
        "fldl %2\n"         /* ST(0) = 2.0, ST(1) = 3.0 */
        "fmulp\n"           /* ST(0) = 6.0 */
        "fstps %0\n"
        : "=m"(r) : "m"((double){3.0}), "m"((double){2.0}));
    return r;
}

/* ==== Stack depth preserved: arithp+fstp with deeper values surviving ==== */
static void arithp_fstp_depth(double *out_result, double *out_remaining) {
    __asm__ volatile(
        "fldl %2\n"         /* push 100.0: ST(0)=100 */
        "fldl %3\n"         /* push 10.0:  ST(0)=10, ST(1)=100 */
        "fldl %4\n"         /* push 3.0:   ST(0)=3, ST(1)=10, ST(2)=100 */
        "faddp\n"           /* ST(0)=10+3=13, ST(1)=100 */
        "fstpl %0\n"        /* store 13.0, pop → ST(0)=100 */
        "fstpl %1\n"        /* store 100.0 */
        : "=m"(*out_result), "=m"(*out_remaining)
        : "m"((double){100.0}), "m"((double){10.0}), "m"((double){3.0}));
}

/* ==== Consecutive arithp+fstp pairs ==== */
static void consecutive_pairs(double *out0, double *out1) {
    __asm__ volatile(
        "fldl %2\n"         /* push 2.0 */
        "fldl %3\n"         /* push 3.0: ST(0)=3, ST(1)=2 */
        "fmulp\n"           /* ST(0)=6 */
        "fstpl %0\n"        /* store 6, pop (empty) */
        "fldl %4\n"         /* push 10.0 */
        "fldl %5\n"         /* push 5.0: ST(0)=5, ST(1)=10 */
        "faddp\n"           /* ST(0)=15 */
        "fstpl %1\n"        /* store 15, pop (empty) */
        : "=m"(*out0), "=m"(*out1)
        : "m"((double){2.0}), "m"((double){3.0}),
          "m"((double){10.0}), "m"((double){5.0}));
}

/* ==== fsubrp (GAS fsubrp) + fstp ==== */
static double fsubrp_fstp(void) {
    double r;
    /* GAS fsubrp → Intel fsubp (DE E8+i): ST(1) = ST(1) - ST(0) */
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 10.0 */
        "fldl %2\n"         /* ST(0) = 3.0, ST(1) = 10.0 */
        "fsubrp\n"          /* ST(0) = 10.0 - 3.0 = 7.0 */
        "fstpl %0\n"
        : "=m"(r) : "m"((double){10.0}), "m"((double){3.0}));
    return r;
}

/* ==== fdivrp (GAS fdivrp) + fstp ==== */
static double fdivrp_fstp(void) {
    double r;
    /* GAS fdivrp → Intel fdivp (DE F8+i): ST(1) = ST(1) / ST(0) */
    __asm__ volatile(
        "fldl %1\n"         /* ST(0) = 20.0 */
        "fldl %2\n"         /* ST(0) = 4.0, ST(1) = 20.0 */
        "fdivrp\n"          /* ST(0) = 20.0 / 4.0 = 5.0 */
        "fstpl %0\n"
        : "=m"(r) : "m"((double){20.0}), "m"((double){4.0}));
    return r;
}

/* ==== arithp+fstp in longer x87 run (middle of run) ==== */
static void arithp_fstp_mid_run(double *out0, double *out1) {
    __asm__ volatile(
        "fldl %2\n"         /* push 5.0 */
        "fldl %3\n"         /* push 2.0: ST(0)=2, ST(1)=5 */
        "fmulp\n"           /* ST(0) = 10 */
        "fstpl %0\n"        /* store 10, pop */
        "fldl %4\n"         /* push 7.0 */
        "fldl %5\n"         /* push 3.0: ST(0)=3, ST(1)=7 */
        "faddp\n"           /* ST(0) = 10 */
        "fstpl %1\n"        /* store 10, pop */
        : "=m"(*out0), "=m"(*out1)
        : "m"((double){5.0}), "m"((double){2.0}),
          "m"((double){7.0}), "m"((double){3.0}));
}

int main(void) {
    /* faddp + fstp m64 */
    check("faddp+fstp_m64: 3+7=10", faddp_fstp_m64(), 10.0);

    /* fsubp + fstp m64 (GAS fsubp → ST(0)-ST(1)) */
    check("fsubp+fstp_m64: 3-10=-7", fsubp_fstp_m64(), -7.0);

    /* fmulp + fstp m64 */
    check("fmulp+fstp_m64: 4*5=20", fmulp_fstp_m64(), 20.0);

    /* fdivp + fstp m64 (GAS fdivp → ST(0)/ST(1)) */
    check("fdivp+fstp_m64: 4/20=0.2", fdivp_fstp_m64(), 0.2);

    /* faddp + fstp m32 (f32) */
    check_f32("faddp+fstp_m32: 1.5+2.5=4", faddp_fstp_m32(), 4.0f);

    /* fmulp + fstp m32 (f32) */
    check_f32("fmulp+fstp_m32: 3*2=6", fmulp_fstp_m32(), 6.0f);

    /* Stack depth preserved */
    {
        double result, remaining;
        arithp_fstp_depth(&result, &remaining);
        check("depth: arith result (10+3=13)", result, 13.0);
        check("depth: remaining ST(0) (100)", remaining, 100.0);
    }

    /* Consecutive pairs */
    {
        double a, b;
        consecutive_pairs(&a, &b);
        check("consecutive: first (2*3=6)", a, 6.0);
        check("consecutive: second (10+5=15)", b, 15.0);
    }

    /* fsubrp + fstp (GAS fsubrp → ST(1)-ST(0)) */
    check("fsubrp+fstp_m64: 10-3=7", fsubrp_fstp(), 7.0);

    /* fdivrp + fstp (GAS fdivrp → ST(1)/ST(0)) */
    check("fdivrp+fstp_m64: 20/4=5", fdivrp_fstp(), 5.0);

    /* Mid-run pairs */
    {
        double a, b;
        arithp_fstp_mid_run(&a, &b);
        check("mid_run: first (5*2=10)", a, 10.0);
        check("mid_run: second (7+3=10)", b, 10.0);
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
