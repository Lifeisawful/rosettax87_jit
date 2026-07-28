/*
 * bench_pow.c — F2XM1 / FSCALE benchmark (OPT-TI pow-trio value calls).
 *
 * Cases:
 *   harness       Reference: fld/fstp loop scaffolding only.
 *   f2xm1_indep   Independent f2xm1 on 0.5 — throughput of the exp2 kernel.
 *   f2xm1_dep     Result feeds the next iteration (kept in (-1,1) by scaling)
 *                 — latency of the value call.
 *   f2xm1_oor     |x| > 1: the stub's early-out path.
 *   fscale_indep  Independent fscale(1.5, 3.0) — the pure-bit-twiddle path.
 *   fscale_sub    Subnormal source: the two54-normalize branch.
 *   fyl2x_indep   Independent fyl2x(3.7, 2.5) — the log2 kernel.
 *   fyl2x_dep     y' = y*log2(2) feeds the next iteration — value-call latency.
 *   fyl2xp1_indep Moderate-x fyl2xp1 (full kernel via 1+x).
 *   fyl2xp1_tiny  |x| < 2^-20: the cubic-series early-out.
 *   pow_idiom     The inlined-pow shape the game census found: frndint/fsub/
 *                 f2xm1/fld1/faddp/fscale computing 2^y — both value calls
 *                 plus surrounding run traffic in one block.
 *   powhlp_idiom  The full CRT __powhlp shape: fyl2x feeding the pow tail —
 *                 all three pow-trio value calls in one block.
 *   in_run        f2xm1 sandwiched between live-value arithmetic.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 300000
#define RUNS  5

static clock_t bench_harness(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_f2xm1_indep(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "f2xm1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_f2xm1_dep(void) {
    clock_t start = clock();
    double acc = 0.7;
    for (int i = 0; i < TIMES; i++) {
        double t;
        /* 2^x-1 for x in (0,1) stays in (0,1) — the chain never escapes */
        __asm__ volatile(
            "fldl %1\n\t"
            "f2xm1\n\t"
            "fstpl %0\n"
            : "=m"(t) : "m"(acc));
        acc = t;
    }
    __asm__ volatile("" : : "m"(acc));
    return clock() - start;
}

static clock_t bench_f2xm1_oor(void) {
    clock_t start = clock();
    volatile double src = 3.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "f2xm1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fscale_indep(void) {
    clock_t start = clock();
    volatile double src = 1.5, n = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fscale\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(src), "m"(n));
    return clock() - start;
}

static clock_t bench_fscale_sub(void) {
    clock_t start = clock();
    volatile double src = 0x1p-1074, n = 100.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fscale\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(src), "m"(n));
    return clock() - start;
}

static clock_t bench_pow_idiom(void) {
    clock_t start = clock();
    volatile double y = 3.3;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fld %%st(0)\n\t"
            "frndint\n\t"
            "fxch\n\t"
            "fsub %%st(1), %%st(0)\n\t"
            "f2xm1\n\t"
            "fld1\n\t"
            "faddp\n\t"
            "fscale\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(y));
    return clock() - start;
}

static clock_t bench_fyl2x_indep(void) {
    clock_t start = clock();
    volatile double x = 3.7, y = 2.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fyl2x\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fyl2x_dep(void) {
    clock_t start = clock();
    double acc = 2.5;
    volatile double x = 2.0;  /* log2(2) == 1: y' = y*1 stays put */
    for (int i = 0; i < TIMES; i++) {
        double t;
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fyl2x\n\t"
            "fstpl %0\n"
            : "=m"(t) : "m"(acc), "m"(x));
        acc = t;
    }
    __asm__ volatile("" : : "m"(acc));
    return clock() - start;
}

static clock_t bench_fyl2xp1_indep(void) {
    clock_t start = clock();
    volatile double x = 0.4, y = 2.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fyl2xp1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fyl2xp1_tiny(void) {
    clock_t start = clock();
    volatile double x = 0x1p-30, y = 2.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fyl2xp1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

/* The full CRT pow shape (__powhlp): x^y = 2^(y*log2 x) — fyl2x feeding
 * the frndint/f2xm1/fscale tail, all three pow-trio value calls. */
static clock_t bench_powhlp_idiom(void) {
    clock_t start = clock();
    volatile double b = 3.7, e = 2.6;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fyl2x\n\t"
            "fld %%st(0)\n\t"
            "frndint\n\t"
            "fxch\n\t"
            "fsub %%st(1), %%st(0)\n\t"
            "f2xm1\n\t"
            "fld1\n\t"
            "faddp\n\t"
            "fscale\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(b), "m"(e));
    return clock() - start;
}

static clock_t bench_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5, b = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"  /* b            */
            "fldl %2\n\t"  /* a    b       */
            "f2xm1\n\t"    /* 2^a-1 b      */
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(b), "m"(a));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"harness",      bench_harness},
        {"f2xm1_indep",  bench_f2xm1_indep},
        {"f2xm1_dep",    bench_f2xm1_dep},
        {"f2xm1_oor",    bench_f2xm1_oor},
        {"fscale_indep", bench_fscale_indep},
        {"fscale_sub",   bench_fscale_sub},
        {"fyl2x_indep",  bench_fyl2x_indep},
        {"fyl2x_dep",    bench_fyl2x_dep},
        {"fyl2xp1_indep", bench_fyl2xp1_indep},
        {"fyl2xp1_tiny", bench_fyl2xp1_tiny},
        {"pow_idiom",    bench_pow_idiom},
        {"powhlp_idiom", bench_powhlp_idiom},
        {"in_run",       bench_in_run},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
