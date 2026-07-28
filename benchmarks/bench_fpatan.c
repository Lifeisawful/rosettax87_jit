/*
 * bench_fpatan.c — FPATAN benchmark (OPT-TI value call).
 *
 * Cases:
 *   harness        Reference: fld/fld/fstp/fstp loop scaffolding only.
 *   fpatan_indep   Independent atan2(4, 3) — the general quadrant path
 *                  (fdiv + reduction id=1 + polynomial).
 *   fpatan_x1      x == 1.0: the direct atan(y) fast path (no fdiv).
 *   fpatan_small   Small ratio |y/x| < 2^-27: division + tiny early-out.
 *   fpatan_gap     Exponent gap > 60: no division, z = pi/2 shortcut.
 *   fpatan_dep     Result feeds y of the next iteration (stays in (0, pi));
 *                  latency of the value call.
 *   in_run         fpatan sandwiched between live-value arithmetic.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 300000
#define RUNS  5

static clock_t bench_harness(void) {
    clock_t start = clock();
    volatile double x = 3.0, y = 4.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fpatan_indep(void) {
    clock_t start = clock();
    volatile double x = 3.0, y = 4.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fpatan\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fpatan_x1(void) {
    clock_t start = clock();
    volatile double x = 1.0, y = 0.7;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fpatan\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fpatan_small(void) {
    clock_t start = clock();
    volatile double x = 8.0, y = 1e-9;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fpatan\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fpatan_gap(void) {
    clock_t start = clock();
    volatile double x = 1e-300, y = 1e300;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fldl %1\n\t"
            "fpatan\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y));
    return clock() - start;
}

static clock_t bench_fpatan_dep(void) {
    clock_t start = clock();
    double acc = 0.9;
    volatile double x = 3.0;
    for (int i = 0; i < TIMES; i++) {
        double t;
        /* atan2(y, 3) for y in (0, pi) stays in (0, pi/2) — never escapes */
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fpatan\n\t"
            "fstpl %0\n"
            : "=m"(t) : "m"(acc), "m"(x));
        acc = t + 0.5;
    }
    __asm__ volatile("" : : "m"(acc));
    return clock() - start;
}

static clock_t bench_in_run(void) {
    clock_t start = clock();
    volatile double x = 3.0, y = 4.0, c = 2.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %3\n\t"   /* c                     */
            "fldl %2\n\t"   /* y     c               */
            "fldl %1\n\t"   /* x     y      c        */
            "fpatan\n\t"    /* z     c               */
            "fmulp\n\t"     /* z*c                   */
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(y), "m"(c));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"harness",       bench_harness},
        {"fpatan_indep",  bench_fpatan_indep},
        {"fpatan_x1",     bench_fpatan_x1},
        {"fpatan_small",  bench_fpatan_small},
        {"fpatan_gap",    bench_fpatan_gap},
        {"fpatan_dep",    bench_fpatan_dep},
        {"in_run",        bench_in_run},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
