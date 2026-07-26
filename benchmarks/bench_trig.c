/*
 * bench_trig.c — FSIN / FSINCOS / FPTAN benchmark, partitioned by fast-path
 * eligibility.  Companion to bench_fcos.c (see there for the rationale); the
 * cases isolate the same regimes per op:
 *
 *   harness         fld/fstp only — loop scaffolding cost, subtract to read
 *                   the trig numbers net of the harness.
 *   <op>_small      argument < pi/4 — pure kernel, no reduction.
 *   <op>_quadrants  four arguments cycling quadrants — reduction + an
 *                   unpredictable n mod 4 selector.  For fptan this also
 *                   alternates the tan / -1/tan kernel shapes.
 *   <op>_medium     1e3..1e6 — multi-term Cody-Waite reduction.
 *   <op>_huge       ~1e15 — must bail to the classic stub; watch for
 *                   regressions only.
 *   <op>_in_run     sandwiched in an x87 run (pinned cache live).
 *   ptan_bigk       0.7: exercises k_tan's |x| >= 0.6744 pi/4-substitution
 *                   branch, which small (0.5) never reaches.
 *
 * FSINCOS and FPTAN push a result, so their sequences pop two values; the
 * extra fstp is part of the measured sequence in ALL configurations, so
 * comparisons across runtimes stay apples-to-apples.
 *
 * Build: clang -arch x86_64 -O0 -g -o bench_trig bench_trig.c
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

/* ---- FSIN ---- */

static clock_t bench_sin_small(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_sin_quadrants(void) {
    clock_t start = clock();
    static volatile double q[4] = {0.4, 1.9, 3.4, 5.0};
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(r) : "m"(q[i & 3]));
    return clock() - start;
}

static clock_t bench_sin_medium(void) {
    clock_t start = clock();
    static volatile double m[4] = {1000.5, 12345.6789, 250000.25, 1e6};
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(r) : "m"(m[i & 3]));
    return clock() - start;
}

static clock_t bench_sin_huge(void) {
    clock_t start = clock();
    volatile double src = 1.234e15;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile("fldl %1\n\t fsin\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_sin_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5, b = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fsin\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(b), "m"(a));
    return clock() - start;
}

/* ---- FSINCOS ---- */

static clock_t bench_sincos_small(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double s, c;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fsincos\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(s), "=m"(c) : "m"(src));
    return clock() - start;
}

static clock_t bench_sincos_quadrants(void) {
    clock_t start = clock();
    static volatile double q[4] = {0.4, 1.9, 3.4, 5.0};
    volatile double s, c;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fsincos\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(s), "=m"(c) : "m"(q[i & 3]));
    return clock() - start;
}

static clock_t bench_sincos_huge(void) {
    clock_t start = clock();
    volatile double src = 1.234e15;
    volatile double s, c;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fsincos\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(s), "=m"(c) : "m"(src));
    return clock() - start;
}

static clock_t bench_sincos_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fsincos\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a));
    return clock() - start;
}

/* ---- FPTAN ---- */

static clock_t bench_ptan_small(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double t, o;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fptan\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(src));
    return clock() - start;
}

static clock_t bench_ptan_bigk(void) {
    clock_t start = clock();
    volatile double src = 0.7; /* >= 0.6744: pi/4-substitution kernel branch */
    volatile double t, o;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fptan\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(src));
    return clock() - start;
}

static clock_t bench_ptan_quadrants(void) {
    clock_t start = clock();
    static volatile double q[4] = {0.4, 1.9, 3.4, 5.0}; /* alternates tan / -1/tan */
    volatile double t, o;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fptan\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(q[i & 3]));
    return clock() - start;
}

static clock_t bench_ptan_huge(void) {
    clock_t start = clock();
    volatile double src = 1.234e15;
    volatile double t, o;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %2\n\t"
            "fptan\n\t"
            "fstpl %1\n\t"
            "fstpl %0\n"
            : "=m"(t), "=m"(o) : "m"(src));
    return clock() - start;
}

static clock_t bench_ptan_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fptan\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"harness",           bench_harness},
        {"sin_small",         bench_sin_small},
        {"sin_quadrants",     bench_sin_quadrants},
        {"sin_medium",        bench_sin_medium},
        {"sin_huge",          bench_sin_huge},
        {"sin_in_run",        bench_sin_in_run},
        {"sincos_small",      bench_sincos_small},
        {"sincos_quadrants",  bench_sincos_quadrants},
        {"sincos_huge",       bench_sincos_huge},
        {"sincos_in_run",     bench_sincos_in_run},
        {"ptan_small",        bench_ptan_small},
        {"ptan_bigk",         bench_ptan_bigk},
        {"ptan_quadrants",    bench_ptan_quadrants},
        {"ptan_huge",         bench_ptan_huge},
        {"ptan_in_run",       bench_ptan_in_run},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
