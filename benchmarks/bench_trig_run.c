/*
 * bench_trig_run.c — FCOS embedded in real x87 arithmetic runs.
 *
 * Written for research/optimizations/16-ir-trig-value-call.md.  The plain
 * bench_fcos loops measure the op with trivial surroundings, which hides the
 * cost this brief targets: a trig op SPLITS the IR run, so the arithmetic
 * around it loses FPR residency, the address cache resets, and every value
 * crosses X87State memory.  These cases put fcos inside runs of increasing
 * arithmetic weight so the split cost (and its removal) is visible.
 *
 *   arith_only      Reference: the surrounding arithmetic with NO fcos —
 *                   what a single unsplit IR run costs.  Subtract to read
 *                   the marginal cost of the embedded fcos.
 *   cos_light       fld a; fcos; fmul b; fstp — minimal surroundings.
 *   cos_poly        A 2nd-degree polynomial evaluated around cos(x):
 *                   r = (cos(x)*c1 + c0) * x + c2 — two IR fragments today.
 *   cos_wave        Two fcos in one expression: cos(a)*w1 + cos(b)*w2 —
 *                   THREE fragments today, the worst case per op.
 *   cos_deep        fcos buried mid-run with 6 arith ops on each side —
 *                   maximal residency loss per split today.
 *
 * All sequences are stack-balanced.  TIMES matches bench_fcos/bench_trig so
 * numbers are comparable across files.
 *
 * Build: clang -arch x86_64 -O0 -g -o bench_trig_run bench_trig_run.c
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 300000
#define RUNS  5

/* The cos_deep arithmetic with the fcos replaced by fsqrt (an inlined op that
 * does NOT split the run) — the unsplit-run reference. */
static clock_t bench_arith_only(void) {
    clock_t start = clock();
    volatile double a = 0.75, b = 1.25, c = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fmul %%st(1), %%st(0)\n\t"
            "fldl %3\n\t"
            "faddp\n\t"
            "fsqrt\n\t"
            "fmul %%st(1), %%st(0)\n\t"
            "faddp\n\t"
            "fldl %2\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

/* Minimal: load, cos, one consumer. */
static clock_t bench_cos_light(void) {
    clock_t start = clock();
    volatile double a = 0.5, b = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fcos\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(b), "m"(a));
    return clock() - start;
}

/* Polynomial around the cos: r = (cos(x)*c1 + c0) * x + c2.
 * Today: [fld c1] [fld x; fcos] split [fmulp; fld c0; faddp; fld x; fmulp;
 * fld c2; faddp] — the arithmetic tail is one fragment, the head another. */
static clock_t bench_cos_poly(void) {
    clock_t start = clock();
    volatile double x = 0.8, c0 = 1.5, c1 = -0.25, c2 = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %3\n\t"  /* c1                          */
            "fldl %1\n\t"  /* x    c1                     */
            "fcos\n\t"     /* cosx c1                     */
            "fmulp\n\t"    /* cosx*c1                     */
            "fldl %2\n\t"  /* c0   cosx*c1                */
            "faddp\n\t"    /* cosx*c1+c0                  */
            "fldl %1\n\t"  /* x    ...                    */
            "fmulp\n\t"    /* (...)*x                     */
            "fldl %4\n\t"  /* c2   ...                    */
            "faddp\n\t"    /* (...)*x+c2                  */
            "fstpl %0\n"
            : "=m"(r) : "m"(x), "m"(c0), "m"(c1), "m"(c2));
    return clock() - start;
}

/* Two cos in one expression: r = cos(a)*w1 + cos(b)*w2 — two splits today. */
static clock_t bench_cos_wave(void) {
    clock_t start = clock();
    volatile double a = 0.4, b = 2.1, w1 = 0.6, w2 = 0.4;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"  /* a                   */
            "fcos\n\t"     /* ca                  */
            "fldl %3\n\t"  /* w1  ca              */
            "fmulp\n\t"    /* ca*w1               */
            "fldl %2\n\t"  /* b   ...             */
            "fcos\n\t"     /* cb  ...             */
            "fldl %4\n\t"  /* w2  cb ...          */
            "fmulp\n\t"    /* cb*w2 ...           */
            "faddp\n\t"    /* ca*w1+cb*w2         */
            "fstpl %0\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(w1), "m"(w2));
    return clock() - start;
}

/* fcos buried mid-run: 6 arithmetic ops before, 3 after. */
static clock_t bench_cos_deep(void) {
    clock_t start = clock();
    volatile double a = 0.75, b = 1.25, c = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fmul %%st(1), %%st(0)\n\t"
            "fldl %3\n\t"
            "faddp\n\t"
            "fcos\n\t"
            "fmul %%st(1), %%st(0)\n\t"
            "faddp\n\t"
            "fldl %2\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"arith_only", bench_arith_only},
        {"cos_light",  bench_cos_light},
        {"cos_poly",   bench_cos_poly},
        {"cos_wave",   bench_cos_wave},
        {"cos_deep",   bench_cos_deep},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
