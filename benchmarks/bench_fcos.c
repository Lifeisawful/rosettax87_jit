/*
 * bench_fcos.c — FCOS-only benchmark, partitioned by fast-path eligibility.
 *
 * Aimed at a fast/slow-path split inside _stub_fcos
 * (rosetta_runtime/src/runtime_entry.S).  A single "fcos" number is useless for
 * that work: it blends the cases a fast path accelerates with the cases it must
 * bail out on, so a fast path that is 4x on small arguments and 1.2x slower on
 * the bail-out looks like a wash.  Each case below isolates one regime.
 *
 * Cases, and what each one tells you:
 *
 *   harness          Reference, NOT an fcos case.  Just fld/fstp, which the x87
 *                    JIT inlines (both are in ALL_OPCODES), so this is the cost
 *                    of the loop scaffolding alone.  Subtract it to read the
 *                    fcos numbers net of the harness.
 *
 *   stub_floor       Reference, NOT an fcos case.  fdecstp+fincstp: two runtime
 *                    routines that are NOT JIT-inlined (neither appears in
 *                    ALL_OPCODES, unlike fchs/fabs/fsqrt, which is why those
 *                    make a useless reference) and that do nothing but shift
 *                    TOP — x87_fdecstp has no SIMDGuard and no arithmetic.  So
 *                    this measures the bare cost of STUB_PROLOGUE + tail +
 *                    vtable call + runtime_exitinst, i.e. the floor any stub
 *                    fast path is bounded by while still entering the stub.
 *                    NOTE: two dispatches per iteration, so the per-dispatch
 *                    floor is half this number.  The pair keeps TOP balanced.
 *
 *   small_indep      cos(0.5) with no data dependency between iterations —
 *                    throughput of the case a fast path should win outright.
 *   small_dep        Each result feeds the next fcos — latency of the same
 *                    case.  A fast path shortens this far more than the
 *                    independent variant.
 *   quadrants        Cycles four arguments landing in different quadrants, so
 *                    the n-mod-4 selector is not predictable and any per-value
 *                    caching is defeated.
 *   medium           1e3..1e6: still reducible with a couple of pi/2 terms, but
 *                    a single-term Cody-Waite fast path goes wrong here.  Watch
 *                    correctness (test_fcos) and speed together.
 *   huge             ~1e15: needs full reduction.  Expect this to stay on the
 *                    slow path; it must not regress.
 *   out_of_range     |x| >= 2^63.  Pure bail-out cost: how expensive is it to
 *                    detect ineligibility and fall through to the slow path.
 *   mixed_90_10      90% small, 10% out-of-range, interleaved.  The realistic
 *                    number: exposes the branch-misprediction cost of the
 *                    fast/slow split, which the pure cases hide entirely.
 *   in_run           fld/fcos/fmulp — FCOS sandwiched in an x87 run so the
 *                    pinned cache is live across it, as in real guest code.
 *
 * TIMES is lower than the arithmetic benchmarks because FCOS is ~1-2 orders of
 * magnitude more expensive per op; keep it fixed when comparing configurations.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 300000
#define RUNS  5

/* Reference: loop scaffolding only.  fld/fstp are JIT-inlined. */
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

/* Reference: bare runtime-routine dispatch cost.  Two dispatches per iteration;
 * fdecstp/fincstp only move TOP, and the pair leaves it where it started. */
static clock_t bench_stub_floor(void) {
    clock_t start = clock();
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fdecstp\n\t"
            "fincstp\n");
    return clock() - start;
}

/* Throughput: independent fcos on a small in-range argument. */
static clock_t bench_small_indep(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

/* Latency: result of each fcos is the input to the next. */
static clock_t bench_small_dep(void) {
    clock_t start = clock();
    double acc = 0.7;
    for (int i = 0; i < TIMES; i++) {
        double t;
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(t) : "m"(acc));
        acc = t;
    }
    /* Keep acc alive so the loop cannot be elided. */
    __asm__ volatile("" : : "m"(acc));
    return clock() - start;
}

/* Four different quadrants, cycled — unpredictable n mod 4. */
static clock_t bench_quadrants(void) {
    clock_t start = clock();
    static volatile double q[4] = {0.4, 1.9, 3.4, 5.0};
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(q[i & 3]));
    return clock() - start;
}

/* Medium magnitude: multi-term reduction required. */
static clock_t bench_medium(void) {
    clock_t start = clock();
    static volatile double m[4] = {1000.5, 12345.6789, 250000.25, 1e6};
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(m[i & 3]));
    return clock() - start;
}

/* Huge but still in range: full reduction, expected to stay on the slow path. */
static clock_t bench_huge(void) {
    clock_t start = clock();
    volatile double src = 1.234e15;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

/* |x| >= 2^63: pure fast-path bail-out cost. */
static clock_t bench_out_of_range(void) {
    clock_t start = clock();
    volatile double src = 1e19;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

/* 90% fast-path-eligible, 10% not — branch-misprediction exposure. */
static clock_t bench_mixed_90_10(void) {
    clock_t start = clock();
    static volatile double mix[10] = {0.5, 1.25, 2.0, 0.75, 3.1, 0.25, 1.6, 2.9, 0.9, 1e19};
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mix[i % 10]));
    return clock() - start;
}

/* FCOS inside an x87 run: the pinned cache is live across the stub. */
static clock_t bench_in_run(void) {
    clock_t start = clock();
    volatile double a = 0.5, b = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"  /* ST0=b        */
            "fldl %2\n\t"  /* ST0=a ST1=b  */
            "fcos\n\t"
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(b), "m"(a));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"harness",         bench_harness},
        {"stub_floor",      bench_stub_floor},
        {"small_indep",     bench_small_indep},
        {"small_dep",       bench_small_dep},
        {"quadrants",       bench_quadrants},
        {"medium",          bench_medium},
        {"huge",            bench_huge},
        {"out_of_range",    bench_out_of_range},
        {"mixed_90_10",     bench_mixed_90_10},
        {"in_run",          bench_in_run},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
