/*
 * bench_fstp_fld.c -- Benchmark for FSTP + FLD fusion (OPT-F11).
 *
 * The fusion saves ~6 AArch64 instructions per pair (TOP writeback,
 * tag-invalidate, tag-validate, push/pop overhead).  To make this
 * measurable we need long x87 runs with many consecutive FSTP+FLD
 * pairs so the savings accumulate within a single translated block.
 *
 * Compare with ROSETTA_X87_DISABLE_FUSIONS=fstp_fld to measure benefit.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

/* --------------------------------------------------------------------------
 * Long chain: 8x (FSTP m64 + FLD m64) in a single asm block.
 * This creates a run of 17 x87 instructions (initial FLD + 8 pairs).
 * Unfused: each pair does pop-deferred → store_top → push-deferred → ...
 * Fused:   each pair is a single net-zero operation, no TOP round-trips.
 * -------------------------------------------------------------------------- */
static clock_t bench_chain_8x(void) {
    clock_t start = clock();
    volatile double r;
    double a = 1.0, b = 2.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %1\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %1\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %1\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %1\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(a), "m"(b));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Interleaved with arithmetic: FLD+FMUL+FSTP then FSTP+FLD.
 * Simulates real-world pattern: compute → store → load next operand.
 * The FSTP+FLD at the boundary is the fusion target.
 * -------------------------------------------------------------------------- */
static clock_t bench_arith_boundary(void) {
    clock_t start = clock();
    volatile double r;
    double a = 2.0, b = 3.0, c = 4.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            /* compute a*b, store result, load c */
            "fldl %1\n\t"          /* ST(0) = a */
            "fmull %2\n\t"         /* ST(0) = a*b */
            "fstpl %0\n\t"         /* store result, pop */
            "fldl %3\n\t"          /* load c -- THIS is the fstp+fld fusion */
            /* compute c*a, store result, load b */
            "fmull %1\n\t"         /* ST(0) = c*a */
            "fstpl %0\n\t"         /* store, pop */
            "fldl %2\n\t"          /* load b -- fusion target */
            /* compute b*c, store result, load a */
            "fmull %3\n\t"         /* ST(0) = b*c */
            "fstpl %0\n\t"         /* store, pop */
            "fldl %1\n\t"          /* load a -- fusion target */
            /* one more round */
            "fmull %2\n\t"
            "fstpl %0\n\t"
            "fldl %3\n\t"          /* fusion target */
            "fmull %1\n\t"
            "fstpl %0\n\t"
            "fldl %2\n\t"          /* fusion target */
            "fmull %3\n\t"
            "fstpl %0\n\t"
            "fldl %1\n\t"          /* fusion target */
            "fmull %2\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Pure FSTP+FLDZ chain (8 pairs).  FLDZ is a constant materialization
 * so the FLD side is trivial — any savings come purely from skipping
 * the push/pop TOP bookkeeping.
 * -------------------------------------------------------------------------- */
static clock_t bench_fldz_chain(void) {
    clock_t start = clock();
    volatile double r;
    double a = 42.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstpl %0\n\t fldz\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(a));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Two-deep stack: maintain ST(0) and ST(1), repeatedly store ST(0)
 * and reload a new value.  Tests FSTP m64 + FLD m64 with a live
 * value below on the stack (common in real code).
 * -------------------------------------------------------------------------- */
static clock_t bench_two_deep(void) {
    clock_t start = clock();
    volatile double r;
    double a = 1.0, b = 2.0, c = 3.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"          /* ST(0)=a, stack depth 1 */
            "fldl %2\n\t"          /* ST(0)=b, ST(1)=a, depth 2 */
            "fstpl %0\n\t fldl %3\n\t"   /* store b, load c: ST(0)=c, ST(1)=a */
            "fstpl %0\n\t fldl %2\n\t"   /* store c, load b: ST(0)=b, ST(1)=a */
            "fstpl %0\n\t fldl %3\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %3\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstpl %0\n\t fldl %3\n\t"
            "fstpl %0\n\t fldl %2\n\t"
            "fstp %%st(0)\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * FSTP ST(1) + FLD m64 chain (register dest).
 * Maintains 2 values, repeatedly overwrites ST(1) then loads new ST(0).
 * -------------------------------------------------------------------------- */
static clock_t bench_reg_chain(void) {
    clock_t start = clock();
    volatile double r;
    double a = 1.0, b = 2.0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"              /* ST(0)=a */
            "fldl %2\n\t"              /* ST(0)=b, ST(1)=a */
            "fstp %%st(1)\n\t fldl %1\n\t"   /* ST(1)=b, pop→ST(0)=b, push a */
            "fstp %%st(1)\n\t fldl %2\n\t"
            "fstp %%st(1)\n\t fldl %1\n\t"
            "fstp %%st(1)\n\t fldl %2\n\t"
            "fstp %%st(1)\n\t fldl %1\n\t"
            "fstp %%st(1)\n\t fldl %2\n\t"
            "fstp %%st(1)\n\t fldl %1\n\t"
            "fstp %%st(1)\n\t fldl %2\n\t"
            "fstp %%st(0)\n\t"
            "fstp %%st(0)\n"
            : "=m"(r) : "m"(a), "m"(b));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Isolated pairs: each FSTP+FLD is its own 2-instruction x87 run,
 * separated by integer MOV instructions that break the X87Cache run.
 *
 * This is the scenario where the fusion helps the most:
 *   Without fusion: X87Cache activates (run=2) but pop precedes push,
 *     so OPT-D cannot cancel.  Full pop tag-invalidate + push tag-validate
 *     + base/TOP reload per pair.
 *   With fusion: pop+push cancel entirely — just load ST(0), store to
 *     memory, materialise FLD value, store to ST(0).  No tag overhead.
 *
 * This pattern is common in real code: store FP result, do integer work
 * (address calculation, loop counter, branch), load next FP operand.
 * -------------------------------------------------------------------------- */
static clock_t bench_isolated_pairs(void) {
    clock_t start = clock();
    volatile double r;
    double a = 1.0, b = 2.0;
    volatile int dummy = 0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            /* Setup: push initial value onto x87 stack */
            "fldl %3\n\t"
            /* integer break — next fstp+fld starts a fresh run of 2 */
            "movl $0, %2\n\t"
            /* pair 1: fstp+fld (run=2, fusion target) */
            "fstpl %0\n\t"
            "fldl %4\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 2 */
            "fstpl %0\n\t"
            "fldl %3\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 3 */
            "fstpl %0\n\t"
            "fldl %4\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 4 */
            "fstpl %0\n\t"
            "fldl %3\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 5 */
            "fstpl %0\n\t"
            "fldl %4\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 6 */
            "fstpl %0\n\t"
            "fldl %3\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 7 */
            "fstpl %0\n\t"
            "fldl %4\n\t"
            /* integer break */
            "movl $0, %2\n\t"
            /* pair 8 */
            "fstpl %0\n\t"
            "fldl %3\n\t"
            /* cleanup */
            "fstp %%st(0)\n"
            : "=m"(r), "+m"(dummy)
            : "m"(dummy), "m"(a), "m"(b));
    return clock() - start;
}

/* --------------------------------------------------------------------------
 * Short-run boundary: FLD+FMUL+FSTP (run=3, fused as fld_arith_fstp),
 * then integer MOV, then FSTP+FLD (run=2, fusion target).
 *
 * Simulates the real-world pattern where a compute block ends, some
 * integer work happens, and the next operand is loaded.  The integer
 * break makes the FSTP+FLD a separate short run.
 * -------------------------------------------------------------------------- */
static clock_t bench_short_run_boundary(void) {
    clock_t start = clock();
    volatile double r;
    double a = 2.0, b = 3.0, c = 4.0;
    volatile int dummy = 0;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            /* compute block 1: fld+fmul+fstp (run=3, fused as fld_arith_fstp) */
            "fldl %1\n\t"
            "fmull %2\n\t"
            /* fstp+fld pair: end of compute → load next operand (run continues) */
            "fstpl %0\n\t"
            "fldl %4\n\t"
            /* integer break — forces fresh run for next block */
            "movl $0, %3\n\t"
            /* compute block 2 */
            "fmull %1\n\t"
            "fstpl %0\n\t"
            "fldl %2\n\t"
            "movl $0, %3\n\t"
            /* compute block 3 */
            "fmull %4\n\t"
            "fstpl %0\n\t"
            "fldl %1\n\t"
            "movl $0, %3\n\t"
            /* compute block 4 */
            "fmull %2\n\t"
            "fstpl %0\n\t"
            "fldl %4\n\t"
            "movl $0, %3\n\t"
            /* final */
            "fmull %1\n\t"
            "fstp %%st(0)\n"
            : "=m"(r), "+m"(dummy)
            : "m"(dummy), "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"chain_8x",           bench_chain_8x},
        {"arith_boundary",     bench_arith_boundary},
        {"fldz_chain",         bench_fldz_chain},
        {"two_deep",           bench_two_deep},
        {"reg_chain",          bench_reg_chain},
        {"isolated_pairs",     bench_isolated_pairs},
        {"short_run_boundary", bench_short_run_boundary},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-20s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
