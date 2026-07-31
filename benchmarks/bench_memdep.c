/*
 * bench_memdep.c -- Loop-carried X87State memory-dependency probes.
 *
 * Every variant is a single asm block containing its own loop, so the
 * loop body is one translated basic block and loop-carried dependencies
 * through X87State (st[] slots, status_word, tag_word) are real at
 * execution time, not artifacts of the C loop.
 *
 * Groups (compare only within this file):
 *   A. Accumulator carry:  acc_st carries the accumulator on the x87 stack
 *      across iterations (epilogue STR st[] -> next iteration ReadSt LDR);
 *      acc_mem carries it through guest memory; noacc has no carried value;
 *      acc_sse is the register-carried floor (SSE addsd, no x87 at all).
 *   B. Split runs:  splitN breaks one balanced fld/fmul/fstp run into N
 *      1-instruction runs with integer stores; each unbalanced fragment
 *      pays TOP writeback (status_word RMW) + tag_word RMW per iteration.
 *      wholeN is the identical FP work as one balanced run (no state traffic).
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

/* ── Group A: accumulator carry ──────────────────────────────────────────── */

/* Accumulator lives in ST(0) across iterations.
 * Loop body block: faddl m ; decl ; jnz  — one x87 run of 1.
 * Per iteration: ReadSt(0) LDR <- previous iteration's epilogue STR st[0]. */
static clock_t bench_acc_st(void) {
    volatile double mem = 1.25;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "fldz\n\t"
        "movl %2, %%ecx\n"
        "1:\n\t"
        "faddl %1\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n\t"
        "fstpl %0\n"
        : "=m"(r) : "m"(mem), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Same arithmetic; accumulator carried through guest memory instead.
 * Loop-carried chain is STR r -> LDR r (guest address, same width). */
static clock_t bench_acc_mem(void) {
    volatile double mem = 1.25;
    volatile double r = 0.0;
    clock_t start = clock();
    __asm__ volatile (
        "movl %2, %%ecx\n"
        "1:\n\t"
        "fldl %0\n\t"
        "faddl %1\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "+m"(r) : "m"(mem), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* No carried value at all: fresh load, add, store to a dead location.
 * More instructions than acc_st but zero loop-carried memory chain. */
static clock_t bench_noacc(void) {
    volatile double a = 3.0, mem = 1.25;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "faddl %2\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "m"(mem), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Register-carried floor: same accumulation in SSE (no x87 anywhere). */
static clock_t bench_acc_sse(void) {
    volatile double mem = 1.25;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "xorpd %%xmm0, %%xmm0\n\t"
        "movl %2, %%ecx\n"
        "1:\n\t"
        "addsd %1, %%xmm0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n\t"
        "movsd %%xmm0, %0\n"
        : "=m"(r) : "m"(mem), "i"(TIMES) : "ecx", "cc", "xmm0");
    return clock() - start;
}

/* ── Group B: split runs ─────────────────────────────────────────────────── */

/* One balanced run: fld/fmul/fstp — no x87-state traffic at all. */
static clock_t bench_whole3(void) {
    volatile double a = 1.0009, b = 1.0004;
    volatile double r;
    clock_t start = clock();
    volatile int d = 0;
    (void)d;
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "fmull %2\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "m"(b), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Same FP work split into three 1-instruction runs by integer stores.
 * Run1 (fld):  net push — st[] STR + status_word TOP RMW + tag_word RMW.
 * Run2 (fmul): balanced — ReadSt LDR + epilogue STR st[0].
 * Run3 (fstp): net pop  — ReadSt LDR + status_word TOP RMW + tag_word RMW. */
static clock_t bench_split3(void) {
    volatile double a = 1.0009, b = 1.0004;
    volatile double r;
    volatile int d = 0;
    clock_t start = clock();
    __asm__ volatile (
        "movl %4, %%ecx\n"
        "1:\n\t"
        "fldl %2\n\t"
        "movl $0, %1\n\t"
        "fmull %3\n\t"
        "movl $0, %1\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r), "+m"(d) : "m"(a), "m"(b), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Minimal unbalanced pair: fld | fstp with one break. */
static clock_t bench_split2(void) {
    volatile double a = 2.5;
    volatile double r;
    volatile int d = 0;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %2\n\t"
        "movl $0, %1\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r), "+m"(d) : "m"(a), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Balanced counterpart of split2. */
static clock_t bench_whole2(void) {
    volatile double a = 2.5;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %2, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}


/* ── Group C: loop-invariant value parked on the x87 stack ───────────────── */

/* A loop-invariant multiplier lives in ST(1) for the whole loop; the body
 * READS it every iteration but never writes it.  Unlike acc_st there is no
 * store->load round trip, so the loop is throughput-bound, not latency-bound:
 * this is the shape where hoisting the reload (and the address preamble that
 * feeds it) out of the loop could actually pay.  Body: fld m ; fmul st(1),st ;
 * fstp r ; dec ; jnz  — net TOP delta 0, ST(1) live-in and never written. */
static clock_t bench_ro_st(void) {
    volatile double k = 1.0009, mem = 1.0004;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "fldl %1\n\t"
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %2\n\t"
        "fmul %%st(1), %%st\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n\t"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(k), "m"(mem), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Control: identical arithmetic with the invariant in guest memory instead of
 * on the x87 stack — one balanced run, zero X87State traffic (== whole3). */
static clock_t bench_ro_mem(void) {
    volatile double k = 1.0009, mem = 1.0004;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %2\n\t"
        "fmull %1\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(k), "m"(mem), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}


/* ── Group D: run split by a flag-LIVE loop counter ──────────────────────── */

/* The shape found in WoW's CMapChunk::CreateRenderLists inner loop: the loop
 * counter's `dec` sits BETWEEN x87 instructions and its ZF is live (the loop
 * branch consumes it).  build_guest_unary declines any inc/dec whose ZF/SF/OF
 * is live, so IR consumption stops there: the first half pays a full epilogue
 * (st[] writeback + status_word RMW + tag_word RMW) and the second half pays a
 * fresh prologue — twice per iteration, inside the loop. */
static clock_t bench_dec_mid(void) {
    volatile double a = 1.0009, b = 1.0004;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "fmull %2\n\t"
        "decl %%ecx\n\t"
        "fstpl %0\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "m"(b), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Identical work and identical instruction count, but the counter sits AFTER
 * the x87 group, so nothing splits the run. The delta between the two is the
 * cost of the split. */
static clock_t bench_dec_end(void) {
    volatile double a = 1.0009, b = 1.0004;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "fmull %2\n\t"
        "fstpl %0\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "m"(b), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Same split position, but the counter's flags are DEAD at the dec (the loop
 * tests a separate compare), so build_guest_unary already inlines it today —
 * the control showing that position alone costs nothing. */
static clock_t bench_dec_mid_dead(void) {
    volatile double a = 1.0009, b = 1.0004;
    volatile double r;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %1\n\t"
        "fmull %2\n\t"
        "decl %%ecx\n\t"
        "fstpl %0\n\t"
        "testl %%ecx, %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r) : "m"(a), "m"(b), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* ── Group E: STP-sourced store->load forwarding (OPT-SS) ────────────────── */

/* Two adjacent f64 stores at the loop tail, both reloaded at the loop head:
 * without OPT-SS the stores pair into one STP and every head load forwards
 * from a pair store (11 cyc on Firestorm); with OPT-SS they stay singles
 * (5 cyc).  The loop-carried chain is load -> faddp -> fmul -> store, so the
 * forwarding latency is the loop bound.  A/B via
 * ROSETTA_X87_DISABLE_STP_SUPPRESS=1 on the same build. */
static clock_t bench_stp_reload(void) {
    volatile double t[2] = {1.0, 1.5};
    volatile double half = 0.5;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %0\n\t"
        "fldl %1\n\t"
        "faddp\n\t"
        "fmull %2\n\t"
        "fld %%st(0)\n\t"
        "fstpl %0\n\t"
        "fstpl %1\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "+m"(t[0]), "+m"(t[1]) : "m"(half), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Control: same two adjacent stores, but nothing ever reloads them — no veto
 * fires, the STP stays in both configs, and the metric should not move. */
static clock_t bench_stp_stream(void) {
    volatile double t[2];
    volatile double k = 1.25;
    clock_t start = clock();
    __asm__ volatile (
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl %2\n\t"
        "fld %%st(0)\n\t"
        "fstpl %0\n\t"
        "fstpl %1\n\t"
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(t[0]), "=m"(t[1]) : "m"(k), "i"(TIMES) : "ecx", "cc");
    return clock() - start;
}

/* Leading movsd store ahead of the x87 run (R3-2): the loop body block
 * starts at the movsd, so window formation must begin THERE for the fld to
 * forward from the register (SseGetXmm) instead of the store buffer. */
static clock_t bench_sse_lead(void) {
    volatile double spill = 0.0;
    volatile double r;
    double seed = 0.25;
    clock_t start = clock();
    __asm__ volatile (
        "movsd %2, %%xmm0\n\t"
        "movl %3, %%ecx\n"
        "1:\n\t"
        "movsd %%xmm0, %1\n\t"   /* leading store from a live xmm */
        "fldl %1\n\t"            /* store-forward target */
        "fadd %%st(0), %%st(0)\n\t"
        "fstpl %0\n\t"
        "movsd %0, %%xmm0\n\t"   /* value flows back through xmm0 —
                                    loop-carried through the seam */
        "decl %%ecx\n\t"
        "jnz 1b\n"
        : "=m"(r), "+m"(spill) : "m"(seed), "i"(TIMES) : "ecx", "cc", "xmm0");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"acc_st",   bench_acc_st},
        {"acc_mem",  bench_acc_mem},
        {"noacc",    bench_noacc},
        {"acc_sse",  bench_acc_sse},
        {"whole3",   bench_whole3},
        {"split3",   bench_split3},
        {"split2",   bench_split2},
        {"whole2",   bench_whole2},
        {"ro_st",    bench_ro_st},
        {"ro_mem",   bench_ro_mem},
        {"dec_mid",  bench_dec_mid},
        {"dec_end",  bench_dec_end},
        {"dec_mid_dead", bench_dec_mid_dead},
        {"stp_reload",   bench_stp_reload},
        {"stp_stream",   bench_stp_stream},
        {"sse_lead",     bench_sse_lead},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        /* Min, not mean: first ~3 runs per process land ~1.55x high. */
        clock_t best = 0;
        for (int r = 0; r < RUNS; r++) {
            clock_t t = benches[i].fn();
            if (r == 0 || t < best) best = t;
        }
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)best);
    }
    return 0;
}
