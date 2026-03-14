/*
 * bench_round.c -- Benchmarks for FISTP, FIST, and FRNDINT rounding dispatch.
 *
 * Each bench uses FLDCW to set a specific rounding mode (RC field bits[11:10])
 * before the instruction under test, then restores the original control word.
 * This forces the RC dispatch chain to execute the correct non-default branch,
 * making the 7-instruction CBZ/SUB chain cost visible.
 *
 * With ROSETTA_X87_FAST_ROUND=1, the dispatch chain is replaced by a single
 * FCVTNS/FRINTN instruction (round-to-nearest only). The benchmark measures
 * the overhead of the dispatch chain vs. the fast path.
 *
 * x87 control word RC encoding (bits[11:10]):
 *   00 = round to nearest (ties to even)  — default
 *   01 = round toward -inf (floor)
 *   10 = round toward +inf (ceil)
 *   11 = round toward zero (truncate)
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 2000000
#define RUNS  5

/* Control word values for each rounding mode */
#define CW_NEAREST   0x037F   /* RC=00 default, double precision, all exceptions masked */
#define CW_FLOOR     0x077F   /* RC=01 toward -inf */
#define CW_CEIL      0x0B7F   /* RC=10 toward +inf */
#define CW_TRUNC     0x0F7F   /* RC=11 toward zero */

/* ── FISTP m32 (most common real-world pattern: FLDCW + FISTP for coord floor) ── */

static clock_t bench_fistp_m32_nearest(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_NEAREST;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpl %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_fistp_m32_floor(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_FLOOR;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpl %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_fistp_m32_ceil(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_CEIL;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpl %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_fistp_m32_trunc(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_TRUNC;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpl %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

/* ── FISTP m64 ── */

static clock_t bench_fistp_m64_nearest(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_NEAREST;
    volatile int64_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpll %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_fistp_m64_floor(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_FLOOR;
    volatile int64_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw %1\n\t"
            "fldl  %2\n\t"
            "fistpll %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

/* ── FRNDINT — rounds ST(0) in place (no integer store) ── */

static clock_t bench_frndint_nearest(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_NEAREST;
    volatile double r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw  %1\n\t"
            "fldl   %2\n\t"
            "frndint\n\t"
            "fstpl  %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_frndint_floor(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_FLOOR;
    volatile double r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw  %1\n\t"
            "fldl   %2\n\t"
            "frndint\n\t"
            "fstpl  %0\n"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

/* ── FIST m32 (non-popping, needs cleanup) ── */

static clock_t bench_fist_m32_nearest(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_NEAREST;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw  %1\n\t"
            "fldl   %2\n\t"
            "fistl  %0\n\t"
            "fstp   %%st(0)\n\t"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

static clock_t bench_fist_m32_floor(void) {
    clock_t start = clock();
    volatile uint16_t cw = CW_FLOOR;
    volatile int32_t r;
    volatile double src = 1.7;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldcw  %1\n\t"
            "fldl   %2\n\t"
            "fistl  %0\n\t"
            "fstp   %%st(0)\n\t"
            : "=m"(r) : "m"(cw), "m"(src));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fistp_m32_nearest", bench_fistp_m32_nearest},
        {"fistp_m32_floor",   bench_fistp_m32_floor},
        {"fistp_m32_ceil",    bench_fistp_m32_ceil},
        {"fistp_m32_trunc",   bench_fistp_m32_trunc},
        {"fistp_m64_nearest", bench_fistp_m64_nearest},
        {"fistp_m64_floor",   bench_fistp_m64_floor},
        {"frndint_nearest",   bench_frndint_nearest},
        {"frndint_floor",     bench_frndint_floor},
        {"fist_m32_nearest",  bench_fist_m32_nearest},
        {"fist_m32_floor",    bench_fist_m32_floor},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %-22s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
