/*
 * bench_mul.c -- Benchmarks for x87 multiplication opcodes.
 * Covers: FMUL (m64, ST), FMULP, FIMUL (m32)
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fmul_m64(void) {
    clock_t start = clock();
    volatile double mem = 2.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2 */
            "fmull %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

static clock_t bench_fmul_st(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2 */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3, ST(1)=2 */
            "fmul %%st(1), %%st(0)\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fmulp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2 */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3, ST(1)=2 */
            "fmulp\n\t"
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fimul_m32(void) {
    clock_t start = clock();
    volatile int32_t mem = 5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fimull %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fmul_m64",  bench_fmul_m64},
        {"fmul_st",   bench_fmul_st},
        {"fmulp",     bench_fmulp},
        {"fimul_m32", bench_fimul_m32},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
