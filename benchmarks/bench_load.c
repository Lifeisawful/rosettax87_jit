/*
 * bench_load.c -- Benchmarks for x87 load opcodes.
 * Covers: FLD (m64, reg), FILD (m32, m64)
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fld_m64(void) {
    clock_t start = clock();
    volatile double src = 3.14159;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("fldl %1\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fld_m32(void) {
    clock_t start = clock();
    volatile float src = 2.71828f;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("flds %1\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fld_reg(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld %%st(0)\n\t"
            "fstpl %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fild_m32(void) {
    clock_t start = clock();
    volatile int32_t src = 42;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("fildl %1\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fild_m64(void) {
    clock_t start = clock();
    volatile int64_t src = 1000000LL;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("fildll %1\n\t fstpl %0\n" : "=m"(r) : "m"(src));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fld_m64",   bench_fld_m64},
        {"fld_m32",   bench_fld_m32},
        {"fld_reg",   bench_fld_reg},
        {"fild_m32",  bench_fild_m32},
        {"fild_m64",  bench_fild_m64},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
