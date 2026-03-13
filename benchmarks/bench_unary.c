/*
 * bench_unary.c -- Benchmarks for x87 unary opcodes.
 * Covers: FXCH, FCHS, FABS, FSQRT, FRNDINT
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fxch(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fxch %%st(1)\n\t"              /* ST(0)=1, ST(1)=2 */
            "fstpl %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fchs(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fchs\n\t"
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fabs(void) {
    clock_t start = clock();
    volatile double src = -2.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fabs\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fsqrt(void) {
    clock_t start = clock();
    volatile double src = 2.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fsqrt\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_frndint(void) {
    clock_t start = clock();
    volatile double src = 2.7;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "frndint\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fxch",    bench_fxch},
        {"fchs",    bench_fchs},
        {"fabs",    bench_fabs},
        {"fsqrt",   bench_fsqrt},
        {"frndint", bench_frndint},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
