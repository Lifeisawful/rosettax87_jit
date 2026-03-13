/*
 * bench_store.c -- Benchmarks for x87 store opcodes.
 * Covers: FSTP (m64), FST (m64), FST ST(i), FISTP (m32), FIST (m32)
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fstp_m64(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("fld1\n\t fstpl %0\n" : "=m"(r));
    return clock() - start;
}

static clock_t bench_fstp_m32(void) {
    clock_t start = clock();
    volatile float r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile ("fld1\n\t fstps %0\n" : "=m"(r));
    return clock() - start;
}

/* FST m64 — non-popping store, needs manual cleanup */
static clock_t bench_fst_m64(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fstl %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(r));
    return clock() - start;
}

/* FST ST(i) — non-popping register-to-register store */
static clock_t bench_fst_stack(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldz\n\t"                                          /* ST(0)=0 */
            "fld1\n\t fld1\n\t faddp\n\t"                      /* ST(0)=2, ST(1)=0 */
            "fst %%st(1)\n\t"                                   /* ST(1)=2 */
            "faddp\n\t"                                         /* 2+2=4 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fistp_m32(void) {
    clock_t start = clock();
    volatile int32_t r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fistpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fist_m32(void) {
    clock_t start = clock();
    volatile int32_t r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fistl %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(r));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fstp_m64",  bench_fstp_m64},
        {"fstp_m32",  bench_fstp_m32},
        {"fst_m64",   bench_fst_m64},
        {"fst_stack", bench_fst_stack},
        {"fistp_m32", bench_fistp_m32},
        {"fist_m32",  bench_fist_m32},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
