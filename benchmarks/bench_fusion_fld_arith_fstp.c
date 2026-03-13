/*
 * bench_fusion_fld_arith_fstp.c -- Benchmark for fld_arith_fstp fusion.
 * Pattern: FLD m64 + non-popping ARITH + FSTP (3-instruction sequence).
 * The fusion folds load+compute+store into a single optimized operation.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fld_fadd_fstp(void) {
    clock_t start = clock();
    volatile double src = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"      /* ST(0) = 2.0 */
            "fldl %1\n\t"                       /* ST(0) = 3.0, ST(1) = 2.0 */
            "fadd %%st(1), %%st(0)\n\t"         /* ST(0) = 3+2=5 */
            "fstp %%st(1)\n\t"                  /* store 5 -> ST(1), pop -> ST(0)=5 */
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fld_fsub_fstp(void) {
    clock_t start = clock();
    volatile double src = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=4 */
            "fldl %1\n\t"                                                           /* ST(0)=3, ST(1)=4 */
            "fsub %%st(1), %%st(0)\n\t"                                            /* ST(0)=3-4=-1 */
            "fstp %%st(1)\n\t"                                                     /* store -1->ST(1) */
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fld_fmul_fstp(void) {
    clock_t start = clock();
    volatile double src = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"      /* ST(0)=2 */
            "fldl %1\n\t"                       /* ST(0)=3, ST(1)=2 */
            "fmul %%st(1), %%st(0)\n\t"         /* ST(0)=3*2=6 */
            "fstp %%st(1)\n\t"                  /* store 6->ST(1) */
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

static clock_t bench_fld_fdiv_fstp(void) {
    clock_t start = clock();
    volatile double src = 6.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fldl %1\n\t"                                       /* ST(0)=6, ST(1)=3 */
            "fdiv %%st(1), %%st(0)\n\t"                        /* ST(0)=6/3=2 */
            "fstp %%st(1)\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fld_fadd_fstp", bench_fld_fadd_fstp},
        {"fld_fsub_fstp", bench_fld_fsub_fstp},
        {"fld_fmul_fstp", bench_fld_fmul_fstp},
        {"fld_fdiv_fstp", bench_fld_fdiv_fstp},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
