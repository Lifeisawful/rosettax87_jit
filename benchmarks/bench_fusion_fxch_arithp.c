/*
 * bench_fusion_fxch_arithp.c -- Benchmark for fxch_arithp fusion.
 * Pattern: FXCH ST(1) + FADDP/FSUBP/FMULP/FDIVP.
 * The fusion detects the swap-then-pop as equivalent to the reversed operation.
 *
 * NOTE: GAS AT&T: fsubp=Intel FSUBRP, fdivp=Intel FDIVRP
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fxch_faddp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fxch %%st(1)\n\t"              /* ST(0)=1, ST(1)=2 */
            "faddp\n\t"                     /* ST(1)=2+1=3, pop -> ST(0)=3 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

/* GAS fsubp = Intel FSUBRP: ST(1) = ST(0) - ST(1) */
static clock_t bench_fxch_fsubp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fxch %%st(1)\n\t"              /* ST(0)=1, ST(1)=2 */
            "fsubp\n\t"                     /* GAS=FSUBRP: ST(1)=1-2=-1, pop -> ST(0)=-1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fxch_fmulp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"                     /* ST(0)=2 */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3, ST(1)=2 */
            "fxch %%st(1)\n\t"                                 /* ST(0)=2, ST(1)=3 */
            "fmulp\n\t"                                        /* ST(1)=3*2=6, pop -> ST(0)=6 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

/* GAS fdivp = Intel FDIVRP: ST(1) = ST(0) / ST(1) */
static clock_t bench_fxch_fdivp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"                                          /* ST(0)=2 */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=4, ST(1)=2 */
            "fxch %%st(1)\n\t"                                                     /* ST(0)=2, ST(1)=4 */
            "fdivp\n\t"                                                            /* GAS=FDIVRP: ST(1)=2/4=0.5, pop */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fxch_faddp", bench_fxch_faddp},
        {"fxch_fsubp", bench_fxch_fsubp},
        {"fxch_fmulp", bench_fxch_fmulp},
        {"fxch_fdivp", bench_fxch_fdivp},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
