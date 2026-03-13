/*
 * bench_fusion_fld_arithp.c -- Benchmark for fld_arithp fusion.
 * Pattern: FLD m64 + FADDP/FSUBP/FMULP/FDIVP (arithmetic with pop).
 * The fusion folds the push+pop into a direct accumulator operation.
 *
 * NOTE: GAS AT&T: fsubp=Intel FSUBRP, fdivp=Intel FDIVRP
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fld_faddp(void) {
    clock_t start = clock();
    volatile double mem = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"                         /* ST(0) = 1.0 accumulator */
            "fldl %1\n\t"                      /* ST(0) = 3.0, ST(1) = 1.0 */
            "faddp %%st, %%st(1)\n\t"          /* ST(1) = 1+3=4, pop -> ST(0)=4 */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

/* GAS fsubp = Intel FSUBRP: ST(1) = ST(0) - ST(1) */
static clock_t bench_fld_fsubp(void) {
    clock_t start = clock();
    volatile double mem = 1.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"      /* ST(0) = 2.0 accumulator */
            "fldl %1\n\t"                       /* ST(0) = 1.0, ST(1) = 2.0 */
            "fsubp %%st, %%st(1)\n\t"           /* GAS=FSUBRP: ST(1)=1-2=-1, pop -> ST(0)=-1 */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

static clock_t bench_fld_fmulp(void) {
    clock_t start = clock();
    volatile double mem = 4.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 accumulator */
            "fldl %1\n\t"                                        /* ST(0)=4, ST(1)=3 */
            "fmulp %%st, %%st(1)\n\t"                           /* ST(1)=3*4=12, pop -> ST(0)=12 */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

/* GAS fdivp = Intel FDIVRP: ST(1) = ST(0) / ST(1) */
static clock_t bench_fld_fdivp(void) {
    clock_t start = clock();
    volatile double mem = 2.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=4 accum */
            "fldl %1\n\t"                                                            /* ST(0)=2, ST(1)=4 */
            "fdivp %%st, %%st(1)\n\t"                                               /* GAS=FDIVRP: ST(1)=2/4=0.5, pop */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fld_faddp", bench_fld_faddp},
        {"fld_fsubp", bench_fld_fsubp},
        {"fld_fmulp", bench_fld_fmulp},
        {"fld_fdivp", bench_fld_fdivp},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
