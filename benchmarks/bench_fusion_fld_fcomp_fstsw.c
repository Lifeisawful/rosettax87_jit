/*
 * bench_fusion_fld_fcomp_fstsw.c -- Benchmark for fld_fcomp_fstsw fusion.
 * Pattern: FLD m64 + FCOMP ST(1) + FNSTSW AX (compare fusion).
 * The fusion avoids the push+compare+pop overhead.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fld_fcomp_fstsw(void) {
    clock_t start = clock();
    volatile double src = 3.0;
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"           /* ST(0) = 1.0 */
            "fldl %1\n\t"        /* ST(0) = 3.0, ST(1) = 1.0 */
            "fcomp %%st(1)\n\t"  /* compare 3 vs 1, pop -> ST(0) = 1.0 */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : "m"(src) : "ax");
    return clock() - start;
}

/* Same pattern but loading a value smaller than the accumulator */
static clock_t bench_fld_fcomp_fstsw_lt(void) {
    clock_t start = clock();
    volatile double src = 0.5;
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0) = 2.0 */
            "fldl %1\n\t"                   /* ST(0) = 0.5, ST(1) = 2.0 */
            "fcomp %%st(1)\n\t"             /* compare 0.5 vs 2.0, pop -> ST(0) = 2.0 */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : "m"(src) : "ax");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fld_fcomp_fstsw",    bench_fld_fcomp_fstsw},
        {"fld_fcomp_fstsw_lt", bench_fld_fcomp_fstsw_lt},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
