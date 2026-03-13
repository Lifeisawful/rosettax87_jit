/*
 * bench_fusion_fxch_fstp.c -- Benchmark for fxch_fstp fusion.
 * Pattern: FXCH ST(1) + FSTP ST(1) — swap then store is equivalent to a pop.
 * The fusion recognizes this and emits a single pop operation.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fxch_fstp_st1(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"                          /* ST(0)=1 */
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2, ST(1)=1 */
            "fxch %%st(1)\n\t"                  /* ST(0)=1, ST(1)=2 */
            "fstp %%st(1)\n\t"                  /* store 1->ST(1), pop -> ST(0)=1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fxch_fstp_st1", bench_fxch_fstp_st1},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
