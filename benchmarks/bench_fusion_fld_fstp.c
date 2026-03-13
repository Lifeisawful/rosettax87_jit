/*
 * bench_fusion_fld_fstp.c -- Benchmark for fld_fstp fusion.
 * Pattern: FLD m64 + FSTP ST(i) — load then immediately store into another slot.
 * The fusion avoids the push+pop by directly writing into the destination register.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

/* FLD m64 + FSTP ST(1): load src and store into the slot above it */
static clock_t bench_fld_fstp_st1(void) {
    clock_t start = clock();
    volatile double src = 2.718;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"           /* existing ST(0) = 1.0 (slot that will be overwritten) */
            "fldl %1\n\t"        /* ST(0) = src, ST(1) = 1.0 */
            "fstp %%st(1)\n\t"   /* store src -> ST(1), pop -> ST(0) = src */
            "fstpl %0\n"
            : "=m"(r) : "m"(src));
    return clock() - start;
}

/* FLD m64 + FSTP m64: load then store to memory (push+pop to memory) */
static clock_t bench_fld_fstp_m64(void) {
    clock_t start = clock();
    volatile double src = 3.14159;
    volatile double dst;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fstpl %0\n"
            : "=m"(dst) : "m"(src));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fld_fstp_st1", bench_fld_fstp_st1},
        {"fld_fstp_m64", bench_fld_fstp_m64},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
