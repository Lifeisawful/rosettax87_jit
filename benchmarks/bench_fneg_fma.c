/*
 * bench_fneg_fma.c -- FNeg folding into the FMA path.
 * Shape: fmul; fchs; fadd (c - a*b) must lower to a single FMSUB via
 * pass_fneg_fold's consumer-fold-first ordering + pass_fma; before 88fc31c
 * the FNeg collapsed into FNMUL first and stranded the add (FNMUL+FADD).
 * Covers both the memory-operand and popping add forms.
 */
#include <stdio.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fmul_fchs_fadd(void) {
    volatile double a = 3.0, b = 4.0, c = 20.0;
    volatile double r;
    clock_t start = clock();
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fmull %2\n\t"
            "fchs\n\t"
            "faddl %3\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

static clock_t bench_fmul_fchs_faddp(void) {
    volatile double a = 3.0, b = 4.0, c = 20.0;
    volatile double r;
    clock_t start = clock();
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %3\n\t"
            "fldl %1\n\t"
            "fmull %2\n\t"
            "fchs\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fmul_fchs_fadd",  bench_fmul_fchs_fadd},
        {"fmul_fchs_faddp", bench_fmul_fchs_faddp},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        /* Min, not mean: the first ~3 runs land ~1.55x high (core/frequency
         * ramp-up) and a mean of 5 buries the ~8% FMSUB delta entirely. */
        clock_t best = 0;
        for (int r = 0; r < RUNS; r++) {
            clock_t t = benches[i].fn();
            if (r == 0 || t < best) best = t;
        }
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)best);
    }
    return 0;
}
