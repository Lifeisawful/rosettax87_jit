/*
 * bench_compare.c -- Benchmarks for x87 compare/status opcodes.
 * Covers: FCOM, FCOMP, FCOMPP, FUCOM, FUCOMP, FUCOMPP,
 *         FCOMI, FCOMIP, FUCOMIP, FTST, FSTSW
 *
 * Compare results go to status word; read via FNSTSW into volatile uint16_t
 * to prevent dead-code elimination.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fcom_st(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fcom %%st(1)\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

static clock_t bench_fcom_m64(void) {
    clock_t start = clock();
    volatile double cmp = 5.0;
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fcoml %1\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : "m"(cmp) : "ax");
    return clock() - start;
}

static clock_t bench_fcomp_st(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fcomp %%st(1)\n\t"             /* compare, pop -> ST(0)=1 */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

static clock_t bench_fcompp(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fcompp\n\t"                    /* compare 2 vs 1, double-pop */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

static clock_t bench_fucom_st(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fucom %%st(1)\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

static clock_t bench_fucomp_st(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fucomp %%st(1)\n\t"            /* compare, pop -> ST(0)=1 */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

static clock_t bench_fucompp(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fucompp\n\t"                   /* compare 2 vs 1, double-pop */
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

/* FCOMI/FCOMIP — write result directly to EFLAGS, no FNSTSW needed */
static clock_t bench_fcomi(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fcomi %%st(1)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fcomip(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fcomip %%st(1)\n\t"            /* compare, pop -> ST(0)=1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fucomip(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fld1\n\t fld1\n\t faddp\n\t"  /* ST(0)=2, ST(1)=1 */
            "fucomip %%st(1)\n\t"           /* compare, pop -> ST(0)=1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

/* FTST — compare ST(0) against 0.0 */
static clock_t bench_ftst(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "ftst\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

/* FSTSW — store status word to memory */
static clock_t bench_fstsw(void) {
    clock_t start = clock();
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            : "=m"(sw) : : "ax");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fcom_st",   bench_fcom_st},
        {"fcom_m64",  bench_fcom_m64},
        {"fcomp_st",  bench_fcomp_st},
        {"fcompp",    bench_fcompp},
        {"fucom_st",  bench_fucom_st},
        {"fucomp_st", bench_fucomp_st},
        {"fucompp",   bench_fucompp},
        {"fcomi",     bench_fcomi},
        {"fcomip",    bench_fcomip},
        {"fucomip",   bench_fucomip},
        {"ftst",      bench_ftst},
        {"fstsw",     bench_fstsw},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
