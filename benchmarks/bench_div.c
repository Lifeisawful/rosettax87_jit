/*
 * bench_div.c -- Benchmarks for x87 division opcodes.
 * Covers: FDIV, FDIVR, FDIVP (=Intel FDIVRP), FDIVRP (=Intel FDIVP),
 *         FIDIV (m32), FIDIVR (m32)
 *
 * NOTE: GAS AT&T syntax: fdivp = Intel FDIVRP, fdivrp = Intel FDIVP
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fdiv_m64(void) {
    clock_t start = clock();
    volatile double dividend = 10.0;
    volatile double divisor  = 4.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fdivl %2\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(dividend), "m"(divisor));
    return clock() - start;
}

static clock_t bench_fdivr_m64(void) {
    clock_t start = clock();
    volatile double src = 3.0;
    volatile double div_mem = 9.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl %1\n\t"
            "fdivrl %2\n\t"     /* ST(0) = 9 / 3 = 3 */
            "fstpl %0\n"
            : "=m"(r) : "m"(src), "m"(div_mem));
    return clock() - start;
}

/* GAS fdivp = Intel FDIVRP: ST(1) = ST(0) / ST(1), pop */
static clock_t bench_fdivp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"                    /* ST(0)=2 denominator */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t" /* ST(0)=3 numerator above */
            /* ST(0)=3, ST(1)=2 */
            "fdivp\n\t"     /* GAS=FDIVRP: ST(1)=3/2=1.5, pop -> ST(0)=1.5 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

/* GAS fdivrp = Intel FDIVP: ST(1) = ST(1) / ST(0), pop */
static clock_t bench_fdivrp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"                    /* ST(0)=2 divisor */
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t" /* ST(0)=4 dividend */
            /* ST(0)=4, ST(1)=2 */
            "fdivrp\n\t"    /* GAS=FDIVP: ST(1)=2/4=0.5, pop -> ST(0)=0.5 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fidiv_m32(void) {
    clock_t start = clock();
    volatile int32_t mem = 4;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl2t\n\t"        /* push log2(10) ~3.32 */
            "fidivl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

static clock_t bench_fidivr_m32(void) {
    clock_t start = clock();
    volatile int32_t mem = 12;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fidivrl %1\n\t"                                     /* ST(0) = 12 / 3 = 4 */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fdiv_m64",   bench_fdiv_m64},
        {"fdivr_m64",  bench_fdivr_m64},
        {"fdivp",      bench_fdivp},
        {"fdivrp",     bench_fdivrp},
        {"fidiv_m32",  bench_fidiv_m32},
        {"fidivr_m32", bench_fidivr_m32},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
