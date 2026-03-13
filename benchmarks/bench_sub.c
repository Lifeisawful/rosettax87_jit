/*
 * bench_sub.c -- Benchmarks for x87 subtraction opcodes.
 * Covers: FSUB, FSUBR, FSUBP (=Intel FSUBRP), FSUBRP (=Intel FSUBP),
 *         FISUB (m32), FISUBR (m32)
 *
 * NOTE: GAS AT&T syntax: fsubp = Intel FSUBRP, fsubrp = Intel FSUBP
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

static clock_t bench_fsub_m64(void) {
    clock_t start = clock();
    volatile double mem = 0.5;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fsubl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

static clock_t bench_fsubr_m64(void) {
    clock_t start = clock();
    volatile double mem = 3.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"
            "fsubrl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

/* GAS fsubp = Intel FSUBRP: ST(1) = ST(0) - ST(1), pop */
static clock_t bench_fsubp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"                          /* ST(0)=1 */
            "fld1\n\t fld1\n\t faddp\n\t"      /* ST(0)=2, ST(1)=1 */
            "fsubp\n\t"                          /* GAS=FSUBRP: ST(1)=2-1=1, pop -> ST(0)=1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

/* GAS fsubrp = Intel FSUBP: ST(1) = ST(1) - ST(0), pop */
static clock_t bench_fsubrp(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t"                          /* ST(0)=1 */
            "fld1\n\t fld1\n\t faddp\n\t"      /* ST(0)=2, ST(1)=1 */
            "fsubrp\n\t"                         /* GAS=FSUBP: ST(1)=1-2=-1, pop -> ST(0)=-1 */
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

static clock_t bench_fisub_m32(void) {
    clock_t start = clock();
    volatile int32_t mem = 3;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=4 */
            "fisubl %1\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

static clock_t bench_fisubr_m32(void) {
    clock_t start = clock();
    volatile int32_t mem = 10;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t fld1\n\t faddp\n\t"  /* ST(0)=3 */
            "fisubrl %1\n\t"                                     /* ST(0) = 10 - 3 = 7 */
            "fstpl %0\n"
            : "=m"(r) : "m"(mem));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fsub_m64",   bench_fsub_m64},
        {"fsubr_m64",  bench_fsubr_m64},
        {"fsubp",      bench_fsubp},
        {"fsubrp",     bench_fsubrp},
        {"fisub_m32",  bench_fisub_m32},
        {"fisubr_m32", bench_fisubr_m32},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
