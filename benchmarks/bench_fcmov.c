/*
 * bench_fcmov.c -- Benchmarks for x87 conditional move opcodes.
 * Covers: FCMOVb, FCMOVnb, FCMOVe, FCMOVne, FCMOVbe, FCMOVnbe,
 *         FCMOVu, FCMOVnu
 *
 * Integer flags are set via cmpl before each fcmov.
 * For FCMOVu/FCMOVnu (PF flag), fucomip with a NaN sets PF=1.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

/* FCMOVb: CF=1 (below). Set CF=1 via: 0 < 1 */
static clock_t bench_fcmovb(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "xorl %%eax, %%eax\n\t"
            "cmpl $1, %%eax\n\t"                 /* 0 < 1 -> CF=1 */
            "fcmovb %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVnb: CF=0 (not below). Set CF=0 via: 1 >= 1 */
static clock_t bench_fcmovnb(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "movl $1, %%eax\n\t"
            "cmpl $1, %%eax\n\t"                 /* 1 == 1 -> CF=0, ZF=1 */
            "fcmovnb %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVe: ZF=1 (equal). Set ZF=1 via: 1 == 1 */
static clock_t bench_fcmove(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "movl $1, %%eax\n\t"
            "cmpl $1, %%eax\n\t"                 /* ZF=1 */
            "fcmove %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVne: ZF=0 (not equal). Set ZF=0 via: 1 != 2 */
static clock_t bench_fcmovne(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "movl $1, %%eax\n\t"
            "cmpl $2, %%eax\n\t"                 /* 1 != 2 -> ZF=0 */
            "fcmovne %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVbe: CF=1 or ZF=1 (below or equal). Use CF=1 case */
static clock_t bench_fcmovbe(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "xorl %%eax, %%eax\n\t"
            "cmpl $1, %%eax\n\t"                 /* 0 < 1 -> CF=1 */
            "fcmovbe %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVnbe: CF=0 and ZF=0 (above). Set via: 2 > 1 */
static clock_t bench_fcmovnbe(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"       /* ST(0)=2 src */
            "fld1\n\t"                            /* ST(0)=1 dst, ST(1)=2 */
            "movl $2, %%eax\n\t"
            "cmpl $1, %%eax\n\t"                 /* 2 > 1 -> CF=0, ZF=0 */
            "fcmovnbe %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : : "eax");
    return clock() - start;
}

/* FCMOVu: PF=1 (unordered). Use fucomip with NaN to set PF=1 */
static clock_t bench_fcmovu(void) {
    clock_t start = clock();
    volatile double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy((void *)&nan_val, &nan_bits, 8);
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"   /* ST(0)=2 (will be src) */
            "fld1\n\t"                        /* ST(0)=1 (will be dst) */
            /* set PF=1 via fucomip with NaN — use a scratch compare */
            "fldl %1\n\t"                     /* push NaN */
            "fld1\n\t"                        /* push 1.0 */
            "fucomip %%st(1), %%st(0)\n\t"   /* 1 vs NaN -> PF=1, pops ST(0) */
            "fstp %%st(0)\n\t"               /* discard NaN */
            /* ST(0)=1 dst, ST(1)=2 src */
            "fcmovu %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r) : "m"(nan_val));
    return clock() - start;
}

/* FCMOVnu: PF=0 (not unordered). Use fucomip with normal values */
static clock_t bench_fcmovnu(void) {
    clock_t start = clock();
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fld1\n\t fld1\n\t faddp\n\t"   /* ST(0)=2 src */
            "fld1\n\t"                        /* ST(0)=1 dst, ST(1)=2 */
            /* set PF=0 via fucomip with normal values */
            "fld1\n\t"                        /* push 1.0 */
            "fld1\n\t fld1\n\t faddp\n\t"   /* push 2.0, ST(1)=1 */
            "fucomip %%st(1), %%st(0)\n\t"  /* 2 vs 1 -> PF=0, pops ST(0) */
            "fstp %%st(0)\n\t"              /* discard 1.0 */
            /* ST(0)=1 dst, ST(1)=2 src */
            "fcmovnu %%st(1), %%st(0)\n\t"
            "fstp %%st(0)\n\t"
            "fstpl %0\n"
            : "=m"(r));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fcmovb",   bench_fcmovb},
        {"fcmovnb",  bench_fcmovnb},
        {"fcmove",   bench_fcmove},
        {"fcmovne",  bench_fcmovne},
        {"fcmovbe",  bench_fcmovbe},
        {"fcmovnbe", bench_fcmovnbe},
        {"fcmovu",   bench_fcmovu},
        {"fcmovnu",  bench_fcmovnu},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
