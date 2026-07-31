/*
 * bench_fcom_trig.c -- Compare + trig value call + FNSTSW in ONE run (OPT-SW).
 *
 * The fcom/fcos/fnstsw shape used to pay three serial status_word RMWs of the
 * same halfword (compare CC store -> C1|C2 clear -> FSTSW TOP merge, each a
 * strh/ldrh round trip through the store buffer).  With the fused-clears
 * window the pack is held in a BL-surviving register, the trig clear becomes
 * one AND, and status_word is written once.
 *
 *   fcom_cos_fstsw   the audit's exact repro shape (ordered compare)
 *   cos_fstsw        no compare: single-call run, window inactive (control)
 *
 * Build: clang -arch x86_64 -O0 -g -o bench_fcom_trig bench_fcom_trig.c
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 300000
#define RUNS  5

static clock_t bench_fcom_cos_fstsw(void) {
    clock_t start = clock();
    volatile double a = 0.75, b = 1.25;
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fldl %2\n\t"
            "fcomp %%st(1)\n\t"
            "fcos\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(sw) : "m"(a), "m"(b) : "ax", "st");
    return clock() - start;
}

static clock_t bench_cos_fstsw(void) {
    clock_t start = clock();
    volatile double a = 0.75;
    volatile uint16_t sw;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile(
            "fldl %1\n\t"
            "fcos\n\t"
            "fnstsw %%ax\n\t"
            "movw %%ax, %0\n\t"
            "fstp %%st(0)\n"
            : "=m"(sw) : "m"(a) : "ax", "st");
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"fcom_cos_fstsw", bench_fcom_cos_fstsw},
        {"cos_fstsw",      bench_cos_fstsw},
    };
    for (unsigned i = 0; i < sizeof(benches) / sizeof(benches[0]); i++) {
        unsigned long best = ~0ul;
        for (int r = 0; r < RUNS; r++) {
            unsigned long t = (unsigned long)benches[i].fn();
            if (t < best) best = t;
        }
        printf("BENCH %s %lu\n", benches[i].name, best);
    }
    return 0;
}
