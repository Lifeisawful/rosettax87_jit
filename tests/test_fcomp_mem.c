/*
 * test_fcomp_mem.c — Targeted test for FCOMP m32fp / m64fp
 *
 * The rendering bug was isolated to FCOMP. Register FCOMP passes unit tests,
 * so this test specifically targets the MEMORY forms (D8 /3 and DC /3)
 * which are what real rendering code uses for comparisons like:
 *   fcomp dword ptr [ebp-0x10]
 *
 * Tests both FCOM (no pop) and FCOMP (pop) with memory operands to
 * identify any divergence.
 *
 * Build: gcc -O0 -mfpmath=387 -o test_fcomp_mem test_fcomp_mem.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;

static void check(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_d(const char *name, double got, double expected) {
    uint64_t a, b;
    memcpy(&a, &got, 8); memcpy(&b, &expected, 8);
    if (a != b) {
        printf("FAIL  %-55s  got=%.10g  expected=%.10g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* C3=0x4000, C2=0x0400, C0=0x0100 */
/* GT: 0x0000  LT: 0x0100  EQ: 0x4000  UN: 0x4500 */

/* ========== FCOM m32fp (D8 /2) — no pop ========== */
static uint16_t fcom_m32(double a, float b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcoms %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* ========== FCOM m64fp (DC /2) — no pop ========== */
static uint16_t fcom_m64(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcoml %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* ========== FCOMP m32fp (D8 /3) — pops ========== */
static uint16_t fcomp_m32(double a, float b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* ========== FCOMP m64fp (DC /3) — pops ========== */
static uint16_t fcomp_m64(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* ========== FCOMP m32 then verify stack is popped ========== */
static double fcomp_m32_stack_check(double under, double top, float cmp) {
    double result;
    __asm__ volatile(
        "fldl %1\n"     /* push 'under' */
        "fldl %2\n"     /* push 'top' — ST(0)=top, ST(1)=under */
        "fcomps %3\n"   /* compare ST(0) with cmp, pop */
        /* After pop: ST(0) should be 'under' */
        "fstpl %0\n"
        : "=m"(result) : "m"(under), "m"(top), "m"(cmp));
    return result;
}

/* ========== FCOMP m64 then verify stack is popped ========== */
static double fcomp_m64_stack_check(double under, double top, double cmp) {
    double result;
    __asm__ volatile(
        "fldl %1\n"     /* push 'under' */
        "fldl %2\n"     /* push 'top' */
        "fcompl %3\n"   /* compare and pop */
        "fstpl %0\n"
        : "=m"(result) : "m"(under), "m"(top), "m"(cmp));
    return result;
}

/* ========== Rendering pattern: FLD + arithmetic + FCOMP m32 + FSTSW + branch ========== */
/* Simulates: load value, subtract threshold, compare against zero */
static uint16_t render_pattern_fcomp_m32(float value, float threshold) {
    uint16_t sw;
    float zero = 0.0f;
    __asm__ volatile(
        "flds %1\n"       /* load value */
        "fsubs %2\n"      /* subtract threshold: ST(0) = value - threshold */
        "fcomps %3\n"     /* compare (value-threshold) against 0.0f, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(value), "m"(threshold), "m"(zero) : "ax");
    return sw & 0x4500;
}

/* ========== Long sequence: multiple FCOMP m32 in a row ========== */
static void multi_fcomp_m32(uint16_t *results, double *vals, float *cmps, int n) {
    for (int i = 0; i < n; i++) {
        __asm__ volatile(
            "fldl %1\n"
            "fcomps %2\n"
            "fnstsw %%ax\n"
            "movw %%ax, %0\n"
            : "=m"(results[i]) : "m"(vals[i]), "m"(cmps[i]) : "ax");
        results[i] &= 0x4500;
    }
}

/* ========== FCOMP m32 inside a larger x87 sequence (cache stress) ========== */
static uint16_t fcomp_m32_in_sequence(void) {
    uint16_t sw;
    float one_f = 1.0f;
    float three_f = 3.0f;
    __asm__ volatile(
        "fld1\n"                                /* push 1.0 */
        "fld1\n fld1\n faddp\n"                 /* push 2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* push 3.0 */
        /* ST(0)=3, ST(1)=2, ST(2)=1 */
        "fcomps %1\n"                            /* compare 3.0 > 1.0f → GT, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        /* ST(0)=2, ST(1)=1 — clean up */
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(one_f) : "ax");
    return sw & 0x4500;
}

/* Same but LT */
static uint16_t fcomp_m32_in_sequence_lt(void) {
    uint16_t sw;
    float five_f = 5.0f;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fcomps %1\n"                             /* 3.0 < 5.0f → LT, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(five_f) : "ax");
    return sw & 0x4500;
}

/* Same but EQ */
static uint16_t fcomp_m32_in_sequence_eq(void) {
    uint16_t sw;
    float three_f = 3.0f;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fcomps %1\n"                             /* 3.0 == 3.0f → EQ, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(three_f) : "ax");
    return sw & 0x4500;
}

int main(void) {
    printf("=== FCOM m32fp (no pop) — baseline ===\n");
    check("FCOM m32  5.0 > 3.0f  GT", fcom_m32(5.0, 3.0f), 0x0000);
    check("FCOM m32  1.0 < 3.0f  LT", fcom_m32(1.0, 3.0f), 0x0100);
    check("FCOM m32  3.0 = 3.0f  EQ", fcom_m32(3.0, 3.0f), 0x4000);
    check("FCOM m32  NaN         UN", fcom_m32(NAN, 1.0f),  0x4500);

    printf("\n=== FCOM m64fp (no pop) — baseline ===\n");
    check("FCOM m64  5.0 > 3.0   GT", fcom_m64(5.0, 3.0), 0x0000);
    check("FCOM m64  1.0 < 3.0   LT", fcom_m64(1.0, 3.0), 0x0100);
    check("FCOM m64  3.0 = 3.0   EQ", fcom_m64(3.0, 3.0), 0x4000);
    check("FCOM m64  NaN         UN", fcom_m64(NAN, 1.0),  0x4500);

    printf("\n=== FCOMP m32fp (pop) — the suspect ===\n");
    check("FCOMP m32  5.0 > 3.0f  GT", fcomp_m32(5.0, 3.0f), 0x0000);
    check("FCOMP m32  1.0 < 3.0f  LT", fcomp_m32(1.0, 3.0f), 0x0100);
    check("FCOMP m32  3.0 = 3.0f  EQ", fcomp_m32(3.0, 3.0f), 0x4000);
    check("FCOMP m32  NaN         UN", fcomp_m32(NAN, 1.0f),  0x4500);

    printf("\n=== FCOMP m64fp (pop) ===\n");
    check("FCOMP m64  5.0 > 3.0   GT", fcomp_m64(5.0, 3.0), 0x0000);
    check("FCOMP m64  1.0 < 3.0   LT", fcomp_m64(1.0, 3.0), 0x0100);
    check("FCOMP m64  3.0 = 3.0   EQ", fcomp_m64(3.0, 3.0), 0x4000);
    check("FCOMP m64  NaN         UN", fcomp_m64(NAN, 1.0),  0x4500);

    printf("\n=== FCOMP m32 — stack correctness after pop ===\n");
    check_d("FCOMP m32 pop: ST(0)=under=7.0", fcomp_m32_stack_check(7.0, 3.0, 1.0f), 7.0);
    check_d("FCOMP m64 pop: ST(0)=under=9.5", fcomp_m64_stack_check(9.5, 2.0, 1.0), 9.5);

    printf("\n=== FCOMP m32 inside x87 sequence (cache active) ===\n");
    check("In-sequence FCOMP m32  3>1 GT", fcomp_m32_in_sequence(), 0x0000);
    check("In-sequence FCOMP m32  3<5 LT", fcomp_m32_in_sequence_lt(), 0x0100);
    check("In-sequence FCOMP m32  3=3 EQ", fcomp_m32_in_sequence_eq(), 0x4000);

    printf("\n=== Rendering pattern: FLD + FSUB + FCOMP m32 + FSTSW ===\n");
    check("Render: 5.0 - 3.0 = 2.0 > 0  GT", render_pattern_fcomp_m32(5.0f, 3.0f), 0x0000);
    check("Render: 1.0 - 3.0 = -2.0 < 0 LT", render_pattern_fcomp_m32(1.0f, 3.0f), 0x0100);
    check("Render: 3.0 - 3.0 = 0.0 == 0  EQ", render_pattern_fcomp_m32(3.0f, 3.0f), 0x4000);

    printf("\n=== Multiple FCOMP m32 in sequence ===\n");
    {
        double vals[] = {5.0, 1.0, 3.0, -1.0};
        float  cmps[] = {3.0f, 3.0f, 3.0f, 0.0f};
        uint16_t results[4];
        multi_fcomp_m32(results, vals, cmps, 4);
        check("Multi[0] 5>3  GT", results[0], 0x0000);
        check("Multi[1] 1<3  LT", results[1], 0x0100);
        check("Multi[2] 3=3  EQ", results[2], 0x4000);
        check("Multi[3] -1<0 LT", results[3], 0x0100);
    }

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}