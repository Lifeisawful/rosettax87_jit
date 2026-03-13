/*
 * test_arith.c — Exhaustive tests for all x87 arithmetic operations.
 *
 * Covers: FADD, FADDP, FIADD, FSUB, FSUBR, FSUBP, FSUBRP,
 *         FMUL, FMULP, FIMUL, FDIV, FDIVR, FDIVP, FDIVRP,
 *         FIDIV, FIDIVR, FISUB
 *
 * NOTE: GAS AT&T syntax swaps fsubp↔fsubrp and fdivp↔fdivrp for
 * register-register popping forms. Comments note actual Intel encoding.
 *
 * Build: gcc -O0 -mfpmath=387 -o test_arith test_arith.c -lm
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Helper: push N onto x87 stack using FLD1+FADDP chain */
/* (inline asm helper strings built below) */

/* ==== FADD ==== */

/* FADD ST(0), ST(i) — D8 C0+i */
static double fadd_st0_st1(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"    /* ST(0)=2 */
        "fld1\n"                    /* ST(0)=1, ST(1)=2 */
        "fadd %%st(1), %%st(0)\n"  /* ST(0)=1+2=3 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FADD ST(i), ST(0) — DC C0+i */
static double fadd_sti_st0(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"    /* ST(0)=2 */
        "fld1\n"                    /* ST(0)=1, ST(1)=2 */
        "fadd %%st(0), %%st(1)\n"  /* ST(1)=2+1=3 */
        "fstp %%st(0)\n fstpl %0\n" : "=m"(r));
    return r;
}

/* FADD m32fp — D8 /0 */
static double fadd_m32(void) {
    double r; float mem = 2.5f;
    __asm__ volatile("fld1\n fadds %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FADD m64fp — DC /0 */
static double fadd_m64(void) {
    double r; double mem = 3.75;
    __asm__ volatile("fld1\n faddl %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FADDP ST(1), ST(0) — DE C1 */
static double faddp_st1(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3 */
        "fld1\n fld1\n faddp\n"                   /* 2 */
        /* ST(0)=2, ST(1)=3 */
        "faddp\n" /* 3+2=5 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* FIADD m32int — DA /0 */
static double fiadd_m32(void) {
    double r; int32_t v = 7;
    __asm__ volatile("fld1\n fiaddl %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* FIADD m16int — DE /0 */
static double fiadd_m16(void) {
    double r; int16_t v = -3;
    __asm__ volatile("fld1\n fiadds %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FSUB / FSUBR ==== */

/* FSUB ST(0), ST(i) — D8 E0+i: ST(0) = ST(0) - ST(i) */
static double fsub_st0_sti(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"    /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5 */
        /* ST(0)=5, ST(1)=2 */
        "fsub %%st(1), %%st(0)\n"  /* 5-2=3 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FSUBR ST(0), ST(i) — D8 E8+i: ST(0) = ST(i) - ST(0) */
static double fsubr_st0_sti(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"   /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5 */
        /* ST(0)=5, ST(1)=2 */
        "fsubr %%st(1), %%st(0)\n" /* 2-5=-3 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FSUB m32fp — D8 /4: ST(0) = ST(0) - m32 */
static double fsub_m32(void) {
    double r; float mem = 1.5f;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fsubs %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FSUBR m64fp — DC /5: ST(0) = m64 - ST(0) */
static double fsubr_m64(void) {
    double r; double mem = 10.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fsubrl %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FSUBP — GAS AT&T fsubp = Intel FSUBRP (DE E8+i) = ST(0)-ST(1) stored in ST(1) */
static double fsubp_gas(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5 */
        /* ST(0)=5, ST(1)=2 */
        "fsubp\n"  /* GAS=FSUBRP: ST(0)-ST(1) = 5-2 = 3 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* FSUBRP — GAS AT&T fsubrp = Intel FSUBP (DE E0+i) = ST(1)-ST(0) stored in ST(1) */
static double fsubrp_gas(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5 */
        /* ST(0)=5, ST(1)=2 */
        "fsubrp\n"  /* GAS=FSUBP: ST(1)-ST(0) = 2-5 = -3 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* ==== FMUL ==== */

/* FMUL ST(0), ST(i) */
static double fmul_st0_sti(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fld1\n fld1\n faddp\n"                  /* 2 */
        "fmul %%st(1), %%st(0)\n" /* 2*3=6 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FMUL m32fp */
static double fmul_m32(void) {
    double r; float mem = 4.0f;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fmuls %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FMULP */
static double fmulp_st1(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3 */
        "fld1\n fld1\n faddp\n"                   /* 2 */
        "fmulp\n" /* 3*2=6 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* FIMUL m32int */
static double fimul_m32(void) {
    double r; int32_t v = 5;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fimull %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* FIMUL m16int */
static double fimul_m16(void) {
    double r; int16_t v = -2;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n" /* 2 */
        "fimuls %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FDIV / FDIVR ==== */

/* FDIV ST(0), ST(i): ST(0) = ST(0) / ST(i) */
static double fdiv_st0_sti(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 6 */
        /* ST(0)=6, ST(1)=2 */
        "fdiv %%st(1), %%st(0)\n" /* 6/2=3 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FDIVR ST(0), ST(i): ST(0) = ST(i) / ST(0) */
static double fdivr_st0_sti(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 6 */
        /* ST(0)=6, ST(1)=2 */
        "fdivr %%st(1), %%st(0)\n" /* 2/6=0.333... */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* FDIV m64fp */
static double fdiv_m64(void) {
    double r, mem = 4.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 8 */
        "fdivl %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* FDIVP — GAS fdivp = Intel FDIVRP = ST(0)/ST(1) */
static double fdivp_gas(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6 */
        /* ST(0)=6, ST(1)=3 */
        "fdivp\n" /* GAS=FDIVRP: ST(0)/ST(1) = 6/3 = 2 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* FDIVRP — GAS fdivrp = Intel FDIVP = ST(1)/ST(0) */
static double fdivrp_gas(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6 */
        /* ST(0)=6, ST(1)=3 */
        "fdivrp\n" /* GAS=FDIVP: ST(1)/ST(0) = 3/6 = 0.5 */
        "fstpl %0\n" : "=m"(r));
    return r;
}

/* FIDIV m32int */
static double fidiv_m32(void) {
    double r; int32_t v = 3;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6 */
        "fidivl %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* FIDIVR m32int: ST(0) = m32 / ST(0) */
static double fidivr_m32(void) {
    double r; int32_t v = 12;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* 3 */
        "fidivrl %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* FISUB m32int: ST(0) = ST(0) - m32 */
static double fisub_m32(void) {
    double r; int32_t v = 3;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5 */
        "fisubl %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

int main(void) {
    printf("=== FADD variants ===\n");
    check("FADD ST(0),ST(1)  1+2=3", fadd_st0_st1(), 3.0);
    check("FADD ST(1),ST(0)  2+1=3", fadd_sti_st0(), 3.0);
    check("FADD m32fp  1+2.5=3.5", fadd_m32(), 3.5);
    check("FADD m64fp  1+3.75=4.75", fadd_m64(), 4.75);
    check("FADDP  3+2=5", faddp_st1(), 5.0);
    check("FIADD m32  1+7=8", fiadd_m32(), 8.0);
    check("FIADD m16  1+(-3)=-2", fiadd_m16(), -2.0);

    printf("\n=== FSUB / FSUBR variants ===\n");
    check("FSUB ST(0),ST(1)  5-2=3", fsub_st0_sti(), 3.0);
    check("FSUBR ST(0),ST(1)  2-5=-3", fsubr_st0_sti(), -3.0);
    check("FSUB m32fp  3-1.5=1.5", fsub_m32(), 1.5);
    check("FSUBR m64fp  10-3=7", fsubr_m64(), 7.0);
    check("FSUBP (GAS=FSUBRP)  5-2=3", fsubp_gas(), 3.0);
    check("FSUBRP (GAS=FSUBP)  2-5=-3", fsubrp_gas(), -3.0);

    printf("\n=== FMUL variants ===\n");
    check("FMUL ST(0),ST(1)  2*3=6", fmul_st0_sti(), 6.0);
    check("FMUL m32fp  3*4=12", fmul_m32(), 12.0);
    check("FMULP  3*2=6", fmulp_st1(), 6.0);
    check("FIMUL m32  3*5=15", fimul_m32(), 15.0);
    check("FIMUL m16  2*(-2)=-4", fimul_m16(), -4.0);

    printf("\n=== FDIV / FDIVR variants ===\n");
    check("FDIV ST(0),ST(1)  6/2=3", fdiv_st0_sti(), 3.0);
    check("FDIVR ST(0),ST(1)  2/6=0.333", fdivr_st0_sti(), 2.0/6.0);
    check("FDIV m64fp  8/4=2", fdiv_m64(), 2.0);
    check("FDIVP (GAS=FDIVRP)  6/3=2", fdivp_gas(), 2.0);
    check("FDIVRP (GAS=FDIVP)  3/6=0.5", fdivrp_gas(), 0.5);
    check("FIDIV m32  6/3=2", fidiv_m32(), 2.0);
    check("FIDIVR m32  12/3=4", fidivr_m32(), 4.0);
    check("FISUB m32  5-3=2", fisub_m32(), 2.0);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
