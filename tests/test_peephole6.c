/*
 * test_peephole6.c -- validate two new peephole fusion patterns
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_peephole6 test_peephole6.c
 *
 * Section A: fld_fcomp
 *   FLD src / FCOMP ST(1)  (no FSTSW following)
 *   Push + pop cancel.  Net stack unchanged.  CC bits written to status word.
 *
 * Section B: fld_arith_arithp
 *   FLD src / non-popping ARITH ST(0),ST(1) / popping ARITHp ST(1)
 *   Push + pop cancel.  Result = op2(old_ST0, op1(fld_value, old_ST0)).
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static uint32_t as_u32(float f) {
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}
static uint64_t as_u64(double d) {
    uint64_t u;
    memcpy(&u, &d, 8);
    return u;
}

static void check_f32(const char *name, float got, float expected) {
    if (as_u32(got) != as_u32(expected)) {
        printf("FAIL  %-60s  got=%.10g (0x%08x)  expected=%.10g (0x%08x)\n",
               name, got, as_u32(got), expected, as_u32(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f64(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-60s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-60s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Read x87 status-word CC bits after a compare. */
#define READ_SW(var)                            \
    uint16_t var;                               \
    __asm__ volatile(                           \
        "fnstsw %%ax\n"                         \
        "andw $0x4500, %%ax\n"                  \
        "movw %%ax, %0\n"                       \
        : "=m"(var)                             \
        :                                       \
        : "ax")

/* =========================================================================
 * Section A: fld_fcomp — FLD + FCOMP/FUCOMP (no FSTSW)
 *
 * The fusion fires on  FLD src / FCOMP ST(1).  We verify:
 *   (a) The correct CC bits land in the status word (read via separate FNSTSW).
 *   (b) The stack depth is unchanged after the pair (net zero: push+pop cancel).
 * =========================================================================
 */

/* FLD m64 + FCOMP ST(1): GT  (loaded > old_ST0)
 * ST(0)=1.0.  FLD [3.0] -> ST(0)=3, ST(1)=1.
 * FCOMP ST(1): 3 > 1 -> GT: CC=0x0000, pop.
 * Stack back to depth 1: ST(0)=1.0.
 */
static uint16_t test_a_fld_m64_fcomp_gt(void) {
    double src = 3.0;
    __asm__ volatile(
        "fld1\n"           /* ST(0)=1.0 */
        "fldl %0\n"        /* ST(0)=3.0, ST(1)=1.0 */
        "fcomp %%st(1)\n"  /* compare 3 vs 1, pop */
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");  /* clean up ST(0)=1.0 */
    return cc;
}

/* FLD m64 + FCOMP ST(1): LT  (loaded < old_ST0)
 * ST(0)=5.0.  FLD [2.0] -> ST(0)=2, ST(1)=5.
 * FCOMP ST(1): 2 < 5 -> LT: CC=0x0100, pop.
 */
static uint16_t test_a_fld_m64_fcomp_lt(void) {
    double src = 2.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fldl %0\n"
        "fcomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 + FCOMP ST(1): EQ
 * ST(0)=4.0.  FLD [4.0] -> compare 4 vs 4 -> EQ: CC=0x4000, pop.
 */
static uint16_t test_a_fld_m64_fcomp_eq(void) {
    double src = 4.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 4.0 */
        "fldl %0\n"
        "fcomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m32 + FCOMP ST(1): GT
 * ST(0)=1.0.  FLD [6.0f] -> compare 6 vs 1 -> GT: CC=0x0000, pop.
 */
static uint16_t test_a_fld_m32_fcomp_gt(void) {
    float src = 6.0f;
    __asm__ volatile(
        "fld1\n"
        "flds %0\n"
        "fcomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD ST(1) + FCOMP ST(1): LT
 * Stack: ST(0)=7.0, ST(1)=2.0.
 * FLD ST(1) pushes 2.0 -> ST(0)=2, ST(1)=7, ST(2)=2.
 * FCOMP ST(1): 2 < 7 -> LT: CC=0x0100, pop -> ST(0)=7, ST(1)=2.
 */
static uint16_t test_a_fld_reg_fcomp_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"                     /* 2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 7.0 */
        /* ST(0)=7, ST(1)=2 */
        "fld %%st(1)\n"
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" "fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD1 + FCOMP ST(1): EQ
 * ST(0)=1.0.  FLD1 pushes 1.0 -> compare 1 vs 1 -> EQ: CC=0x4000, pop.
 */
static uint16_t test_a_fld1_fcomp_eq(void) {
    __asm__ volatile(
        "fld1\n"
        "fld1\n"
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLDZ + FCOMP ST(1): LT  (0 < 3)
 * ST(0)=3.0.  FLDZ pushes 0 -> compare 0 vs 3 -> LT: CC=0x0100, pop.
 */
static uint16_t test_a_fldz_fcomp_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fldz\n"
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 (NaN) + FUCOMP ST(1): Unordered
 * ST(0)=1.0.  FLD [NaN] -> FUCOMP ST(1): compare NaN vs 1 -> Unordered: CC=0x4500.
 */
static uint16_t test_a_fld_nan_fucomp_unordered(void) {
    double nan_val = __builtin_nan("");
    __asm__ volatile(
        "fld1\n"
        "fldl %0\n"
        "fucomp %%st(1)\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* Verify stack depth is preserved (net zero) after fld + fcomp.
 * Build a known 2-deep stack (ST(0)=10, ST(1)=5), do fld+fcomp, then
 * confirm ST(0)=10 is unchanged (net zero stack: pair push+pop cancel).
 */
static double test_a_stack_preserved(void) {
    double src = 3.0;
    double result;
    __asm__ volatile(
        /* Build ST(1)=5.0 first, then ST(0)=10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* push 5, start 10 */
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 10.0 */
        /* Now: ST(0)=10.0, ST(1)=5.0 (depth=2) */
        /* fld_fcomp: push 3.0, compare vs ST(1)=10.0, pop -> net zero */
        "fldl %1\n"
        "fcomp %%st(1)\n"
        /* Stack should be back to depth 2: ST(0)=10.0, ST(1)=5.0 */
        "fstpl %0\n"   /* read ST(0)=10.0, pop */
        "fstp %%st(0)\n"  /* discard ST(1)=5.0 */
        : "=m"(result)
        : "m"(src));
    return result;
}

/* =========================================================================
 * Section B: fld_arith_arithp — FLD + ARITH + ARITHp
 *
 * The pattern: FLD src / ARITH ST(0),ST(1) / ARITHp ST(1)
 * After fusion, ST(0) = op2(old_ST0, op1(fld_value, old_ST0)).
 * Net zero stack change.
 * =========================================================================
 */

/* FLD m64 + FMUL ST(0),ST(1) + FADDP ST(1)
 * ST(0)=4.0.  FLD [3.0] -> ST(0)=3, ST(1)=4.
 * FMUL ST(0),ST(1): ST(0) = 3*4 = 12.
 * FADDP ST(1): ST(1) = ST(1)+ST(0) = 4+12 = 16, pop.
 * Result: ST(0) = 16.0.
 */
static double test_b_fld_fmul_faddp(void) {
    double src = 3.0;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 4.0 */
        "fldl %1\n"
        "fmul %%st(1), %%st(0)\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD m64 + FMUL ST(0),ST(1) + FMULP ST(1)
 * ST(0)=2.0.  FLD [5.0] -> ST(0)=5, ST(1)=2.
 * FMUL: ST(0) = 5*2 = 10.
 * FMULP ST(1): ST(1) = ST(1)*ST(0) = 2*10 = 20, pop.
 * Result: ST(0) = 20.0.
 */
static double test_b_fld_fmul_fmulp(void) {
    double src = 5.0;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* 2.0 */
        "fldl %1\n"
        "fmul %%st(1), %%st(0)\n"
        "fmulp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD m64 + FADD ST(0),ST(1) + FADDP ST(1)
 * ST(0)=3.0.  FLD [2.0] -> ST(0)=2, ST(1)=3.
 * FADD: ST(0) = 2+3 = 5.
 * FADDP ST(1): ST(1) = ST(1)+ST(0) = 3+5 = 8, pop.
 * Result: ST(0) = 8.0.
 */
static double test_b_fld_fadd_faddp(void) {
    double src = 2.0;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fldl %1\n"
        "fadd %%st(1), %%st(0)\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD m64 + FSUB ST(0),ST(1) + FSUBRP ST(1)
 * NOTE: GAS AT&T swaps fsubp/fsubrp for register popping forms.
 * `fsubp %%st(0), %%st(1)` encodes FSUBRP (DE E8+i): ST(1) = ST(0) - ST(1).
 * ST(0)=10.0.  FLD [3.0] -> ST(0)=3, ST(1)=10.
 * FSUB ST(0),ST(1): ST(0) = 3-10 = -7.
 * FSUBRP ST(1): ST(1) = ST(0)-ST(1) = -7-10 = -17, pop.
 * Result: ST(0) = -17.0.
 */
static double test_b_fld_fsub_fsubrp(void) {
    double src = 3.0;
    double result;
    __asm__ volatile(
        /* build ST(0)=10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fldl %1\n"
        "fsub %%st(1), %%st(0)\n"
        "fsubp %%st(0), %%st(1)\n"  /* GAS encodes as FSUBRP: ST(1)=ST(0)-ST(1) */
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD m64 + FMUL ST(0),ST(1) + FSUBRP ST(1)
 * NOTE: GAS AT&T swaps fsubp/fsubrp for register popping forms.
 * `fsubp %%st(0), %%st(1)` encodes FSUBRP: ST(1) = ST(0) - ST(1).
 * ST(0)=6.0.  FLD [2.0] -> ST(0)=2, ST(1)=6.
 * FMUL: ST(0) = 2*6 = 12.
 * FSUBRP ST(1): ST(1) = ST(0)-ST(1) = 12-6 = 6, pop.
 * Result: ST(0) = 6.0.
 */
static double test_b_fld_fmul_fsubrp(void) {
    double src = 2.0;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        "fldl %1\n"
        "fmul %%st(1), %%st(0)\n"
        "fsubp %%st(0), %%st(1)\n"  /* GAS encodes as FSUBRP: ST(1)=ST(0)-ST(1) */
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD ST(1) + FMUL ST(0),ST(1) + FADDP ST(1)
 * Stack: ST(0)=3.0, ST(1)=2.0.
 * FLD ST(1) pushes 2.0 -> ST(0)=2, ST(1)=3, ST(2)=2.
 * FMUL ST(0),ST(1): ST(0) = 2*3 = 6.
 * FADDP ST(1): ST(1) = 3+6 = 9, pop -> ST(0)=9, ST(1)=2.
 * Result: ST(0)=9.0 (read and pop), then ST(0)=2.0 remains.
 */
static double test_b_fld_reg_fmul_faddp(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"                     /* 2.0 — ST(0) */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"      /* 3.0 — ST(0), ST(1)=2 */
        "fld %%st(1)\n"
        "fmul %%st(1), %%st(0)\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"    /* read ST(0)=9 */
        "fstp %%st(0)\n"  /* pop ST(0)=2 */
        : "=m"(result));
    return result;
}

/* FLD m64 + FMUL mem + FADDP ST(1)
 * (memory operand form for middle arith)
 * ST(0)=5.0.  FLD [2.0] -> ST(0)=2, ST(1)=5.
 * FMUL [4.0]: ST(0) = 2*4 = 8.
 * FADDP ST(1): ST(1) = 5+8 = 13, pop.
 * Result: 13.0.
 */
static double test_b_fld_fmul_mem_faddp(void) {
    double src = 2.0;
    double mul_val = 4.0;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fldl %1\n"
        "fmull %2\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result)
        : "m"(src), "m"(mul_val));
    return result;
}

/* FLD1 + FMUL ST(0),ST(1) + FADDP ST(1)
 * ST(0)=7.0.  FLD1 -> ST(0)=1, ST(1)=7.
 * FMUL: ST(0) = 1*7 = 7.
 * FADDP ST(1): ST(1) = 7+7 = 14, pop.
 * Result: 14.0.
 */
static double test_b_fld1_fmul_faddp(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 7.0 */
        "fld1\n"
        "fmul %%st(1), %%st(0)\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* FILDL + FMUL ST(0),ST(1) + FADDP ST(1)
 * ST(0)=3.0.  FILD [4] pushes 4.0 -> FMUL: 4*3=12.
 * FADDP: 3+12=15, pop.
 * Result: 15.0.
 */
static double test_b_fild_fmul_faddp(void) {
    int ival = 4;
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fildl %1\n"
        "fmul %%st(1), %%st(0)\n"
        "faddp %%st(0), %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result)
        : "m"(ival));
    return result;
}

/* =========================================================================
 * Entry point
 * =========================================================================
 */

int main(void) {
    printf("=== Section A: fld_fcomp (FLD + FCOMP/FUCOMP, no FSTSW) ===\n");
    check_u16("A  FLD m64 + FCOMP  GT   3>1=0x0000",
              test_a_fld_m64_fcomp_gt(), 0x0000);
    check_u16("A  FLD m64 + FCOMP  LT   2<5=0x0100",
              test_a_fld_m64_fcomp_lt(), 0x0100);
    check_u16("A  FLD m64 + FCOMP  EQ   4=4=0x4000",
              test_a_fld_m64_fcomp_eq(), 0x4000);
    check_u16("A  FLD m32 + FCOMP  GT   6>1=0x0000",
              test_a_fld_m32_fcomp_gt(), 0x0000);
    check_u16("A  FLD ST(1) + FCOMP LT  2<7=0x0100",
              test_a_fld_reg_fcomp_lt(), 0x0100);
    check_u16("A  FLD1 + FCOMP     EQ   1=1=0x4000",
              test_a_fld1_fcomp_eq(), 0x4000);
    check_u16("A  FLDZ + FCOMP     LT   0<3=0x0100",
              test_a_fldz_fcomp_lt(), 0x0100);
    check_u16("A  FLD NaN + FUCOMP UN   NaN=0x4500",
              test_a_fld_nan_fucomp_unordered(), 0x4500);
    check_f64("A  stack depth preserved: ST(0)=10.0 after fld+fcomp",
              test_a_stack_preserved(), 10.0);

    printf("\n=== Section B: fld_arith_arithp (FLD + ARITH + ARITHp) ===\n");
    check_f64("B  FLD m64 + FMUL + FADDP  4+(3*4)=16",
              test_b_fld_fmul_faddp(), 16.0);
    check_f64("B  FLD m64 + FMUL + FMULP  2*(5*2)=20",
              test_b_fld_fmul_fmulp(), 20.0);
    check_f64("B  FLD m64 + FADD + FADDP  3+(2+3)=8",
              test_b_fld_fadd_faddp(), 8.0);
    /* GAS AT&T: fsubp encodes FSUBRP; fsubrp encodes FSUBP */
    check_f64("B  FLD m64 + FSUB + FSUBRP(AT&T fsubp)  (-7)-10=-17",
              test_b_fld_fsub_fsubrp(), -17.0);
    check_f64("B  FLD m64 + FMUL + FSUBRP(AT&T fsubp)  12-6=6",
              test_b_fld_fmul_fsubrp(), 6.0);
    check_f64("B  FLD ST(1) + FMUL + FADDP  3+(2*3)=9",
              test_b_fld_reg_fmul_faddp(), 9.0);
    check_f64("B  FLD m64 + FMUL mem + FADDP  5+(2*4)=13",
              test_b_fld_fmul_mem_faddp(), 13.0);
    check_f64("B  FLD1 + FMUL + FADDP  7+(1*7)=14",
              test_b_fld1_fmul_faddp(), 14.0);
    check_f64("B  FILD m32 + FMUL + FADDP  3+(4*3)=15",
              test_b_fild_fmul_faddp(), 15.0);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
