/*
 * test_peephole3.c -- validate 3-instruction peephole fusion patterns
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_peephole3 test_peephole3.c
 *
 * OPT-F7:  FLD src / non-popping ARITH / FSTP dst
 *   Push + pop cancel.  Result = op(fld_value, old_ST(0)).
 *
 * OPT-F8:  FLD src / FCOMP ST(1) / FNSTSW AX
 *   Push + pop cancel.  Compares loaded value vs old_ST(0).
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
        printf("FAIL  %-55s  got=%.10g (0x%08x)  expected=%.10g (0x%08x)\n",
               name, got, as_u32(got), expected, as_u32(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f64(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
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

/* ========================================================================= */
/* OPT-F7: FLD + non-popping ARITH + FSTP                                   */
/* ========================================================================= */

/* FLD ST(1) + FADD ST(0),ST(1) + FSTP ST(1)
 * Stack: ST(0)=5.0, ST(1)=3.0.
 * FLD ST(1): push 3.0 -> ST(0)=3, ST(1)=5, ST(2)=3.
 * FADD ST(0),ST(1): ST(0) = 3+5 = 8.  ST(1)=5, ST(2)=3.
 * FSTP ST(1): store 8->ST(1), pop -> ST(0)=8, ST(1)=3.
 * Net: ST(0) = old_ST(0) + old_ST(1) = 5+3 = 8.
 */
static float test_f7_fld_reg_fadd_fstp_reg(void) {
    float result;
    __asm__ volatile(
        /* build stack: ST(0)=5.0, ST(1)=3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n"           /* 5.0 */
        /* FLD ST(1) / FADD ST(0),ST(1) / FSTP ST(1) */
        "fld %%st(1)\n"
        "fadd %%st(1), %%st(0)\n"
        "fstp %%st(1)\n"
        /* read result */
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m"(result));
    return result;
}

/* FLD m64 + FMUL ST(0),ST(1) + FSTP m64
 * ST(0) = 4.0.  FLD [3.0] pushes 3.0.
 * FMUL: ST(0) = 3*4 = 12.
 * FSTP m64: store 12.0 to memory, pop -> ST(0)=4.0.
 */
static void test_f7_fld_m64_fmul_fstp_m64(double *dst) {
    double src = 3.0;
    __asm__ volatile(
        /* build stack: ST(0)=4.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* FLD m64 / FMUL / FSTP m64 */
        "fldl %1\n"
        "fmul %%st(1), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        : "=m"(*dst)
        : "m"(src));
}

/* FLD m32 + FADD ST(0),ST(1) + FSTP m32
 * ST(0) = 2.0.  FLD [1.5f] pushes 1.5.
 * FADD: ST(0) = 1.5+2 = 3.5.
 * FSTP m32: store 3.5f, pop.
 */
static void test_f7_fld_m32_fadd_fstp_m32(float *dst) {
    float src = 1.5f;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* ST(0) = 2.0 */
        "flds %1\n"
        "fadd %%st(1), %%st(0)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m"(*dst)
        : "m"(src));
}

/* FLD m64 + FSUB ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 10.0.  FLD [3.0].
 * FSUB ST(0),ST(1): ST(0) = 3 - 10 = -7.
 * FSTP ST(1): store -7 -> ST(1), pop -> ST(0) = -7.
 */
static float test_f7_fld_m64_fsub_fstp_reg(void) {
    float result;
    double src = 3.0;
    __asm__ volatile(
        /* build ST(0) = 10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* FLD m64 / FSUB / FSTP ST(1) */
        "fldl %1\n"
        "fsub %%st(1), %%st(0)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLDZ + FADD ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 7.0.  FLDZ pushes 0.0.
 * FADD: ST(0) = 0+7 = 7.  FSTP ST(1): pop -> ST(0) = 7.
 * Identity: 0 + x = x.
 */
static float test_f7_fldz_fadd_fstp_reg(void) {
    float result;
    __asm__ volatile(
        /* build ST(0) = 7.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* FLDZ / FADD / FSTP ST(1) */
        "fldz\n"
        "fadd %%st(1), %%st(0)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result));
    return result;
}

/* FLD1 + FMUL ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 9.0.  FLD1 pushes 1.0.
 * FMUL: ST(0) = 1*9 = 9.  FSTP ST(1): pop -> ST(0) = 9.
 * Identity: 1 * x = x.
 */
static float test_f7_fld1_fmul_fstp_reg(void) {
    float result;
    __asm__ volatile(
        /* build ST(0) = 9.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* FLD1 / FMUL / FSTP ST(1) */
        "fld1\n"
        "fmul %%st(1), %%st(0)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result));
    return result;
}

/* FILD m32 + FADD ST(0),ST(1) + FSTP m64
 * ST(0) = 1.5.  FILD [10] pushes 10.0.
 * FADD: ST(0) = 10+1.5 = 11.5.
 * FSTP m64: store 11.5, pop.
 */
static void test_f7_fild_m32_fadd_fstp_m64(double *dst) {
    int32_t ival = 10;
    double base = 1.5;
    __asm__ volatile(
        "fldl %2\n"       /* ST(0) = 1.5 */
        "fildl %1\n"      /* ST(0) = 10.0, ST(1) = 1.5 */
        "fadd %%st(1), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        : "=m"(*dst)
        : "m"(ival), "m"(base));
}

/* FLD m64 + FDIV ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 6.0.  FLD [3.0].
 * FDIV ST(0),ST(1): ST(0) = 3/6 = 0.5.
 * FSTP ST(1): pop -> ST(0) = 0.5.
 */
static float test_f7_fld_m64_fdiv_fstp_reg(void) {
    float result;
    double src = 3.0;
    __asm__ volatile(
        /* build ST(0) = 6.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n"
        /* FLD m64 / FDIV / FSTP ST(1) */
        "fldl %1\n"
        "fdiv %%st(1), %%st(0)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result)
        : "m"(src));
    return result;
}

/* FLD m64 (mem FADD) + FSTP m64
 * ST(0) = 2.0.  FLD [3.0].
 * FADD m64 [1.5]: ST(0) = 3+1.5 = 4.5 (memory-form arithmetic).
 * Wait -- memory-form FADD operates on ST(0) and memory.
 * After FLD: ST(0)=3.0, ST(1)=2.0.
 * FADD m64 [1.5]: ST(0) = 3.0 + 1.5 = 4.5.
 * FSTP ST(1): pop -> ST(0) = 4.5.
 *
 * NOTE: This tests the memory-operand arithmetic path of OPT-F7.
 */
static float test_f7_fld_m64_fadd_mem_fstp_reg(void) {
    float result;
    double fld_src = 3.0;
    double add_src = 1.5;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n" /* ST(0) = 2.0 (will be ST(1) after FLD) */
        "fldl %1\n"             /* ST(0) = 3.0, ST(1) = 2.0 */
        "faddl %2\n"            /* ST(0) = 3.0 + 1.5 = 4.5 */
        "fstp %%st(1)\n"        /* pop -> ST(0) = 4.5 */
        "fstps %0\n"
        : "=m"(result)
        : "m"(fld_src), "m"(add_src));
    return result;
}

/* ========================================================================= */
/* OPT-F8: FLD + FCOMP ST(1) + FNSTSW AX                                    */
/* ========================================================================= */

/* FLD m64 + FCOMP + FNSTSW: GT
 * ST(0) = 1.0.  FLD [3.0] -> ST(0)=3, ST(1)=1.
 * FCOMP ST(1): compare 3 vs 1 -> GT (CC=0x0000), pop.
 */
static uint16_t test_f8_fld_m64_gt(void) {
    double src = 3.0;
    __asm__ volatile(
        "fld1\n"        /* ST(0) = 1.0 */
        "fldl %0\n"     /* ST(0) = 3.0, ST(1) = 1.0 */
        "fcomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 + FCOMP + FNSTSW: LT
 * ST(0) = 3.0.  FLD [1.0] -> ST(0)=1, ST(1)=3.
 * FCOMP ST(1): compare 1 vs 3 -> LT (CC=0x0100), pop.
 */
static uint16_t test_f8_fld_m64_lt(void) {
    double src = 1.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n" /* ST(0) = 3.0 */
        "fldl %0\n"
        "fcomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 + FCOMP + FNSTSW: EQ
 * ST(0) = 5.0.  FLD [5.0] -> ST(0)=5, ST(1)=5.
 * FCOMP ST(1): compare 5 vs 5 -> EQ (CC=0x4000), pop.
 */
static uint16_t test_f8_fld_m64_eq(void) {
    double src = 5.0;
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

/* FLD m32 + FCOMP + FNSTSW: GT
 * ST(0) = 1.0.  FLD [7.0f] -> compare 7 vs 1 -> GT.
 */
static uint16_t test_f8_fld_m32_gt(void) {
    float src = 7.0f;
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

/* FLD ST(1) + FCOMP + FNSTSW: LT
 * Stack: ST(0)=5, ST(1)=2.  FLD ST(1) pushes 2 -> ST(0)=2, ST(1)=5, ST(2)=2.
 * FCOMP ST(1): compare 2 vs 5 -> LT (0x0100), pop -> ST(0)=5, ST(1)=2.
 */
static uint16_t test_f8_fld_reg_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n" /* 2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        /* ST(0)=5, ST(1)=2 */
        "fld %%st(1)\n"
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" "fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD1 + FCOMP + FNSTSW: EQ
 * ST(0) = 1.0.  FLD1 pushes 1.0 -> compare 1 vs 1 -> EQ.
 */
static uint16_t test_f8_fld1_eq(void) {
    __asm__ volatile(
        "fld1\n"   /* ST(0) = 1.0 */
        "fld1\n"   /* ST(0) = 1.0, ST(1) = 1.0 */
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLDZ + FCOMP + FNSTSW: LT (0 < 5)
 * ST(0) = 5.0.  FLDZ pushes 0 -> compare 0 vs 5 -> LT.
 */
static uint16_t test_f8_fldz_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fldz\n"
        "fcomp %%st(1)\n"
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 (NaN) + FCOMP + FNSTSW: Unordered
 * ST(0) = 1.0.  FLD [NaN] -> compare NaN vs 1 -> Unordered (0x4500).
 */
static uint16_t test_f8_nan_unordered(void) {
    double nan_val = __builtin_nan("");
    __asm__ volatile(
        "fld1\n"
        "fldl %0\n"
        "fcomp %%st(1)\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* ========================================================================= */
/* Entry point                                                               */
/* ========================================================================= */

int main(void) {
    printf("=== OPT-F7: FLD + non-popping ARITH + FSTP ===\n");
    check_f32("F7  FLD ST(1) + FADD + FSTP ST(1)     5+3=8",
              test_f7_fld_reg_fadd_fstp_reg(), 8.0f);
    {
        double dst = 0.0;
        test_f7_fld_m64_fmul_fstp_m64(&dst);
        check_f64("F7  FLD m64 + FMUL + FSTP m64         3*4=12",
                  dst, 12.0);
    }
    {
        float dst = 0.0f;
        test_f7_fld_m32_fadd_fstp_m32(&dst);
        check_f32("F7  FLD m32 + FADD + FSTP m32         1.5+2=3.5",
                  dst, 3.5f);
    }
    check_f32("F7  FLD m64 + FSUB + FSTP ST(1)       3-10=-7",
              test_f7_fld_m64_fsub_fstp_reg(), -7.0f);
    check_f32("F7  FLDZ + FADD + FSTP ST(1)          0+7=7",
              test_f7_fldz_fadd_fstp_reg(), 7.0f);
    check_f32("F7  FLD1 + FMUL + FSTP ST(1)          1*9=9",
              test_f7_fld1_fmul_fstp_reg(), 9.0f);
    {
        double dst = 0.0;
        test_f7_fild_m32_fadd_fstp_m64(&dst);
        check_f64("F7  FILD m32 + FADD + FSTP m64        10+1.5=11.5",
                  dst, 11.5);
    }
    check_f32("F7  FLD m64 + FDIV + FSTP ST(1)       3/6=0.5",
              test_f7_fld_m64_fdiv_fstp_reg(), 0.5f);
    check_f32("F7  FLD m64 + FADD mem + FSTP ST(1)   3+1.5=4.5",
              test_f7_fld_m64_fadd_mem_fstp_reg(), 4.5f);

    printf("\n=== OPT-F8: FLD + FCOMP + FNSTSW ===\n");
    check_u16("F8  FLD m64 + FCOMP + FNSTSW  GT      3>1=0x0000",
              test_f8_fld_m64_gt(), 0x0000);
    check_u16("F8  FLD m64 + FCOMP + FNSTSW  LT      1<3=0x0100",
              test_f8_fld_m64_lt(), 0x0100);
    check_u16("F8  FLD m64 + FCOMP + FNSTSW  EQ      5=5=0x4000",
              test_f8_fld_m64_eq(), 0x4000);
    check_u16("F8  FLD m32 + FCOMP + FNSTSW  GT      7>1=0x0000",
              test_f8_fld_m32_gt(), 0x0000);
    check_u16("F8  FLD ST(1) + FCOMP + FNSTSW LT     2<5=0x0100",
              test_f8_fld_reg_lt(), 0x0100);
    check_u16("F8  FLD1 + FCOMP + FNSTSW     EQ      1=1=0x4000",
              test_f8_fld1_eq(), 0x4000);
    check_u16("F8  FLDZ + FCOMP + FNSTSW     LT      0<5=0x0100",
              test_f8_fldz_lt(), 0x0100);
    check_u16("F8  FLD NaN + FCOMP + FNSTSW  UN      NaN=0x4500",
              test_f8_nan_unordered(), 0x4500);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
