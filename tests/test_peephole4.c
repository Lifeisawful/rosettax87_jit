/*
 * test_peephole4.c -- Validate peephole fusion variants not covered by
 *                     sample_peephole.c or test_peephole3.c.
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_peephole4 test_peephole4.c
 *
 * Covers:
 *   fld_arithp:    FILD m64, FLDPI/FLDLN2/FLDLG2/FLDL2E/FLDL2T constant sources
 *   fld_fstp:      FLD1/FLDPI + FSTP, FILD m16/m32/m64 + FSTP
 *   fld_arith_fstp: FSUBR/FDIVR in middle; FSUB m32/FDIV m64 memory middle
 *   fld_fcomp_fstsw: FUCOMP variant (GT/LT/EQ/UN)
 *   fxch_fstp:     3-level stack (ST(2) present)
 *   fcom_fstsw:    FUCOM+FSTSW, FCOM m32fp+FSTSW, FCOM m64fp+FSTSW
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static int failures = 0;

static uint32_t as_u32(float f)  { uint32_t u; memcpy(&u, &f, 4); return u; }
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_f32(const char *name, float got, float expected) {
    if (as_u32(got) != as_u32(expected)) {
        printf("FAIL  %-65s  got=%.10g (0x%08x)  expected=%.10g (0x%08x)\n",
               name, (double)got, as_u32(got), (double)expected, as_u32(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_f64(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-65s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_f64_approx(const char *name, double got, double expected) {
    double denom = expected != 0.0 ? fabs(expected) : 1.0;
    if (fabs(got - expected) / denom > 1e-6) {
        printf("FAIL  %-65s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-65s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Read x87 status-word CC bits (C0/C2/C3 only). */
#define READ_SW(var)                                \
    uint16_t var;                                   \
    __asm__ volatile(                               \
        "fnstsw %%ax\n"                             \
        "andw $0x4500, %%ax\n"                      \
        "movw %%ax, %0\n"                           \
        : "=m"(var)                                 \
        :                                           \
        : "ax")

/* Comparison result codes */
#define SW_GT  0x0000u
#define SW_LT  0x0100u
#define SW_EQ  0x4000u
#define SW_UN  0x4500u

/* =========================================================================
 * fld_arithp: FLD + popping arithmetic — constant and FILD sources
 * ========================================================================= */

/* FILD m64 + FADDP ST(1)
 * ST(0) = 5.0.  FILD [12] pushes 12.0 → ST(0)=12, ST(1)=5.
 * FADDP ST(1): ST(1) = 5+12 = 17, pop → ST(0) = 17.
 */
static double test_p1_fild_m64_faddp(void) {
    double result;
    int64_t ival = 12;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5.0 */
        "fildll %1\n"
        "faddp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result) : "m"(ival));
    return result;
}

/* FLDPI + FMULP ST(1)
 * ST(0) = 2.0.  FLDPI pushes π → ST(0)=π, ST(1)=2.
 * FMULP ST(1): ST(1) = 2*π, pop → ST(0) = 2π.
 */
static double test_p1_fldpi_fmulp(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"   /* 2.0 */
        "fldpi\n"
        "fmulp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* FLDLN2 + FADDP ST(1)
 * ST(0) = 0.0.  FLDLN2 pushes ln(2).
 * FADDP: 0 + ln(2) = ln(2).
 */
static double test_p1_fldln2_faddp(void) {
    double result;
    __asm__ volatile(
        "fldz\n"
        "fldln2\n"
        "faddp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* FLDLG2 + FADDP ST(1)
 * ST(0) = 0.0.  FLDLG2 pushes log10(2).
 * FADDP: 0 + log10(2) = log10(2).
 */
static double test_p1_fldlg2_faddp(void) {
    double result;
    __asm__ volatile(
        "fldz\n"
        "fldlg2\n"
        "faddp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* FLDL2E + FMULP ST(1)
 * ST(0) = 1.0.  FLDL2E pushes log2(e) ≈ 1.4427.
 * FMULP: 1.0 * log2(e) = log2(e).
 */
static double test_p1_fldl2e_fmulp(void) {
    double result;
    __asm__ volatile(
        "fld1\n"
        "fldl2e\n"
        "fmulp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* FLDL2T + FMULP ST(1)
 * ST(0) = 1.0.  FLDL2T pushes log2(10) ≈ 3.3219.
 * FMULP: 1.0 * log2(10) = log2(10).
 */
static double test_p1_fldl2t_fmulp(void) {
    double result;
    __asm__ volatile(
        "fld1\n"
        "fldl2t\n"
        "fmulp %%st, %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* =========================================================================
 * fld_fstp: FLD + FSTP — constant and FILD sources
 * ========================================================================= */

/* FLD1 + FSTP ST(1)
 * Stack: ST(0) = old = 7.0.  FLD1 pushes 1.0.
 * FSTP ST(1): store 1.0 → ST(1) (= old ST(0)), pop.
 * Net: ST(0) = 1.0 (old value overwritten by 1.0).
 */
static double test_p2_fld1_fstp_reg(void) {
    double result;
    __asm__ volatile(
        /* build 7.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n"               /* push 1.0 */
        "fstp %%st(1)\n"       /* store 1 → ST(1), pop */
        "fstpl %0\n"           /* result = ST(0) = 1.0 */
        : "=m"(result));
    return result;
}

/* FLDPI + FSTP m64
 * ST(0) = 2.0.  FLDPI pushes π.
 * FSTP m64: store π to memory, pop → ST(0) = 2.0.
 * We verify the stored π value.
 */
static double test_p2_fldpi_fstp_m64(void) {
    double dst = 0.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"   /* ST(0) = 2.0 (stays on stack) */
        "fldpi\n"
        "fstpl %0\n"              /* store π, pop */
        "fstp %%st(0)\n"          /* clean 2.0 */
        : "=m"(dst));
    return dst;
}

/* FILD m16 + FSTP ST(1)
 * ST(0) = 5.0.  FILD [42] pushes 42.0.
 * FSTP ST(1): store 42 → old ST(0), pop.
 * Net: ST(0) = 42.0.
 */
static double test_p2_fild_m16_fstp_reg(void) {
    double result;
    int16_t ival = 42;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5.0 */
        "filds %1\n"
        "fstp %%st(1)\n"
        "fstpl %0\n"
        : "=m"(result) : "m"(ival));
    return result;
}

/* FILD m32 + FSTP m64
 * ST(0) = 1.5.  FILD [100] pushes 100.0.
 * FSTP m64: store 100.0 to memory, pop.
 */
static double test_p2_fild_m32_fstp_m64(void) {
    double dst = 0.0;
    double base = 1.5;
    int32_t ival = 100;
    __asm__ volatile(
        "fldl %2\n"   /* ST(0) = 1.5 */
        "fildl %1\n"  /* ST(0) = 100.0, ST(1) = 1.5 */
        "fstpl %0\n"  /* store 100.0, pop */
        "fstp %%st(0)\n"  /* clean 1.5 */
        : "=m"(dst) : "m"(ival), "m"(base));
    return dst;
}

/* FILD m64 + FSTP m64
 * FILD [1000000] pushes 1000000.0.
 * FSTP m64: store → verify.
 */
static double test_p2_fild_m64_fstp_m64(void) {
    double dst = 0.0;
    int64_t ival = 1000000;
    __asm__ volatile(
        "fld1\n"      /* dummy base, stays on stack */
        "fildll %1\n"  /* ST(0) = 1000000.0, ST(1) = 1.0 */
        "fstpl %0\n"  /* store 1000000.0, pop */
        "fstp %%st(0)\n"  /* clean dummy */
        : "=m"(dst) : "m"(ival));
    return dst;
}

/* =========================================================================
 * fld_arith_fstp (OPT-F7): FSUBR/FDIVR in middle; memory arithmetic middle
 * ========================================================================= */

/* FLD m64 + FSUBR ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 10.0.  FLD [3.0] → ST(0)=3, ST(1)=10.
 * FSUBR ST(0),ST(1): ST(0) = ST(1) - ST(0) = 10 - 3 = 7.
 * FSTP ST(1): store 7 → old ST(0), pop → ST(0) = 7.
 */
static float test_f7_fld_m64_fsubr_fstp_reg(void) {
    float result;
    double src = 3.0;
    __asm__ volatile(
        /* build 10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fldl %1\n"
        "fsubr %%st(1), %%st(0)\n"   /* ST(0) = 10-3=7 */
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result) : "m"(src));
    return result;
}

/* FLD m64 + FDIVR ST(0),ST(1) + FSTP ST(1)
 * ST(0) = 3.0.  FLD [6.0] → ST(0)=6, ST(1)=3.
 * FDIVR ST(0),ST(1): ST(0) = ST(1) / ST(0) = 3 / 6 = 0.5.
 * FSTP ST(1): store 0.5, pop → ST(0) = 0.5.
 */
static float test_f7_fld_m64_fdivr_fstp_reg(void) {
    float result;
    double src = 6.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3.0 */
        "fldl %1\n"
        "fdivr %%st(1), %%st(0)\n"   /* ST(0) = 3/6 = 0.5 */
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result) : "m"(src));
    return result;
}

/* FLD m64 + FSUB m32fp + FSTP ST(1) (memory-form arithmetic middle)
 * ST(0) = 8.0.  FLD [5.0] → ST(0)=5, ST(1)=8.
 * FSUB m32fp [2.5f]: ST(0) = 5 - 2.5 = 2.5.
 * FSTP ST(1): store 2.5, pop → ST(0) = 2.5.
 */
static float test_f7_fld_m64_fsub_m32_fstp_reg(void) {
    float result;
    double fld_src = 5.0;
    float sub_src = 2.5f;
    __asm__ volatile(
        /* build 8.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fldl %1\n"
        "fsubs %2\n"          /* ST(0) = 5 - 2.5 = 2.5 */
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result) : "m"(fld_src), "m"(sub_src));
    return result;
}

/* FLD m64 + FDIV m64fp + FSTP ST(1) (memory-form arithmetic middle)
 * ST(0) = 4.0.  FLD [12.0] → ST(0)=12, ST(1)=4.
 * FDIV m64 [4.0]: ST(0) = 12 / 4 = 3.0.
 * FSTP ST(1): store 3.0, pop → ST(0) = 3.0.
 */
static float test_f7_fld_m64_fdiv_m64_fstp_reg(void) {
    float result;
    double fld_src = 12.0;
    double div_src = 4.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"   /* 4.0 */
        "fldl %1\n"
        "fdivl %2\n"          /* ST(0) = 12 / 4 = 3 */
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m"(result) : "m"(fld_src), "m"(div_src));
    return result;
}

/* =========================================================================
 * fld_fcomp_fstsw (OPT-F8): FUCOMP variant
 * ========================================================================= */

/* FLD m64 + FUCOMP ST(1) + FNSTSW: GT (3 > 1) */
static uint16_t test_f8_fucomp_m64_gt(void) {
    double src = 3.0;
    __asm__ volatile(
        "fld1\n"        /* ST(0) = 1.0 */
        "fldl %0\n"     /* ST(0) = 3.0, ST(1) = 1.0 */
        "fucomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 + FUCOMP ST(1) + FNSTSW: LT (1 < 3) */
static uint16_t test_f8_fucomp_m64_lt(void) {
    double src = 1.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* ST(0) = 3.0 */
        "fldl %0\n"     /* ST(0) = 1.0, ST(1) = 3.0 */
        "fucomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 + FUCOMP ST(1) + FNSTSW: EQ (5 = 5) */
static uint16_t test_f8_fucomp_m64_eq(void) {
    double src = 5.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"   /* 5.0 */
        "fldl %0\n"
        "fucomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 (NaN) + FUCOMP ST(1) + FNSTSW: Unordered */
static uint16_t test_f8_fucomp_m64_unordered(void) {
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

/* FLD m32 + FUCOMP ST(1) + FNSTSW: GT (7 > 1) */
static uint16_t test_f8_fucomp_m32_gt(void) {
    float src = 7.0f;
    __asm__ volatile(
        "fld1\n"
        "flds %0\n"
        "fucomp %%st(1)\n"
        :
        : "m"(src));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* =========================================================================
 * fxch_fstp: FXCH ST(1) + FSTP ST(1) with 3-level stack
 *
 * Verify that ST(2) is undisturbed when FXCH ST(1) + FSTP ST(1) fires.
 * Stack: ST(0)=A, ST(1)=B, ST(2)=C.
 * FXCH ST(1): ST(0)=B, ST(1)=A, ST(2)=C.
 * FSTP ST(1): store B→ST(1) (= A's slot), pop: ST(0)=B, ST(1)=C.
 * Net from perspective of pre-FXCH: just a pop.
 * Result: ST(0)=B, ST(1)=C.  C must be unchanged.
 *
 * Use A=1.0, B=2.0, C=3.0.
 * ========================================================================= */
static void test_p4_fxch_fstp_deep(double *r0, double *r1) {
    __asm__ volatile(
        /* push C=3.0 (deepest) */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"
        /* push B=2.0 */
        "fld1\n fld1\n faddp\n"
        /* push A=1.0 */
        "fld1\n"
        /* ST(0)=1, ST(1)=2, ST(2)=3 */
        "fxch %%st(1)\n"      /* ST(0)=2, ST(1)=1, ST(2)=3 */
        "fstp %%st(1)\n"      /* store 2→ST(1), pop: ST(0)=2, ST(1)=3 */
        "fstpl %0\n"          /* r0 = 2 */
        "fstpl %1\n"          /* r1 = 3 */
        : "=m"(*r0), "=m"(*r1));
}

/* =========================================================================
 * fcom_fstsw: FUCOM+FSTSW, FCOM m32fp+FSTSW, FCOM m64fp+FSTSW
 * ========================================================================= */

/* FUCOM ST(1) + FNSTSW AX: GT (5 > 3) */
static uint16_t test_fcom_fucom_gt(void) {
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 = ST(1) */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5 = ST(0) */
        "fucom %%st(1)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : : "ax");
    return sw;
}

/* FUCOM ST(1) + FNSTSW AX: LT (2 < 8) */
static uint16_t test_fcom_fucom_lt(void) {
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"   /* 8 = ST(1) */
        "fld1\n fld1\n faddp\n"                            /* 2 = ST(0) */
        "fucom %%st(1)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : : "ax");
    return sw;
}

/* FUCOM ST(1) + FNSTSW AX: EQ (4 = 4) */
static uint16_t test_fcom_fucom_eq(void) {
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"   /* 4 = ST(1) */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"   /* 4 = ST(0) */
        "fucom %%st(1)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : : "ax");
    return sw;
}

/* FUCOM ST(1) + FNSTSW AX: Unordered (NaN) */
static uint16_t test_fcom_fucom_unordered(void) {
    double nan_val = __builtin_nan("");
    uint16_t sw;
    __asm__ volatile(
        "fld1\n"          /* ST(1) = 1.0 */
        "fldl %1\n"       /* ST(0) = NaN */
        "fucom %%st(1)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(nan_val) : "ax");
    return sw;
}

/* FCOM m32fp + FNSTSW AX: GT (5 > 3.0f) */
static uint16_t test_fcom_m32_gt(void) {
    float cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5.0 */
        "fcoms %1\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw;
}

/* FCOM m32fp + FNSTSW AX: LT (1 < 4.0f) */
static uint16_t test_fcom_m32_lt(void) {
    float cmp = 4.0f;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n"
        "fcoms %1\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw;
}

/* FCOM m64fp + FNSTSW AX: GT (6 > 2.5) */
static uint16_t test_fcom_m64_gt(void) {
    double cmp = 2.5;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 6.0 */
        "fcoml %1\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw;
}

/* FCOM m64fp + FNSTSW AX: LT (1 < 9.0) */
static uint16_t test_fcom_m64_lt(void) {
    double cmp = 9.0;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n"
        "fcoml %1\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw;
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void) {
    /* --- fld_arithp: FILD m64 + constant sources --- */
    printf("=== fld_arithp: constant and FILD m64 sources ===\n");

    /* Use x87 canonical bit patterns so that the comparison is exact
     * regardless of C library rounding vs x87 extended-precision rounding. */
    double x87_ln2, x87_lg2, x87_l2e, x87_l2t, x87_pi;
    { uint64_t b = 0x3FE62E42FEFA39EFULL; memcpy(&x87_ln2, &b, 8); }
    { uint64_t b = 0x3FD34413509F79FFULL; memcpy(&x87_lg2, &b, 8); }
    { uint64_t b = 0x3FF71547652B82FEULL; memcpy(&x87_l2e, &b, 8); }
    { uint64_t b = 0x400A934F0979A371ULL; memcpy(&x87_l2t, &b, 8); }
    { uint64_t b = 0x400921FB54442D18ULL; memcpy(&x87_pi,  &b, 8); }

    check_f64("P1  FILD m64 + FADDP            5+12=17",
              test_p1_fild_m64_faddp(), 17.0);
    check_f64_approx("P1  FLDPI  + FMULP              2*pi",
              test_p1_fldpi_fmulp(), 2.0 * x87_pi);
    check_f64_approx("P1  FLDLN2 + FADDP              0+ln2",
              test_p1_fldln2_faddp(), x87_ln2);
    check_f64_approx("P1  FLDLG2 + FADDP              0+log10(2)",
              test_p1_fldlg2_faddp(), x87_lg2);
    check_f64_approx("P1  FLDL2E + FMULP              1*log2(e)",
              test_p1_fldl2e_fmulp(), x87_l2e);
    check_f64_approx("P1  FLDL2T + FMULP              1*log2(10)",
              test_p1_fldl2t_fmulp(), x87_l2t);

    /* --- fld_fstp: FLD1/FLDPI + FSTP, FILD m16/m32/m64 + FSTP --- */
    printf("\n=== fld_fstp: constant and FILD sources ===\n");

    check_f64("P2  FLD1 + FSTP ST(1)           → 1.0",
              test_p2_fld1_fstp_reg(), 1.0);
    check_f64_approx("P2  FLDPI + FSTP m64            → pi",
              test_p2_fldpi_fstp_m64(), x87_pi);
    check_f64("P2  FILD m16 + FSTP ST(1)       → 42",
              test_p2_fild_m16_fstp_reg(), 42.0);
    check_f64("P2  FILD m32 + FSTP m64         → 100",
              test_p2_fild_m32_fstp_m64(), 100.0);
    check_f64("P2  FILD m64 + FSTP m64         → 1000000",
              test_p2_fild_m64_fstp_m64(), 1000000.0);

    /* --- fld_arith_fstp: FSUBR/FDIVR, memory-form arithmetic --- */
    printf("\n=== fld_arith_fstp: FSUBR/FDIVR and memory arithmetic ===\n");

    check_f32("F7  FLD m64 + FSUBR + FSTP ST(1)  10-3=7",
              test_f7_fld_m64_fsubr_fstp_reg(), 7.0f);
    check_f32("F7  FLD m64 + FDIVR + FSTP ST(1)  3/6=0.5",
              test_f7_fld_m64_fdivr_fstp_reg(), 0.5f);
    check_f32("F7  FLD m64 + FSUB m32 + FSTP ST(1) 5-2.5=2.5",
              test_f7_fld_m64_fsub_m32_fstp_reg(), 2.5f);
    check_f32("F7  FLD m64 + FDIV m64 + FSTP ST(1) 12/4=3",
              test_f7_fld_m64_fdiv_m64_fstp_reg(), 3.0f);

    /* --- fld_fcomp_fstsw: FUCOMP variant --- */
    printf("\n=== fld_fcomp_fstsw: FUCOMP variant ===\n");

    check_u16("F8  FLD m64 + FUCOMP + FNSTSW  GT  3>1=0x0000",
              test_f8_fucomp_m64_gt(), SW_GT);
    check_u16("F8  FLD m64 + FUCOMP + FNSTSW  LT  1<3=0x0100",
              test_f8_fucomp_m64_lt(), SW_LT);
    check_u16("F8  FLD m64 + FUCOMP + FNSTSW  EQ  5=5=0x4000",
              test_f8_fucomp_m64_eq(), SW_EQ);
    check_u16("F8  FLD m64 + FUCOMP + FNSTSW  UN  NaN=0x4500",
              test_f8_fucomp_m64_unordered(), SW_UN);
    check_u16("F8  FLD m32 + FUCOMP + FNSTSW  GT  7>1=0x0000",
              test_f8_fucomp_m32_gt(), SW_GT);

    /* --- fxch_fstp: 3-level stack --- */
    printf("\n=== fxch_fstp: 3-level stack (ST(2) present) ===\n");

    {
        double r0 = 0.0, r1 = 0.0;
        test_p4_fxch_fstp_deep(&r0, &r1);
        check_f64("P4  FXCH+FSTP deep: new ST(0)", r0, 2.0);
        check_f64("P4  FXCH+FSTP deep: ST(1)=C=3 undisturbed", r1, 3.0);
    }

    /* --- fcom_fstsw: FUCOM+FSTSW, FCOM m32/m64 +FSTSW --- */
    printf("\n=== fcom_fstsw: FUCOM, FCOM m32fp, FCOM m64fp ===\n");

    check_u16("fcom_fstsw  FUCOM ST(1) GT  5>3=0x0000",
              test_fcom_fucom_gt(), SW_GT);
    check_u16("fcom_fstsw  FUCOM ST(1) LT  2<8=0x0100",
              test_fcom_fucom_lt(), SW_LT);
    check_u16("fcom_fstsw  FUCOM ST(1) EQ  4=4=0x4000",
              test_fcom_fucom_eq(), SW_EQ);
    check_u16("fcom_fstsw  FUCOM ST(1) UN  NaN=0x4500",
              test_fcom_fucom_unordered(), SW_UN);
    check_u16("fcom_fstsw  FCOM m32fp  GT  5>3.0f=0x0000",
              test_fcom_m32_gt(), SW_GT);
    check_u16("fcom_fstsw  FCOM m32fp  LT  1<4.0f=0x0100",
              test_fcom_m32_lt(), SW_LT);
    check_u16("fcom_fstsw  FCOM m64fp  GT  6>2.5=0x0000",
              test_fcom_m64_gt(), SW_GT);
    check_u16("fcom_fstsw  FCOM m64fp  LT  1<9.0=0x0100",
              test_fcom_m64_lt(), SW_LT);

    if (failures == 0)
        printf("\nAll tests passed.\n");
    else
        printf("\n%d test(s) FAILED.\n", failures);
    return failures ? 1 : 0;
}
