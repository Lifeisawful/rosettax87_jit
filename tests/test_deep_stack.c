/*
 * test_deep_stack.c -- Validate x87 operations with deep register operands ST(2)–ST(7).
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_deep_stack test_deep_stack.c
 *
 * Covers operand depths not exercised by other tests:
 *   - FLD ST(3..6)
 *   - FXCH ST(3), ST(4)
 *   - FCOM/FCOMP ST(2..3) + FSTSW
 *   - FUCOM ST(2) (explicit, non-pp form)
 *   - FADD/FSUB/FMUL/FDIV ST(0),ST(i) with i=2,3
 *   - FADDP/FMULP ST(i),ST(0) with i=2,3
 *   - FCMOV ST(i) with i>1
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static uint64_t as_u64(double d) {
    uint64_t u;
    memcpy(&u, &d, 8);
    return u;
}
static uint32_t as_u32(float f) {
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

static void check_f64(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-60s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_f32(const char *name, float got, float expected) {
    if (as_u32(got) != as_u32(expected)) {
        printf("FAIL  %-60s  got=%.10g  expected=%.10g\n", name, (double)got, (double)expected);
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

/* x87 comparison result codes */
#define SW_GT  0x0000u   /* C3=0 C2=0 C0=0 */
#define SW_LT  0x0100u   /* C3=0 C2=0 C0=1 */
#define SW_EQ  0x4000u   /* C3=1 C2=0 C0=0 */
#define SW_UN  0x4500u   /* C3=1 C2=1 C0=1  (unordered) */

/* =========================================================================
 * Stack builder helpers
 *
 * Build values 1.0 through N onto the x87 stack by accumulating fld1 + faddp.
 * After calling push_N_values (inline asm), the stack looks like:
 *   ST(0)=1, ST(1)=2, ..., ST(N-1)=N   (deepest == largest integer)
 *
 * We push largest first so that ST(0) ends up with the smallest value,
 * making it easy to reason about which slot holds what.
 * ========================================================================= */

/* Push 5 values: ST(0)=1, ST(1)=2, ST(2)=3, ST(3)=4, ST(4)=5 */
#define PUSH_5_VALUES \
    "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5 */ \
    "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"                  /* 4 */ \
    "fld1\n fld1\n faddp\n fld1\n faddp\n"                                  /* 3 */ \
    "fld1\n fld1\n faddp\n"                                                  /* 2 */ \
    "fld1\n"                                                                 /* 1 */

/* Push 6 values: ST(0)=1, ST(1)=2, ..., ST(5)=6 */
#define PUSH_6_VALUES \
    "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 6 */ \
    PUSH_5_VALUES

/* Pop N values off the stack (without storing) */
#define POP1 "fstp %%st(0)\n"
#define POP2 POP1 POP1
#define POP3 POP2 POP1
#define POP4 POP3 POP1
#define POP5 POP4 POP1
#define POP6 POP5 POP1

/* =========================================================================
 * FLD ST(i) — deep register loads
 * ========================================================================= */

/* FLD ST(3): with ST(0)=1,ST(1)=2,ST(2)=3,ST(3)=4,ST(4)=5
 * FLD ST(3) pushes ST(3)=4 → ST(0)=4.
 */
static double test_fld_st3(void) {
    double result;
    __asm__ volatile(
        PUSH_5_VALUES
        "fld %%st(3)\n"     /* push copy of ST(3)=4 */
        "fstpl %0\n"        /* store ST(0)=4 */
        POP5                /* clean remaining 5 */
        : "=m"(result));
    return result;
}

/* FLD ST(4): ST(4)=5 → ST(0)=5 */
static double test_fld_st4(void) {
    double result;
    __asm__ volatile(
        PUSH_5_VALUES
        "fld %%st(4)\n"
        "fstpl %0\n"
        POP5
        : "=m"(result));
    return result;
}

/* FLD ST(5): need 6 values on stack; ST(5)=6 → ST(0)=6 */
static double test_fld_st5(void) {
    double result;
    __asm__ volatile(
        PUSH_6_VALUES
        "fld %%st(5)\n"
        "fstpl %0\n"
        POP6
        : "=m"(result));
    return result;
}

/* FLD ST(6): need 7 values; build 7 then FLD ST(6)=7 */
static double test_fld_st6(void) {
    double result;
    __asm__ volatile(
        /* push 7 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        PUSH_6_VALUES
        "fld %%st(6)\n"
        "fstpl %0\n"
        /* pop 7 */
        POP6 POP1
        : "=m"(result));
    return result;
}

/* =========================================================================
 * FXCH — deep exchange
 * ========================================================================= */

/* FXCH ST(3): with ST(0)=1,ST(1)=2,ST(2)=3,ST(3)=4,ST(4)=5
 * After FXCH ST(3): ST(0)=4, ST(3)=1.
 * Verify ST(0) and original ST(3) slot.
 */
static void test_fxch_st3(double *r0, double *r3) {
    __asm__ volatile(
        PUSH_5_VALUES
        "fxch %%st(3)\n"
        /* ST(0)=4, ST(1)=2, ST(2)=3, ST(3)=1, ST(4)=5 */
        "fstpl %0\n"        /* r0 = 4 */
        /* now ST(0)=2, ST(1)=3, ST(2)=1, ST(3)=5 */
        "fstp %%st(0)\n"    /* discard 2 */
        "fstp %%st(0)\n"    /* discard 3 */
        "fstpl %1\n"        /* r3 = 1 (was ST(3)) */
        "fstp %%st(0)\n"    /* discard 5 */
        : "=m"(*r0), "=m"(*r3));
}

/* FXCH ST(4): with ST(0)=1,...,ST(4)=5
 * After FXCH ST(4): ST(0)=5, ST(4)=1.
 */
static void test_fxch_st4(double *r0, double *r4) {
    __asm__ volatile(
        PUSH_5_VALUES
        "fxch %%st(4)\n"
        /* ST(0)=5, ST(1)=2, ST(2)=3, ST(3)=4, ST(4)=1 */
        "fstpl %0\n"        /* r0 = 5 */
        "fstp %%st(0)\n"    /* discard 2 */
        "fstp %%st(0)\n"    /* discard 3 */
        "fstp %%st(0)\n"    /* discard 4 */
        "fstpl %1\n"        /* r4 = 1 */
        : "=m"(*r0), "=m"(*r4));
}

/* =========================================================================
 * FCOM ST(i) + FSTSW — compare at depth
 * ========================================================================= */

/* FCOM ST(2): build ST(0)=a, ST(1)=unused, ST(2)=b.
 * Use: a=3, dummy=99, b=5  → 3 < 5 → LT (C0=1) = 0x0100
 */
static uint16_t test_fcom_st2_lt(void) {
    double a = 3.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"         /* ST(0)=b=5 */
        "fldl %2\n"         /* ST(0)=dummy=99, ST(1)=5 */
        "fldl %1\n"         /* ST(0)=a=3, ST(1)=99, ST(2)=5 */
        "fcom %%st(2)\n"    /* compare 3 vs ST(2)=5 → LT */
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FCOM ST(2): a=7, dummy=99, b=5 → 7 > 5 → GT (0x0000) */
static uint16_t test_fcom_st2_gt(void) {
    double a = 7.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fcom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FCOM ST(2): a=5, dummy=99, b=5 → EQ (0x4000) */
static uint16_t test_fcom_st2_eq(void) {
    double a = 5.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fcom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FCOMP ST(2): compare + pop. Use a=3, dummy=99, b=5 → LT.
 * After FCOMP, stack has 2 values left.
 */
static uint16_t test_fcomp_st2_lt(void) {
    double a = 3.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fcomp %%st(2)\n"   /* compare 3 vs 5, pop ST(0) */
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"   /* clean 2 remaining */
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FCOMP ST(3): compare ST(0) vs ST(3), pop. */
static uint16_t test_fcomp_st3_gt(void) {
    double a = 9.0, d1 = 1.0, d2 = 2.0, b = 4.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %4\n"         /* ST(0)=b=4  (will become ST(3)) */
        "fldl %3\n"         /* ST(0)=d2=2 */
        "fldl %2\n"         /* ST(0)=d1=1 */
        "fldl %1\n"         /* ST(0)=a=9  */
        "fcomp %%st(3)\n"   /* compare 9 vs ST(3)=4 → GT, pop */
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(d1), "m"(d2), "m"(b) : "ax");
    return sw;
}

/* =========================================================================
 * FUCOM ST(i) — explicit non-pp form (never tested elsewhere)
 * ========================================================================= */

/* FUCOM ST(2): a=3, dummy=99, b=5 → LT */
static uint16_t test_fucom_st2_lt(void) {
    double a = 3.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fucom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FUCOM ST(2): a=7, dummy=99, b=5 → GT */
static uint16_t test_fucom_st2_gt(void) {
    double a = 7.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fucom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FUCOM ST(2): a=5, dummy=99, b=5 → EQ */
static uint16_t test_fucom_st2_eq(void) {
    double a = 5.0, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fucom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* FUCOM ST(2): NaN → unordered (0x4500) */
static uint16_t test_fucom_st2_unordered(void) {
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    double a = nan_val, dummy = 99.0, b = 5.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %2\n"
        "fldl %1\n"
        "fucom %%st(2)\n"
        "fnstsw %%ax\n"
        "andw $0x4500, %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(dummy), "m"(b) : "ax");
    return sw;
}

/* =========================================================================
 * FADD/FSUB/FMUL/FDIV ST(0),ST(i) with i=2,3
 * ========================================================================= */

/* FADD ST(0),ST(2): ST(0)=1, ST(1)=2, ST(2)=3 → ST(0)=1+3=4 */
static double test_fadd_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* ST(0)=3 */
        "fld1\n fld1\n faddp\n"                    /* ST(0)=2, ST(1)=3 */
        "fld1\n"                                   /* ST(0)=1, ST(1)=2, ST(2)=3 */
        "fadd %%st(2), %%st(0)\n"                  /* ST(0)=1+3=4 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result));
    return result;
}

/* FSUB ST(0),ST(2): ST(0)=10, ST(1)=2, ST(2)=3 → ST(0)=10-3=7 */
static double test_fsub_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        /* build 10.0 at top */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* ST(0)=10, ST(1)=2, ST(2)=3 */
        "fsub %%st(2), %%st(0)\n"                  /* 10-3=7 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result));
    return result;
}

/* FMUL ST(0),ST(2): ST(0)=2, ST(1)=dummy, ST(2)=3 → ST(0)=2*3=6 */
static double test_fmul_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n"                                   /* dummy=1 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        /* ST(0)=2, ST(1)=1, ST(2)=3 */
        "fmul %%st(2), %%st(0)\n"                  /* 2*3=6 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result));
    return result;
}

/* FDIV ST(0),ST(2): ST(0)=6, ST(1)=dummy, ST(2)=2 → ST(0)=6/2=3 */
static double test_fdiv_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n"                                   /* dummy=1 */
        /* build 6.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* ST(0)=6, ST(1)=1, ST(2)=2 */
        "fdiv %%st(2), %%st(0)\n"                  /* 6/2=3 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result));
    return result;
}

/* FADD ST(0),ST(3): need 4 values; ST(0)=1, ST(3)=4 → ST(0)=1+4=5 */
static double test_fadd_st3(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"                  /* 3 */
        "fld1\n fld1\n faddp\n"                                  /* 2 */
        "fld1\n"                                                 /* 1 */
        /* ST(0)=1, ST(1)=2, ST(2)=3, ST(3)=4 */
        "fadd %%st(3), %%st(0)\n"                               /* 1+4=5 */
        "fstpl %0\n"
        POP3
        : "=m"(result));
    return result;
}

/* =========================================================================
 * FADDP/FMULP ST(i),ST(0) with i=2,3
 * ========================================================================= */

/* FADDP ST(2),ST(0): ST(0)=1, ST(1)=2, ST(2)=3.
 * ST(2) = ST(2)+ST(0) = 3+1 = 4, pop ST(0).
 * After pop: ST(0)=2, ST(1)=4.
 */
static double test_faddp_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n"                                   /* 1 */
        /* ST(0)=1, ST(1)=2, ST(2)=3 */
        "faddp %%st(0), %%st(2)\n"                 /* ST(2)=4, pop → ST(0)=2, ST(1)=4 */
        "fstp %%st(0)\n"                           /* discard 2 */
        "fstpl %0\n"                               /* result = 4 */
        : "=m"(result));
    return result;
}

/* FMULP ST(2),ST(0): ST(0)=3, ST(1)=dummy, ST(2)=4.
 * ST(2) = 4*3 = 12, pop.
 * After pop: ST(0)=dummy, ST(1)=12.
 */
static double test_fmulp_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4 */
        "fld1\n"                                                 /* dummy=1 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"                  /* 3 */
        /* ST(0)=3, ST(1)=1, ST(2)=4 */
        "fmulp %%st(0), %%st(2)\n"                              /* ST(2)=12, pop */
        "fstp %%st(0)\n"                                        /* discard dummy */
        "fstpl %0\n"                                            /* result = 12 */
        : "=m"(result));
    return result;
}

/* FADDP ST(3),ST(0): ST(0)=2, ..., ST(3)=5.
 * ST(3) = 5+2 = 7, pop ST(0).
 * After pop: ST(0)=..., ST(2)=7.
 */
static double test_faddp_st3(void) {
    double result;
    __asm__ volatile(
        /* build ST(0)=2, ST(1)=d1, ST(2)=d2, ST(3)=5 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5 */
        "fld1\n"                                                                /* d2=1 */
        "fld1\n"                                                                /* d1=1 */
        "fld1\n fld1\n faddp\n"                                                 /* 2 */
        /* ST(0)=2, ST(1)=1, ST(2)=1, ST(3)=5 */
        "faddp %%st(0), %%st(3)\n"  /* ST(3)=7, pop */
        /* now ST(0)=1, ST(1)=1, ST(2)=7 */
        "fstp %%st(0)\n"            /* discard */
        "fstp %%st(0)\n"            /* discard */
        "fstpl %0\n"                /* result=7 */
        : "=m"(result));
    return result;
}

/* =========================================================================
 * FCMOV ST(i) with i>1
 *
 * FCMOV uses NZCV flags set by prior integer/comparison instructions.
 * We use XOR EAX,EAX (ZF=1,CF=0) before FCMOVE to trigger the move,
 * and STC (CF=1) before FCMOVB.
 *
 * Note: FCMOV only supports ST(0)←ST(i) form; we test i=2 and i=3.
 * ========================================================================= */

/* FCMOVB ST(2): CF=1 set by STC.
 * Stack: ST(0)=old=1, ST(1)=dummy=2, ST(2)=src=3.
 * After FCMOVB: ST(0)=3 (moved from ST(2)).
 */
static double test_fcmovb_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 = src */
        "fld1\n fld1\n faddp\n"                    /* 2 = dummy */
        "fld1\n"                                   /* 1 = old ST(0) */
        "stc\n"                                    /* CF=1 */
        "fcmovb %%st(2), %%st(0)\n"               /* ST(0) ← ST(2)=3 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result) : : "cc");
    return result;
}

/* FCMOVNB ST(2): CF=0 (cleared by CLC).
 * Stack: ST(0)=old=1, ST(1)=dummy=2, ST(2)=src=3.
 * CF=0 → condition true for FCMOVNB → ST(0)=3.
 */
static double test_fcmovnb_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n"                                   /* 1 */
        "clc\n"                                    /* CF=0 */
        "fcmovnb %%st(2), %%st(0)\n"              /* ST(0) ← ST(2)=3 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result) : : "cc");
    return result;
}

/* FCMOVB ST(3): CF=1 set by STC; ST(3)=4 → ST(0)=4. */
static double test_fcmovb_st3(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4 = src */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"                  /* 3 = dummy */
        "fld1\n fld1\n faddp\n"                                  /* 2 = dummy */
        "fld1\n"                                                 /* 1 = old */
        "stc\n"
        "fcmovb %%st(3), %%st(0)\n"               /* ST(0) ← ST(3)=4 */
        "fstpl %0\n"
        POP3
        : "=m"(result) : : "cc");
    return result;
}

/* FCMOVE ST(2): ZF=1 (set by XOR EAX,EAX) → move.
 * ST(2)=3 → ST(0)=3.
 */
static double test_fcmove_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n"                                   /* 1 */
        "xorl %%eax, %%eax\n"                     /* ZF=1 */
        "fcmove %%st(2), %%st(0)\n"               /* ST(0) ← ST(2)=3 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result) : : "eax", "cc");
    return result;
}

/* FCMOVNE ST(2): ZF=0 (set by OR EAX,1 which clears ZF) → move.
 * ST(2)=3 → ST(0)=3.
 */
static double test_fcmovne_st2(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"   /* 3 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n"                                   /* 1 */
        "xorl %%eax, %%eax\n orl $1, %%eax\n"    /* ZF=0 */
        "fcmovne %%st(2), %%st(0)\n"              /* ST(0) ← ST(2)=3 */
        "fstpl %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(result) : : "eax", "cc");
    return result;
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void) {
    /* FLD deep register */
    check_f64("fld ST(3)",        test_fld_st3(), 4.0);
    check_f64("fld ST(4)",        test_fld_st4(), 5.0);
    check_f64("fld ST(5)",        test_fld_st5(), 6.0);
    check_f64("fld ST(6)",        test_fld_st6(), 7.0);

    /* FXCH deep */
    {
        double r0, r3;
        test_fxch_st3(&r0, &r3);
        check_f64("fxch ST(3) → new ST(0)", r0, 4.0);
        check_f64("fxch ST(3) → new ST(3)", r3, 1.0);
    }
    {
        double r0, r4;
        test_fxch_st4(&r0, &r4);
        check_f64("fxch ST(4) → new ST(0)", r0, 5.0);
        check_f64("fxch ST(4) → new ST(4)", r4, 1.0);
    }

    /* FCOM ST(2) */
    check_u16("fcom ST(2) LT",    test_fcom_st2_lt(), SW_LT);
    check_u16("fcom ST(2) GT",    test_fcom_st2_gt(), SW_GT);
    check_u16("fcom ST(2) EQ",    test_fcom_st2_eq(), SW_EQ);

    /* FCOMP ST(2), ST(3) */
    check_u16("fcomp ST(2) LT",   test_fcomp_st2_lt(), SW_LT);
    check_u16("fcomp ST(3) GT",   test_fcomp_st3_gt(), SW_GT);

    /* FUCOM ST(2) — explicit non-pp form */
    check_u16("fucom ST(2) LT",   test_fucom_st2_lt(), SW_LT);
    check_u16("fucom ST(2) GT",   test_fucom_st2_gt(), SW_GT);
    check_u16("fucom ST(2) EQ",   test_fucom_st2_eq(), SW_EQ);
    check_u16("fucom ST(2) UN",   test_fucom_st2_unordered(), SW_UN);

    /* FADD/FSUB/FMUL/FDIV ST(0),ST(i) */
    check_f64("fadd ST(0),ST(2)",  test_fadd_st2(), 4.0);
    check_f64("fsub ST(0),ST(2)",  test_fsub_st2(), 7.0);
    check_f64("fmul ST(0),ST(2)",  test_fmul_st2(), 6.0);
    check_f64("fdiv ST(0),ST(2)",  test_fdiv_st2(), 3.0);
    check_f64("fadd ST(0),ST(3)",  test_fadd_st3(), 5.0);

    /* FADDP/FMULP ST(i),ST(0) */
    check_f64("faddp ST(2),ST(0)", test_faddp_st2(), 4.0);
    check_f64("fmulp ST(2),ST(0)", test_fmulp_st2(), 12.0);
    check_f64("faddp ST(3),ST(0)", test_faddp_st3(), 7.0);

    /* FCMOV ST(i>1) */
    check_f64("fcmovb  ST(2) CF=1", test_fcmovb_st2(),  3.0);
    check_f64("fcmovnb ST(2) CF=0", test_fcmovnb_st2(), 3.0);
    check_f64("fcmovb  ST(3) CF=1", test_fcmovb_st3(),  4.0);
    check_f64("fcmove  ST(2) ZF=1", test_fcmove_st2(),  3.0);
    check_f64("fcmovne ST(2) ZF=0", test_fcmovne_st2(), 3.0);

    if (failures == 0)
        printf("All tests passed.\n");
    else
        printf("%d test(s) FAILED.\n", failures);
    return failures ? 1 : 0;
}
