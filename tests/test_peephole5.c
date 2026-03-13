/*
 * test_peephole5.c -- validate double-pop compare peephole fusion patterns
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_peephole5 test_peephole5.c
 *
 * Change A: extend fcom_fstsw to handle FCOMPP/FUCOMPP (double-pop).
 *   FCOMPP/FUCOMPP + FNSTSW AX
 *
 * Change B: FLD + FCOMPP/FUCOMPP + FNSTSW AX (OPT-F9)
 *   Push + double-pop = net one pop.
 *
 * Change C: FLD + FLD + FCOMPP/FUCOMPP [+ FNSTSW AX] (OPT-F10)
 *   Two pushes + two pops = net zero stack change.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

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
 * Change A: FCOMPP/FUCOMPP + FNSTSW AX
 * =========================================================================
 *
 * Stack setup: push two values, compare with fcompp, read SW.
 * After fcompp the stack has TWO fewer items (double-pop).
 */

/* FCOMPP: ST(0)=3.0 > ST(1)=1.0 → GT: CC=0x0000 */
static uint16_t test_a_fcompp_gt(void) {
    __asm__ volatile(
        "fld1\n"                                    /* ST(0)=1.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"     /* ST(0)=3.0, ST(1)=1.0 */
        "fcompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FCOMPP: ST(0)=1.0 < ST(1)=3.0 → LT: CC=0x0100 */
static uint16_t test_a_fcompp_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"     /* ST(0)=3.0 */
        "fld1\n"                                    /* ST(0)=1.0, ST(1)=3.0 */
        "fcompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FCOMPP: ST(0)=2.0 == ST(1)=2.0 → EQ: CC=0x4000 */
static uint16_t test_a_fcompp_eq(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"                     /* ST(0)=2.0 */
        "fld1\n fld1\n faddp\n"                     /* ST(0)=2.0, ST(1)=2.0 */
        "fcompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FUCOMPP: ST(0)=5.0 > ST(1)=2.0 → GT: CC=0x0000 */
static uint16_t test_a_fucompp_gt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"                     /* 2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fucompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FUCOMPP: ST(0)=1.0 < ST(1)=4.0 → LT: CC=0x0100 */
static uint16_t test_a_fucompp_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4.0 */
        "fld1\n"                                                  /* 1.0 */
        "fucompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FUCOMPP: ST(0)==ST(1) → EQ: CC=0x4000 */
static uint16_t test_a_fucompp_eq(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"     /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"     /* 3.0 */
        "fucompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FUCOMPP: NaN vs 1.0 → Unordered: CC=0x4500 */
static uint16_t test_a_fucompp_un(void) {
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;  /* quiet NaN */
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fld1\n"        /* ST(0)=1.0 */
        "fldl %0\n"     /* ST(0)=NaN, ST(1)=1.0 */
        "fucompp\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* Stack integrity after double-pop: push 3 values, fcompp, check one remains */
static double test_a_stack_integrity(void) {
    double result;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=4.0 */
        "fld1\n"                                                  /* ST(0)=1.0, ST(1)=4.0 */
        "fld1\n fld1\n faddp\n"                                   /* ST(0)=2.0, ST(1)=1.0, ST(2)=4.0 */
        "fcompp\n"          /* compare 2.0 vs 1.0, double-pop → ST(0)=4.0 */
        "fstpl %0\n"
        : "=m"(result));
    return result;
}

/* =========================================================================
 * Change B: FLD + FCOMPP/FUCOMPP + FNSTSW AX (OPT-F9)
 * =========================================================================
 *
 * FLD pushes, FUCOMPP double-pops. Net: one pop (old ST(1) is consumed).
 * After fusion: ST(0) = what was ST(1) before FLD.
 */

/* FLD m64 [3.0] + FUCOMPP (vs old ST(0)=1.0) → GT: CC=0x0000 */
static uint16_t test_b_fld_fucompp_gt(void) {
    double src = 3.0;
    __asm__ volatile(
        "fld1\n"        /* ST(0)=1.0 */
        "fldl %0\n"     /* ST(0)=3.0, ST(1)=1.0 */
        "fucompp\n"     /* compare 3.0 vs 1.0, double-pop → stack empty */
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* FLD m64 [1.0] + FUCOMPP (vs old ST(0)=3.0) → LT: CC=0x0100 */
static uint16_t test_b_fld_fucompp_lt(void) {
    double src = 1.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=3.0 */
        "fldl %0\n"     /* ST(0)=1.0, ST(1)=3.0 */
        "fucompp\n"
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* FLD m64 [5.0] + FUCOMPP (vs old ST(0)=5.0) → EQ: CC=0x4000 */
static uint16_t test_b_fld_fucompp_eq(void) {
    double src = 5.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fldl %0\n"
        "fucompp\n"
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* FLD NaN + FUCOMPP → Unordered: CC=0x4500 */
static uint16_t test_b_fld_fucompp_un(void) {
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fld1\n"
        "fldl %0\n"
        "fucompp\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* FLD m64 [2.0] + FCOMPP (ordered, vs old ST(0)=4.0) → LT: CC=0x0100 */
static uint16_t test_b_fld_fcompp_lt(void) {
    double src = 2.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4.0 */
        "fldl %0\n"
        "fcompp\n"
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* Stack integrity: push extra value, fld+fucompp, then check extra value survives */
static double test_b_stack_integrity(void) {
    double result;
    double val = 3.0;
    __asm__ volatile(
        /* push sentinel 7.0 at bottom */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=7.0 */
        "fld1\n"        /* ST(0)=1.0, ST(1)=7.0 */
        "fldl %1\n"     /* ST(0)=3.0, ST(1)=1.0, ST(2)=7.0 */
        "fucompp\n"     /* compare 3.0 vs 1.0, double-pop → ST(0)=7.0 */
        "fstpl %0\n"
        : "=m"(result)
        : "m"(val));
    return result;
}

/* =========================================================================
 * Change C: FLD + FLD + FCOMPP/FUCOMPP [+ FNSTSW AX] (OPT-F10)
 * =========================================================================
 *
 * Net zero stack change. val2 (second FLD) is ST(0), val1 (first FLD) is ST(1).
 * FUCOMPP compares val2 vs val1.
 */

/* FLD [1.0] + FLD [3.0] + FUCOMPP + FNSTSW: 3>1 → GT: CC=0x0000 */
static uint16_t test_c_fld_fld_fucompp_fstsw_gt(void) {
    double val1 = 1.0;
    double val2 = 3.0;
    __asm__ volatile(
        "fldl %0\n"     /* push 1.0 */
        "fldl %1\n"     /* push 3.0 → ST(0)=3.0, ST(1)=1.0 */
        "fucompp\n"     /* compare 3.0 vs 1.0, double-pop */
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD [3.0] + FLD [1.0] + FUCOMPP + FNSTSW: 1<3 → LT: CC=0x0100 */
static uint16_t test_c_fld_fld_fucompp_fstsw_lt(void) {
    double val1 = 3.0;
    double val2 = 1.0;
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD [4.0] + FLD [4.0] + FUCOMPP + FNSTSW: EQ: CC=0x4000 */
static uint16_t test_c_fld_fld_fucompp_fstsw_eq(void) {
    double val1 = 4.0;
    double val2 = 4.0;
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD [1.0] + FLD [NaN] + FUCOMPP + FNSTSW: Unordered: CC=0x4500 */
static uint16_t test_c_fld_fld_fucompp_fstsw_un(void) {
    double val1 = 1.0;
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fucompp\n"
        :
        : "m"(val1), "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* 3-instruction form (no FSTSW): FLD + FLD + FUCOMPP, check SW separately */
static uint16_t test_c_fld_fld_fucompp_3instr_gt(void) {
    double val1 = 2.0;
    double val2 = 6.0;
    __asm__ volatile(
        "fldl %0\n"     /* push val1=2.0 */
        "fldl %1\n"     /* push val2=6.0 */
        "fucompp\n"     /* 6.0 vs 2.0 → GT */
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);  /* separate fnstsw after the 3-instr fusion */
    return cc;
}

/* FLD+FLD+FCOMPP (ordered)+FSTSW: 2.0 < 5.0 → LT */
static uint16_t test_c_fld_fld_fcompp_fstsw_lt(void) {
    double val1 = 5.0;
    double val2 = 2.0;
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fcompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* Stack integrity: push a sentinel, then FLD+FLD+FUCOMPP, verify sentinel survives */
static double test_c_stack_integrity(void) {
    double result;
    double val1 = 2.0;
    double val2 = 5.0;
    __asm__ volatile(
        /* sentinel = 9.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 9.0 */
        "fldl %1\n"     /* push val1=2.0 */
        "fldl %2\n"     /* push val2=5.0 → ST(0)=5, ST(1)=2, ST(2)=9 */
        "fucompp\n"     /* compare 5 vs 2, double-pop → ST(0)=9.0 */
        "fstpl %0\n"
        : "=m"(result)
        : "m"(val1), "m"(val2));
    return result;
}

/* =========================================================================
 * Change A: additional tests
 * ========================================================================= */

/* FCOMPP with NaN: ordered compare with NaN still sets C0=C2=C3=1 → 0x4500 */
static uint16_t test_a_fcompp_un(void) {
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fld1\n"        /* ST(0)=1.0 */
        "fldl %0\n"     /* ST(0)=NaN, ST(1)=1.0 */
        "fcompp\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* Deep stack: 3 values below the two being compared; all must survive. */
static double test_a_deep_stack(void) {
    double r1, r2, r3;
    __asm__ volatile(
        /* push 3 sentinels: 11.0, 13.0, 17.0 (bottom to top) */
        /* build 11.0: fld1+fld1+faddp=2, then 9 x (fld1+faddp) */
        "fld1\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n"  /* ST(0)=11.0 */
        /* build 13.0: same pattern, 11 x (fld1+faddp) after initial */
        "fld1\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=13.0 */
        /* build 17.0: 15 x (fld1+faddp) after initial */
        "fld1\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=17.0 */
        /* push the two values to compare */
        "fld1\n fld1\n faddp\n"  /* ST(0)=2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=3.0, ST(1)=2.0 */
        "fcompp\n"        /* compare 3 vs 2, double-pop → ST(0)=17, ST(1)=13, ST(2)=11 */
        "fstpl %0\n"      /* pop 17.0 */
        "fstpl %1\n"      /* pop 13.0 */
        "fstpl %2\n"      /* pop 11.0 */
        : "=m"(r1), "=m"(r2), "=m"(r3));
    /* verify order and values */
    if (r1 != 17.0 || r2 != 13.0 || r3 != 11.0) {
        printf("FAIL  A  deep stack sentinels: got %.1f %.1f %.1f expected 17 13 11\n",
               r1, r2, r3);
        failures++;
        return 0.0;
    }
    return r1;
}

/* =========================================================================
 * Change B: additional FLD source variant tests
 * ========================================================================= */

/* FLD m32 [3.0f] + FUCOMPP vs old ST(0)=1.0 → GT: CC=0x0000 */
static uint16_t test_b_fld_m32_gt(void) {
    float src = 3.0f;
    __asm__ volatile(
        "fld1\n"        /* ST(0)=1.0 */
        "flds %0\n"     /* ST(0)=3.0, ST(1)=1.0 */
        "fucompp\n"
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* FLD ST(1) + FUCOMPP vs old ST(0) → LT: 2.0 < 5.0
 * Stack: ST(0)=5.0, ST(1)=2.0.
 * FLD ST(1) loads 2.0 → compare 2.0 vs old_ST(0)=5.0 → LT.
 */
static uint16_t test_b_fld_reg_lt(void) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"     /* ST(0)=2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* ST(0)=5.0, ST(1)=2.0 */
        "fld %%st(1)\n"   /* push 2.0 → ST(0)=2.0, ST(1)=5.0, ST(2)=2.0 */
        "fucompp\n"       /* compare 2.0 vs 5.0 → LT; double-pop → ST(0)=2.0 */
        :);
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLDZ + FUCOMPP vs old ST(0)=1.0 → LT: 0 < 1 → CC=0x0100 */
static uint16_t test_b_fldz_lt(void) {
    __asm__ volatile(
        "fld1\n"    /* ST(0)=1.0 */
        "fldz\n"    /* ST(0)=0.0, ST(1)=1.0 */
        "fucompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FLD1 + FUCOMPP vs old ST(0)=1.0 → EQ: CC=0x4000 */
static uint16_t test_b_fld1_eq(void) {
    __asm__ volatile(
        "fld1\n"    /* ST(0)=1.0 */
        "fld1\n"    /* ST(0)=1.0, ST(1)=1.0 */
        "fucompp\n"
        :);
    READ_SW(cc);
    return cc;
}

/* FILD m32 [5] + FUCOMPP vs old ST(0)=2.0 → GT: CC=0x0000 */
static uint16_t test_b_fild_m32_gt(void) {
    int32_t ival = 5;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* ST(0)=2.0 */
        "fildl %0\n"             /* ST(0)=5.0, ST(1)=2.0 */
        "fucompp\n"
        :
        : "m"(ival));
    READ_SW(cc);
    return cc;
}

/* FLD NaN + FCOMPP (ordered) → still unordered: CC=0x4500 */
static uint16_t test_b_fcompp_nan(void) {
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fld1\n"
        "fldl %0\n"
        "fcompp\n"
        :
        : "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* FLD m64 [3.0] + FCOMPP (ordered) vs old ST(0)=1.0 → GT: CC=0x0000 */
static uint16_t test_b_fcompp_gt(void) {
    double src = 3.0;
    __asm__ volatile(
        "fld1\n"        /* ST(0)=1.0 */
        "fldl %0\n"     /* ST(0)=3.0, ST(1)=1.0 */
        "fcompp\n"
        :
        : "m"(src));
    READ_SW(cc);
    return cc;
}

/* =========================================================================
 * Change C: additional FLD source combinations
 * ========================================================================= */

/* FLD m32 [3.0f]=val1 + FLD m64 [1.0]=val2 + FUCOMPP + FSTSW
 * After pushes: ST(0)=1.0, ST(1)=3.0. val2=1 < val1=3 → LT: CC=0x0100 */
static uint16_t test_c_m32_m64_lt(void) {
    float  val1 = 3.0f;
    double val2 = 1.0;
    __asm__ volatile(
        "flds %0\n"
        "fldl %1\n"
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD ST(1)=val1 + FLD m64 [big]=val2 + FUCOMPP + FSTSW
 * Stack: ST(0)=2.0, ST(1)=0.5.
 * FLD ST(1) loads 0.5 → val1=0.5. FLD m64 [10.0] → val2=10.0.
 * After pushes: ST(0)=10.0, ST(1)=0.5. val2=10>val1=0.5 → GT: CC=0x0000 */
static uint16_t test_c_reg_m64_gt(void) {
    double val2 = 10.0;
    __asm__ volatile(
        /* build stack: ST(0)=2.0, ST(1)=0.5 */
        "fld1\n fld1\n faddp\n"              /* 2.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4.0... */
        /* Actually build 0.5 = 1.0/2.0 */
        "fld1\n"                             /* 1.0 on top of 2.0 */
        "fld1\n fld1\n faddp\n"              /* 2.0 */
        "fdivp\n"                            /* 0.5; ST(0)=0.5, ST(1)=2.0 */
        "fld %%st(1)\n"                      /* push ST(1)=val1=0.5: ST(0)=0.5, ST(1)=0.5, ST(2)=2.0 */
        "fldl %0\n"                          /* push val2=10.0 */
        "fucompp\n"                          /* compare 10.0 vs 0.5 → GT; double-pop → ST(0)=0.5, ST(1)=2.0 */
        :
        : "m"(val2));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLDZ=val1 + FLD m64 [2.0]=val2 + FUCOMPP + FSTSW
 * After pushes: ST(0)=2.0, ST(1)=0.0. val2=2>val1=0 → GT: CC=0x0000 */
static uint16_t test_c_fldz_m64_gt(void) {
    double val2 = 2.0;
    __asm__ volatile(
        "fldz\n"
        "fldl %0\n"
        "fucompp\n"
        :
        : "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD1=val1 + FLD m64 [0.5]=val2 + FUCOMPP + FSTSW
 * After pushes: ST(0)=0.5, ST(1)=1.0. val2=0.5<val1=1 → LT: CC=0x0100 */
static uint16_t test_c_fld1_m64_lt(void) {
    double val2 = 0.5;
    __asm__ volatile(
        "fld1\n"
        "fldl %0\n"
        "fucompp\n"
        :
        : "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FILD m32 [3]=val1 + FLD m64 [3.0]=val2 + FUCOMPP + FSTSW
 * After pushes: ST(0)=3.0, ST(1)=3.0. val2==val1 → EQ: CC=0x4000 */
static uint16_t test_c_fild_m64_eq(void) {
    int32_t val1 = 3;
    double  val2 = 3.0;
    __asm__ volatile(
        "fildl %0\n"
        "fldl  %1\n"
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD m64 + FLD m64 + FCOMPP 3-instr form (no FSTSW): 1.0 < 4.0 → LT */
static uint16_t test_c_fcompp_3instr_lt(void) {
    double val1 = 4.0;
    double val2 = 1.0;
    __asm__ volatile(
        "fldl %0\n"   /* push val1=4.0 */
        "fldl %1\n"   /* push val2=1.0 → ST(0)=1, ST(1)=4 */
        "fcompp\n"    /* 1.0 vs 4.0 → LT */
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD m64 + FLD m64 + FCOMPP + FSTSW GT: 5.0 > 2.0 → CC=0x0000 */
static uint16_t test_c_fcompp_gt(void) {
    double val1 = 2.0;
    double val2 = 5.0;
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fcompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD m64 + FLD NaN + FCOMPP + FSTSW: ordered compare with NaN → 0x4500 */
static uint16_t test_c_fcompp_nan(void) {
    double val1 = 1.0;
    double nan_val;
    uint64_t nan_bits = 0x7FF8000000000000ULL;
    memcpy(&nan_val, &nan_bits, 8);
    __asm__ volatile(
        "fldl %0\n"
        "fldl %1\n"
        "fcompp\n"
        :
        : "m"(val1), "m"(nan_val));
    READ_SW(cc);
    return cc;
}

/* =========================================================================
 * Change C: additional source-combo tests (fld_fld_fucompp)
 * =========================================================================
 *
 * Tests for kFldReg as second FLD, kFldReg(depth=0) as first FLD,
 * kFildM16, kFildM64, kFldConst64, 3-instr stack integrity, consecutive fusions.
 *
 * FLD ST(i) as val2 (second FLD) executes after val1 has been pushed, so
 * ST(i) at that point = pre-fusion ST(i-1).  The fusion adjusts reg_depth
 * by -1 to account for this.
 */

/* FLD m64 [5.0]=val1 + FLD ST(0)=val2 (pre-push ST(0)=2.0) + FUCOMPP + FSTSW
 * val2=2.0, val1=5.0 → val2<val1 → LT=0x0100 */
static uint16_t test_c_m64_reg_lt(void) {
    double val1 = 5.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* push 2.0 → ST(0)=2.0 */
        "fldl %0\n"              /* val1=5.0: ST(0)=5.0, ST(1)=2.0 */
        "fld %%st(1)\n"          /* val2=FLD ST(1)=2.0; ST(0)=2.0, ST(1)=5.0, ST(2)=2.0 */
        "fucompp\n"              /* compare 2.0 vs 5.0 → LT; double-pop → ST(0)=2.0 */
        :
        : "m"(val1));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 [1.0]=val1 + FLD ST(0)=val2 (pre-push ST(0)=2.0) + FUCOMPP + FSTSW
 * val2=2.0, val1=1.0 → val2>val1 → GT=0x0000 */
static uint16_t test_c_m64_reg_gt(void) {
    double val1 = 1.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* push 2.0 → ST(0)=2.0 */
        "fldl %0\n"              /* val1=1.0: ST(0)=1.0, ST(1)=2.0 */
        "fld %%st(1)\n"          /* val2=FLD ST(1)=2.0; ST(0)=2.0, ST(1)=1.0, ST(2)=2.0 */
        "fucompp\n"              /* compare 2.0 vs 1.0 → GT; double-pop → ST(0)=2.0 */
        :
        : "m"(val1));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD m64 [6.0]=val1 + FLD ST(1)=val2 + FUCOMPP + FSTSW
 * Pre-fusion stack: ST(0)=5.0, ST(1)=99.0 (sentinel).
 * After fld1 push (6.0): ST(0)=6.0, ST(1)=5.0, ST(2)=99.0.
 * fld ST(1) → val2=ST(1)=5.0; compare 5.0 vs 6.0 → LT=0x0100.
 * Bug: loads pre-fusion ST(1)=99.0 → compare 99>6 → GT=0x0000 → FAIL. */
static uint16_t test_c_m64_reg_deep(void) {
    double fld1_val = 6.0;
    __asm__ volatile(
        /* build 99.0 */
        "fld1\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* ST(0)=99.0; push 5.0 → pre-fusion ST(0)=5.0, ST(1)=99.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* fuse: fldl[6.0] + fld ST(1) + fucompp */
        "fldl %0\n"         /* push 6.0: ST(0)=6.0, ST(1)=5.0, ST(2)=99.0 */
        "fld %%st(1)\n"     /* fld ST(1)=5.0: ST(0)=5.0, ST(1)=6.0, ST(2)=5.0, ST(3)=99 */
        "fucompp\n"         /* compare ST(0)=5.0 vs ST(1)=6.0 → LT; double-pop */
        :
        : "m"(fld1_val));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FLD ST(0)=val1 (pre-push ST(0)=3.0) + FLD m64 [1.0]=val2 + FUCOMPP + FSTSW
 * val1=3.0, val2=1.0 → val2<val1 → LT=0x0100 */
static uint16_t test_c_reg0_m64_lt(void) {
    double val2 = 1.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* push 3.0 → ST(0)=3.0 */
        "fld %%st(0)\n"                           /* val1=FLD ST(0)=3.0; ST(0)=3.0, ST(1)=3.0 */
        "fldl %0\n"                               /* val2=1.0; ST(0)=1.0, ST(1)=3.0, ST(2)=3.0 */
        "fucompp\n"                               /* compare 1.0 vs 3.0 → LT; double-pop → ST(0)=3.0 */
        :
        : "m"(val2));
    READ_SW(cc);
    __asm__ volatile("fstp %%st(0)\n" ::: "st");
    return cc;
}

/* FILD m16 [2]=val1 + FLD m64 [1.0]=val2 + FUCOMPP + FSTSW
 * val1=2.0, val2=1.0 → val2<val1 → LT=0x0100 */
static uint16_t test_c_fild16_m64_lt(void) {
    int16_t val1 = 2;
    double  val2 = 1.0;
    __asm__ volatile(
        "filds %0\n"   /* val1=2.0 */
        "fldl  %1\n"   /* val2=1.0; ST(0)=1.0, ST(1)=2.0 */
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FILD m64 [5]=val1 + FLD m64 [9.0]=val2 + FUCOMPP + FSTSW
 * val1=5.0, val2=9.0 → val2>val1 → GT=0x0000 */
static uint16_t test_c_fild64_m64_gt(void) {
    int64_t val1 = 5;
    double  val2 = 9.0;
    __asm__ volatile(
        "fildll %0\n"  /* val1=5.0 */
        "fldl   %1\n"  /* val2=9.0; ST(0)=9.0, ST(1)=5.0 */
        "fucompp\n"
        :
        : "m"(val1), "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLDPI=val1 (~3.14159) + FLD m64 [4.0]=val2 + FUCOMPP + FSTSW
 * val2=4.0 > val1=pi → GT=0x0000 */
static uint16_t test_c_fldpi_m64_gt(void) {
    double val2 = 4.0;
    __asm__ volatile(
        "fldpi\n"     /* val1=pi */
        "fldl %0\n"   /* val2=4.0; ST(0)=4.0, ST(1)=pi */
        "fucompp\n"
        :
        : "m"(val2));
    READ_SW(cc);
    return cc;
}

/* FLD m64 [7.0] + FLD m64 [3.0] + FCOMPP 3-instr form; stack must be net-zero.
 * Push sentinel 99.0 before, verify it survives as ST(0) after fusion. */
static double test_c_3instr_stack(void) {
    double sentinel = 99.0;
    double r;
    __asm__ volatile(
        "fldl %1\n"              /* push sentinel=99.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n"  /* push 7.0 = val1 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* push 3.0 = val2; ST(0)=3, ST(1)=7, ST(2)=99 */
        "fcompp\n"               /* compare 3 vs 7 → LT; double-pop → ST(0)=99 */
        "fstpl %0\n"             /* pop 99.0 */
        : "=m"(r)
        : "m"(sentinel));
    return r;
}

/* Two consecutive FLD+FLD+FUCOMPP+FSTSW fusions.
 * First: FLD m64 [5.0] + FLD m64 [2.0] + FUCOMPP + FSTSW → GT (5>2 but val2=2<val1=5 → LT... wait)
 * Semantics: after pushes ST(0)=val2=second FLD, ST(1)=val1=first FLD.
 * First fusion: val1=5.0, val2=2.0 → val2<val1 → LT=0x0100.
 * Second fusion: val1=1.0, val2=3.0 → val2>val1 → GT=0x0000. */
static uint16_t test_c_consecutive(void) {
    double a1 = 5.0, a2 = 2.0;
    double b1 = 1.0, b2 = 3.0;
    __asm__ volatile(
        "fldl %0\n fldl %1\n fucompp\n"  /* first: 2<5 → LT; W_ax = 0x0100; net zero */
        :
        : "m"(a1), "m"(a2));
    READ_SW(cc1);
    __asm__ volatile(
        "fldl %0\n fldl %1\n fucompp\n"  /* second: 3>1 → GT; W_ax = 0x0000; net zero */
        :
        : "m"(b1), "m"(b2));
    READ_SW(cc2);
    /* first must be LT, second must be GT */
    if (cc1 != 0x0100) {
        printf("FAIL  C  consecutive: first fusion got=0x%04x expected=0x0100\n", cc1);
        failures++;
    }
    return cc2;
}

/* =========================================================================
 * Entry point
 * ========================================================================= */

static uint64_t as_u64(double d) {
    uint64_t u;
    memcpy(&u, &d, 8);
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

int main(void) {
    printf("=== Change A: FCOMPP/FUCOMPP + FNSTSW AX ===\n");
    check_u16("A  FCOMPP  GT  3>1=0x0000",   test_a_fcompp_gt(),    0x0000);
    check_u16("A  FCOMPP  LT  1<3=0x0100",   test_a_fcompp_lt(),    0x0100);
    check_u16("A  FCOMPP  EQ  2=2=0x4000",   test_a_fcompp_eq(),    0x4000);
    check_u16("A  FUCOMPP GT  5>2=0x0000",   test_a_fucompp_gt(),   0x0000);
    check_u16("A  FUCOMPP LT  1<4=0x0100",   test_a_fucompp_lt(),   0x0100);
    check_u16("A  FUCOMPP EQ  3=3=0x4000",   test_a_fucompp_eq(),   0x4000);
    check_u16("A  FUCOMPP UN  NaN=0x4500",   test_a_fucompp_un(),   0x4500);
    check_f64("A  stack integrity after fcompp  ST(0)=4.0",
              test_a_stack_integrity(), 4.0);
    check_u16("A  FCOMPP  UN  NaN=0x4500",       test_a_fcompp_un(),    0x4500);
    check_f64("A  deep stack sentinels survive fcompp  top=17.0",
              test_a_deep_stack(), 17.0);

    printf("\n=== Change B: FLD + FCOMPP/FUCOMPP + FNSTSW AX (OPT-F9) ===\n");
    check_u16("B  FLD+FUCOMPP GT   3>1=0x0000",  test_b_fld_fucompp_gt(), 0x0000);
    check_u16("B  FLD+FUCOMPP LT   1<3=0x0100",  test_b_fld_fucompp_lt(), 0x0100);
    check_u16("B  FLD+FUCOMPP EQ   5=5=0x4000",  test_b_fld_fucompp_eq(), 0x4000);
    check_u16("B  FLD+FUCOMPP UN   NaN=0x4500",  test_b_fld_fucompp_un(), 0x4500);
    check_u16("B  FLD+FCOMPP  LT   2<4=0x0100",  test_b_fld_fcompp_lt(),  0x0100);
    check_f64("B  stack integrity after fld+fucompp  ST(0)=7.0",
              test_b_stack_integrity(), 7.0);
    check_u16("B  FLD m32 + FUCOMPP  GT  3>1=0x0000",    test_b_fld_m32_gt(),   0x0000);
    check_u16("B  FLD ST(1) + FUCOMPP LT  2<5=0x0100",   test_b_fld_reg_lt(),   0x0100);
    check_u16("B  FLDZ + FUCOMPP     LT  0<1=0x0100",    test_b_fldz_lt(),      0x0100);
    check_u16("B  FLD1 + FUCOMPP     EQ  1=1=0x4000",    test_b_fld1_eq(),      0x4000);
    check_u16("B  FILD m32 + FUCOMPP GT  5>2=0x0000",    test_b_fild_m32_gt(),  0x0000);
    check_u16("B  FLD NaN + FCOMPP   UN  NaN=0x4500",    test_b_fcompp_nan(),   0x4500);
    check_u16("B  FLD m64 + FCOMPP   GT  3>1=0x0000",    test_b_fcompp_gt(),    0x0000);

    printf("\n=== Change C: FLD+FLD+FUCOMPP[+FNSTSW] (OPT-F10) ===\n");
    check_u16("C  FLD+FLD+FUCOMPP+FNSTSW GT  3>1=0x0000",
              test_c_fld_fld_fucompp_fstsw_gt(), 0x0000);
    check_u16("C  FLD+FLD+FUCOMPP+FNSTSW LT  1<3=0x0100",
              test_c_fld_fld_fucompp_fstsw_lt(), 0x0100);
    check_u16("C  FLD+FLD+FUCOMPP+FNSTSW EQ  4=4=0x4000",
              test_c_fld_fld_fucompp_fstsw_eq(), 0x4000);
    check_u16("C  FLD+FLD+FUCOMPP+FNSTSW UN  NaN=0x4500",
              test_c_fld_fld_fucompp_fstsw_un(), 0x4500);
    check_u16("C  FLD+FLD+FUCOMPP 3-instr GT  6>2=0x0000",
              test_c_fld_fld_fucompp_3instr_gt(), 0x0000);
    check_u16("C  FLD+FLD+FCOMPP+FNSTSW  LT  2<5=0x0100",
              test_c_fld_fld_fcompp_fstsw_lt(), 0x0100);
    check_f64("C  stack integrity after fld+fld+fucompp  ST(0)=9.0",
              test_c_stack_integrity(), 9.0);
    check_u16("C  FLD m32+m64 FUCOMPP LT  1<3=0x0100",    test_c_m32_m64_lt(),       0x0100);
    check_u16("C  FLD reg+m64 FUCOMPP GT  10>0.5=0x0000",  test_c_reg_m64_gt(),       0x0000);
    check_u16("C  FLDZ+m64   FUCOMPP GT  2>0=0x0000",      test_c_fldz_m64_gt(),      0x0000);
    check_u16("C  FLD1+m64   FUCOMPP LT  0.5<1=0x0100",    test_c_fld1_m64_lt(),      0x0100);
    check_u16("C  FILD+m64   FUCOMPP EQ  3=3=0x4000",      test_c_fild_m64_eq(),      0x4000);
    check_u16("C  FLD+FLD+FCOMPP 3-instr LT  1<4=0x0100",  test_c_fcompp_3instr_lt(), 0x0100);
    check_u16("C  FLD+FLD+FCOMPP+FSTSW GT  5>2=0x0000",    test_c_fcompp_gt(),        0x0000);
    check_u16("C  FLD+FLD NaN+FCOMPP   UN  NaN=0x4500",    test_c_fcompp_nan(),       0x4500);

    printf("\n=== Change C: additional source combos (fld_fld_fucompp) ===\n");
    check_u16("C  m64+ST(1) LT  2<5=0x0100",               test_c_m64_reg_lt(),       0x0100);
    check_u16("C  m64+ST(1) GT  2>1=0x0000",               test_c_m64_reg_gt(),       0x0000);
    check_u16("C  m64+ST(1) deep LT  5<6=0x0100",          test_c_m64_reg_deep(),     0x0100);
    check_u16("C  ST(0)+m64 LT  1<3=0x0100",               test_c_reg0_m64_lt(),      0x0100);
    check_u16("C  FILD16+m64 LT  1<2=0x0100",              test_c_fild16_m64_lt(),    0x0100);
    check_u16("C  FILD64+m64 GT  9>5=0x0000",              test_c_fild64_m64_gt(),    0x0000);
    check_u16("C  FLDPI+m64  GT  4>pi=0x0000",             test_c_fldpi_m64_gt(),     0x0000);
    check_f64("C  3-instr stack net-zero  ST(0)=99.0",     test_c_3instr_stack(),     99.0);
    check_u16("C  consecutive 2nd GT  3>1=0x0000",         test_c_consecutive(),      0x0000);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
