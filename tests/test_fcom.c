/*
 * sample_fcom.c — exercise every FCOM / FCOMP / FCOMPP variant.
 *
 * Each test function performs one x87 compare instruction and returns the
 * masked x87 status-word CC bits as a uint16_t:
 *
 *   result & 0x4500
 *         bit 14 = C3   (equal / above-or-equal)
 *         bit 10 = C2   (unordered / parity)
 *         bit  8 = C0   (below / carry)
 *
 * Expected values:
 *   ST(0) > src   0x0000    (C3=0, C2=0, C0=0)
 *   ST(0) < src   0x0100    (C3=0, C2=0, C0=1)
 *   ST(0) = src   0x4000    (C3=1, C2=0, C0=0)
 *   Unordered     0x4500    (C3=1, C2=1, C0=1)
 *
 * Compile (x86 / i386 target, e.g. under Rosetta):
 *   gcc -O0 -m32 -o sample_fcom sample_fcom.c && ./sample_fcom
 */

#include <stdio.h>
#include <stdint.h>

/* Read x87 status-word CC bits after a compare. */
#define READ_SW(var)                                   \
    uint16_t var;                                      \
    __asm__ volatile (                                 \
        "fnstsw %%ax\n"                                \
        "andw $0x4500, %%ax\n"                         \
        "movw %%ax, %0\n"                              \
        : "=m" (var) : : "ax"                          \
    )

/* ---------------------------------------------------------------------------
 * Test value constants.
 * NaN is produced with __builtin_nanf / __builtin_nan, which are safe and
 * do not rely on FP exceptions or undefined arithmetic.
 * --------------------------------------------------------------------------- */
static const float  F_GT_ST0 = 3.0f,  F_GT_SRC = 1.0f;   /* ST(0) > src */
static const float  F_LT_ST0 = 1.0f,  F_LT_SRC = 3.0f;   /* ST(0) < src */
static const float  F_EQ_ST0 = 2.0f,  F_EQ_SRC = 2.0f;   /* ST(0) = src */
static const float  F_UN_ST0 = 0.0f;                       /* NaN loaded below */

static const double D_GT_ST0 = 3.0,   D_GT_SRC = 1.0;
static const double D_LT_ST0 = 1.0,   D_LT_SRC = 3.0;
static const double D_EQ_ST0 = 2.0,   D_EQ_SRC = 2.0;

/* ===========================================================================
 * FCOM ST(i)  —  D8 D0+i  —  compare ST(0) with ST(i), no pop
 * Setup: fldl src -> ST(0)=src; fldl st0 -> ST(0)=st0_val, ST(1)=src
 * Teardown: two fstp to empty the stack.
 * =========================================================================== */
#ifndef TEST_FCOM_STI
#  define TEST_FCOM_STI 1
#endif

#if TEST_FCOM_STI
/* FCOM ST(1)  D8 D1  — 3.0 > 1.0 — expected 0x0000 */
static uint16_t test_fcom_sti_gt(void)
{
    double st0 = D_GT_ST0, src = D_GT_SRC;
    __asm__ volatile (
        "fldl %1\n"              /* ST(0) = src = 1.0               */
        "fldl %0\n"              /* ST(0) = 3.0, ST(1) = 1.0        */
        "fcom %%st(1)\n"         /* compare ST(0)=3.0 with ST(1)=1.0 */
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" "fstp %%st(0)\n" : : : "st");
    return cc;
}

/* FCOM ST(1)  D8 D1  — 1.0 < 3.0 — expected 0x0100 */
static uint16_t test_fcom_sti_lt(void)
{
    double st0 = D_LT_ST0, src = D_LT_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcom %%st(1)\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" "fstp %%st(0)\n" : : : "st");
    return cc;
}

/* FCOM ST(1)  D8 D1  — 2.0 = 2.0 — expected 0x4000 */
static uint16_t test_fcom_sti_eq(void)
{
    double st0 = D_EQ_ST0, src = D_EQ_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcom %%st(1)\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" "fstp %%st(0)\n" : : : "st");
    return cc;
}

/* FCOM ST(1)  D8 D1  — NaN vs 1.0 — expected 0x4500 */
static uint16_t test_fcom_sti_un(void)
{
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcom %%st(1)\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" "fstp %%st(0)\n" : : : "st");
    return cc;
}
#endif /* TEST_FCOM_STI */

/* ===========================================================================
 * FCOM m32fp  —  D8 /2  —  compare ST(0) with float32 memory, no pop
 * =========================================================================== */
#ifndef TEST_FCOM_M32FP
#  define TEST_FCOM_M32FP 1
#endif

#if TEST_FCOM_M32FP
/* D8 /2  — 3.0 > 1.0f — expected 0x0000 */
static uint16_t test_fcom_m32fp_gt(void)
{
    double st0 = D_GT_ST0;
    float  src = F_GT_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoms %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 /2  — 1.0 < 3.0f — expected 0x0100 */
static uint16_t test_fcom_m32fp_lt(void)
{
    double st0 = D_LT_ST0;
    float  src = F_LT_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoms %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 /2  — 2.0 = 2.0f — expected 0x4000 */
static uint16_t test_fcom_m32fp_eq(void)
{
    double st0 = D_EQ_ST0;
    float  src = F_EQ_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoms %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 /2  — NaN vs 1.0f — expected 0x4500 */
static uint16_t test_fcom_m32fp_un(void)
{
    double nan_val = __builtin_nan("");
    float  src = 1.0f;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoms %1\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}
#endif /* TEST_FCOM_M32FP */

/* ===========================================================================
 * FCOM m64fp  —  DC /2  —  compare ST(0) with float64 memory, no pop
 * =========================================================================== */
#ifndef TEST_FCOM_M64FP
#  define TEST_FCOM_M64FP 1
#endif

#if TEST_FCOM_M64FP
/* DC /2  — 3.0 > 1.0 — expected 0x0000 */
static uint16_t test_fcom_m64fp_gt(void)
{
    double st0 = D_GT_ST0, src = D_GT_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoml %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* DC /2  — 1.0 < 3.0 — expected 0x0100 */
static uint16_t test_fcom_m64fp_lt(void)
{
    double st0 = D_LT_ST0, src = D_LT_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoml %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* DC /2  — 2.0 = 2.0 — expected 0x4000 */
static uint16_t test_fcom_m64fp_eq(void)
{
    double st0 = D_EQ_ST0, src = D_EQ_SRC;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoml %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* DC /2  — NaN vs 1.0 — expected 0x4500 */
static uint16_t test_fcom_m64fp_un(void)
{
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile (
        "fldl  %0\n"
        "fcoml %1\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}
#endif /* TEST_FCOM_M64FP */

/* ===========================================================================
 * FCOMP ST(i)  —  D8 D8+i  —  compare ST(0) with ST(i), pop once
 * Setup: identical to FCOM ST(i). After the pop, only src remains; fstp cleans up.
 * =========================================================================== */
#ifndef TEST_FCOMP_STI
#  define TEST_FCOMP_STI 1
#endif

#if TEST_FCOMP_STI
/* D8 D9  — 3.0 > 1.0 — expected 0x0000 */
static uint16_t test_fcomp_sti_gt(void)
{
    double st0 = D_GT_ST0, src = D_GT_SRC;
    __asm__ volatile (
        "fldl %1\n"              /* ST(0)=src=1.0                    */
        "fldl %0\n"              /* ST(0)=3.0, ST(1)=1.0             */
        "fcomp %%st(1)\n"        /* compare, pop ST(0) -> ST(0)=1.0  */
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 D9  — 1.0 < 3.0 — expected 0x0100 */
static uint16_t test_fcomp_sti_lt(void)
{
    double st0 = D_LT_ST0, src = D_LT_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcomp %%st(1)\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 D9  — 2.0 = 2.0 — expected 0x4000 */
static uint16_t test_fcomp_sti_eq(void)
{
    double st0 = D_EQ_ST0, src = D_EQ_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcomp %%st(1)\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* D8 D9  — NaN vs 1.0 — expected 0x4500 */
static uint16_t test_fcomp_sti_un(void)
{
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcomp %%st(1)\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}
#endif /* TEST_FCOMP_STI */

/* ===========================================================================
 * FCOMP m32fp  —  D8 /3  —  compare ST(0) with float32 memory, pop once
 * After the pop, the stack is empty — no teardown needed.
 * =========================================================================== */
#ifndef TEST_FCOMP_M32FP
#  define TEST_FCOMP_M32FP 1
#endif

#if TEST_FCOMP_M32FP
/* D8 /3  — 3.0 > 1.0f — expected 0x0000 */
static uint16_t test_fcomp_m32fp_gt(void)
{
    double st0 = D_GT_ST0;
    float  src = F_GT_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcomps %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* D8 /3  — 1.0 < 3.0f — expected 0x0100 */
static uint16_t test_fcomp_m32fp_lt(void)
{
    double st0 = D_LT_ST0;
    float  src = F_LT_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcomps %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* D8 /3  — 2.0 = 2.0f — expected 0x4000 */
static uint16_t test_fcomp_m32fp_eq(void)
{
    double st0 = D_EQ_ST0;
    float  src = F_EQ_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcomps %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* D8 /3  — NaN vs 1.0f — expected 0x4500 */
static uint16_t test_fcomp_m32fp_un(void)
{
    double nan_val = __builtin_nan("");
    float  src = 1.0f;
    __asm__ volatile (
        "fldl   %0\n"
        "fcomps %1\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    return cc;
}
#endif /* TEST_FCOMP_M32FP */

/* ===========================================================================
 * FCOMP m64fp  —  DC /3  —  compare ST(0) with float64 memory, pop once
 * =========================================================================== */
#ifndef TEST_FCOMP_M64FP
#  define TEST_FCOMP_M64FP 1
#endif

#if TEST_FCOMP_M64FP
/* DC /3  — 3.0 > 1.0 — expected 0x0000 */
static uint16_t test_fcomp_m64fp_gt(void)
{
    double st0 = D_GT_ST0, src = D_GT_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcompl %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DC /3  — 1.0 < 3.0 — expected 0x0100 */
static uint16_t test_fcomp_m64fp_lt(void)
{
    double st0 = D_LT_ST0, src = D_LT_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcompl %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DC /3  — 2.0 = 2.0 — expected 0x4000 */
static uint16_t test_fcomp_m64fp_eq(void)
{
    double st0 = D_EQ_ST0, src = D_EQ_SRC;
    __asm__ volatile (
        "fldl   %0\n"
        "fcompl %1\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DC /3  — NaN vs 1.0 — expected 0x4500 */
static uint16_t test_fcomp_m64fp_un(void)
{
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile (
        "fldl   %0\n"
        "fcompl %1\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    return cc;
}
#endif /* TEST_FCOMP_M64FP */

/* ===========================================================================
 * FCOMPP  —  DE D9  —  compare ST(0) with ST(1), pop twice
 * Stack is empty after the instruction — no teardown needed.
 * =========================================================================== */
#ifndef TEST_FCOMPP
#  define TEST_FCOMPP 1
#endif

#if TEST_FCOMPP
/* DE D9  — 3.0 > 1.0 — expected 0x0000 */
static uint16_t test_fcompp_gt(void)
{
    double st0 = D_GT_ST0, src = D_GT_SRC;
    __asm__ volatile (
        "fldl %1\n"              /* ST(0) = src = 1.0                */
        "fldl %0\n"              /* ST(0) = 3.0, ST(1) = 1.0         */
        "fcompp\n"               /* compare, pop twice               */
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DE D9  — 1.0 < 3.0 — expected 0x0100 */
static uint16_t test_fcompp_lt(void)
{
    double st0 = D_LT_ST0, src = D_LT_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcompp\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DE D9  — 2.0 = 2.0 — expected 0x4000 */
static uint16_t test_fcompp_eq(void)
{
    double st0 = D_EQ_ST0, src = D_EQ_SRC;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcompp\n"
        : : "m" (st0), "m" (src)
    );
    READ_SW(cc);
    return cc;
}

/* DE D9  — NaN vs 1.0 — expected 0x4500 */
static uint16_t test_fcompp_un(void)
{
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %0\n"
        "fcompp\n"
        : : "m" (nan_val), "m" (src)
    );
    READ_SW(cc);
    return cc;
}
#endif /* TEST_FCOMPP */

/* ===========================================================================
 * Test table and harness
 * =========================================================================== */
typedef struct {
    const char    *name;
    uint16_t     (*fn)(void);
    uint16_t       expected;
} TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FCOM_STI
        { "fcom  ST(1)    D8 D1   GT  3.0>1.0", test_fcom_sti_gt,      0x0000 },
        { "fcom  ST(1)    D8 D1   LT  1.0<3.0", test_fcom_sti_lt,      0x0100 },
        { "fcom  ST(1)    D8 D1   EQ  2.0=2.0", test_fcom_sti_eq,      0x4000 },
        { "fcom  ST(1)    D8 D1   UN  NaN,1.0", test_fcom_sti_un,      0x4500 },
#endif
#if TEST_FCOM_M32FP
        { "fcom  m32fp    D8 /2   GT  3.0>1.0", test_fcom_m32fp_gt,    0x0000 },
        { "fcom  m32fp    D8 /2   LT  1.0<3.0", test_fcom_m32fp_lt,    0x0100 },
        { "fcom  m32fp    D8 /2   EQ  2.0=2.0", test_fcom_m32fp_eq,    0x4000 },
        { "fcom  m32fp    D8 /2   UN  NaN,1.0", test_fcom_m32fp_un,    0x4500 },
#endif
#if TEST_FCOM_M64FP
        { "fcom  m64fp    DC /2   GT  3.0>1.0", test_fcom_m64fp_gt,    0x0000 },
        { "fcom  m64fp    DC /2   LT  1.0<3.0", test_fcom_m64fp_lt,    0x0100 },
        { "fcom  m64fp    DC /2   EQ  2.0=2.0", test_fcom_m64fp_eq,    0x4000 },
        { "fcom  m64fp    DC /2   UN  NaN,1.0", test_fcom_m64fp_un,    0x4500 },
#endif
#if TEST_FCOMP_STI
        { "fcomp ST(1)    D8 D9   GT  3.0>1.0", test_fcomp_sti_gt,     0x0000 },
        { "fcomp ST(1)    D8 D9   LT  1.0<3.0", test_fcomp_sti_lt,     0x0100 },
        { "fcomp ST(1)    D8 D9   EQ  2.0=2.0", test_fcomp_sti_eq,     0x4000 },
        { "fcomp ST(1)    D8 D9   UN  NaN,1.0", test_fcomp_sti_un,     0x4500 },
#endif
#if TEST_FCOMP_M32FP
        { "fcomp m32fp    D8 /3   GT  3.0>1.0", test_fcomp_m32fp_gt,   0x0000 },
        { "fcomp m32fp    D8 /3   LT  1.0<3.0", test_fcomp_m32fp_lt,   0x0100 },
        { "fcomp m32fp    D8 /3   EQ  2.0=2.0", test_fcomp_m32fp_eq,   0x4000 },
        { "fcomp m32fp    D8 /3   UN  NaN,1.0", test_fcomp_m32fp_un,   0x4500 },
#endif
#if TEST_FCOMP_M64FP
        { "fcomp m64fp    DC /3   GT  3.0>1.0", test_fcomp_m64fp_gt,   0x0000 },
        { "fcomp m64fp    DC /3   LT  1.0<3.0", test_fcomp_m64fp_lt,   0x0100 },
        { "fcomp m64fp    DC /3   EQ  2.0=2.0", test_fcomp_m64fp_eq,   0x4000 },
        { "fcomp m64fp    DC /3   UN  NaN,1.0", test_fcomp_m64fp_un,   0x4500 },
#endif
#if TEST_FCOMPP
        { "fcompp         DE D9   GT  3.0>1.0", test_fcompp_gt,        0x0000 },
        { "fcompp         DE D9   LT  1.0<3.0", test_fcompp_lt,        0x0100 },
        { "fcompp         DE D9   EQ  2.0=2.0", test_fcompp_eq,        0x4000 },
        { "fcompp         DE D9   UN  NaN,1.0", test_fcompp_un,        0x4500 },
#endif
    };

    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        uint16_t got = tests[i].fn();
        int ok = (got == tests[i].expected);
        printf("%s  got=0x%04x  expected=0x%04x  %s\n",
               tests[i].name, (unsigned)got, (unsigned)tests[i].expected,
               ok ? "PASS" : "FAIL");
        ok ? pass++ : fail++;
    }

    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}