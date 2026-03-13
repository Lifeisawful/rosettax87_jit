#include <stdio.h>
#include <stdint.h>

static uint32_t as_u32(float f) { uint32_t u; __builtin_memcpy(&u, &f, 4); return u; }

// ---------------------------------------------------------------------------
// Per-test enable flags.
// ---------------------------------------------------------------------------
#ifndef TEST_FMUL_ST0_STI
#  define TEST_FMUL_ST0_STI    1
#endif
#ifndef TEST_FMUL_STI_ST0
#  define TEST_FMUL_STI_ST0    1
#endif
#ifndef TEST_FMUL_M32FP
#  define TEST_FMUL_M32FP      1
#endif
#ifndef TEST_FMUL_M64FP
#  define TEST_FMUL_M64FP      1
#endif
#ifndef TEST_FMULP_STI_ST0
#  define TEST_FMULP_STI_ST0   1
#endif
#ifndef TEST_FMULP_IMPLICIT
#  define TEST_FMULP_IMPLICIT  1
#endif

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

// FMUL ST(0), ST(i)  (D8 C8+i)
// Stack: push 3.0, push 2.0.  FMUL ST(0), ST(1) => ST(0) = 2.0 * 3.0 = 6.0
// expected: 6.0 = 0x40c00000
#if TEST_FMUL_ST0_STI
static uint32_t test_fmul_st0_sti(void)
{
    float result;
    __asm__ volatile (
        "fld1\n" "fld1\n" "faddp\n"      // ST(0) = 2.0
        "fld1\n" "faddp\n"               // build 3.0 via 2.0+1.0 into scratch...
        // restart: we need ST(0)=2.0, ST(1)=3.0 cleanly
        // easier: push 3.0 first (1+1+1), then push 2.0 (1+1)
        "fldz\n"                         // clear stack to a known depth
        "fstp %%st(0)\n"
        // push 3.0 = 1+1+1
        "fld1\n" "fld1\n" "faddp\n"      // 2.0
        "fld1\n" "faddp\n"               // 3.0  → this is ST(1) after next push
        // push 2.0 = 1+1
        "fld1\n" "fld1\n" "faddp\n"      // ST(0)=2.0, ST(1)=3.0
        "fmul %%st(1), %%st\n"           // D8 C8+i: ST(0) = ST(0)*ST(1) = 6.0
        "fstps %0\n"
        "fstp %%st(0)\n"                 // discard ST(1)=3.0
        : "=m" (result)
    );
    return as_u32(result);
}
#endif

// FMUL ST(i), ST(0)  (DC C8+i)
// Stack: ST(0)=2.0, ST(1)=3.0.  FMUL ST(1), ST(0) => ST(1) = 3.0 * 2.0 = 6.0
// expected: 6.0 = 0x40c00000
#if TEST_FMUL_STI_ST0
static uint32_t test_fmul_sti_st0(void)
{
    float result;
    __asm__ volatile (
        // push 3.0
        "fld1\n" "fld1\n" "faddp\n"      // 2.0
        "fld1\n" "faddp\n"               // 3.0  → ST(1) after next push
        // push 2.0
        "fld1\n" "fld1\n" "faddp\n"      // ST(0)=2.0, ST(1)=3.0
        "fmul %%st, %%st(1)\n"           // DC C8+i: ST(1) = ST(1)*ST(0) = 6.0
        "fstp %%st(0)\n"                 // pop 2.0
        "fstps %0\n"                     // store ST(0)=6.0
        : "=m" (result)
    );
    return as_u32(result);
}
#endif

// FMUL m32fp  (D8 /1)
// ST(0) = 3.0 * 1.5 = 4.5
// expected: 4.5 = 0x40900000
#if TEST_FMUL_M32FP
static uint32_t test_fmul_m32fp(void)
{
    float result;
    float mem = 1.5f;
    __asm__ volatile (
        "fld1\n" "fld1\n" "faddp\n"      // 2.0
        "fld1\n" "faddp\n"               // 3.0
        "fmuls %1\n"                     // D8 /1: ST(0) = 3.0 * 1.5 = 4.5
        "fstps %0\n"
        : "=m" (result)
        : "m"  (mem)
    );
    return as_u32(result);
}
#endif

// FMUL m64fp  (DC /1)
// ST(0) = 2.0 * 2.5 = 5.0
// expected: 5.0 = 0x40a00000
#if TEST_FMUL_M64FP
static uint32_t test_fmul_m64fp(void)
{
    float result;
    double mem = 2.5;
    __asm__ volatile (
        "fld1\n" "fld1\n" "faddp\n"      // 2.0
        "fmull %1\n"                     // DC /1: ST(0) = 2.0 * 2.5 = 5.0
        "fstps %0\n"
        : "=m" (result)
        : "m"  (mem)
    );
    return as_u32(result);
}
#endif

// FMULP ST(i), ST(0)  (DE C8+i)
// ST(0)=2.0, ST(1)=3.0.  FMULP ST(1),ST(0) => ST(1)=6.0, pop => ST(0)=6.0
// expected: 6.0 = 0x40c00000
#if TEST_FMULP_STI_ST0
static uint32_t test_fmulp_sti_st0(void)
{
    float result;
    __asm__ volatile (
        // push 3.0
        "fld1\n" "fld1\n" "faddp\n"      // 2.0
        "fld1\n" "faddp\n"               // 3.0  → becomes ST(1)
        // push 2.0
        "fld1\n" "fld1\n" "faddp\n"      // ST(0)=2.0, ST(1)=3.0
        "fmulp %%st(0), %%st(1)\n"       // DE C8+i: ST(1)=3.0*2.0=6.0, pop
        "fstps %0\n"                     // ST(0) is now 6.0
        : "=m" (result)
    );
    return as_u32(result);
}
#endif

// FMULP  (DE C9, implicit ST(1),ST(0))
// ST(0)=2.0, ST(1)=2.0.  FMULP => ST(1)=4.0, pop => ST(0)=4.0
// expected: 4.0 = 0x40800000
#if TEST_FMULP_IMPLICIT
static uint32_t test_fmulp_implicit(void)
{
    float result;
    __asm__ volatile (
        "fld1\n" "fld1\n" "faddp\n"      // push 2.0
        "fld1\n" "fld1\n" "faddp\n"      // push 2.0  →  ST(0)=2.0, ST(1)=2.0
        "fmulp\n"                        // DE C9: ST(1)=2.0*2.0=4.0, pop
        "fstps %0\n"
        : "=m" (result)
    );
    return as_u32(result);
}
#endif

// ---------------------------------------------------------------------------
// Test table
// ---------------------------------------------------------------------------
typedef struct { const char* name; uint32_t (*fn)(void); uint32_t expected; } TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FMUL_ST0_STI
        { "fmul  ST(0),ST(i)  D8 C8+i  2.0*3.0=6.0 ", test_fmul_st0_sti,   0x40c00000 },
#endif
#if TEST_FMUL_STI_ST0
        { "fmul  ST(i),ST(0)  DC C8+i  3.0*2.0=6.0 ", test_fmul_sti_st0,   0x40c00000 },
#endif
#if TEST_FMUL_M32FP
        { "fmul  m32fp        D8 /1    3.0*1.5=4.5  ", test_fmul_m32fp,     0x40900000 },
#endif
#if TEST_FMUL_M64FP
        { "fmul  m64fp        DC /1    2.0*2.5=5.0  ", test_fmul_m64fp,     0x40a00000 },
#endif
#if TEST_FMULP_STI_ST0
        { "fmulp ST(i),ST(0)  DE C8+i  3.0*2.0=6.0 ", test_fmulp_sti_st0,  0x40c00000 },
#endif
#if TEST_FMULP_IMPLICIT
        { "fmulp implicit     DE C9    2.0*2.0=4.0  ", test_fmulp_implicit, 0x40800000 },
#endif
    };

    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        uint32_t got = tests[i].fn();
        int ok = (got == tests[i].expected);
        printf("%s  got=%08x  expected=%08x  %s\n",
               tests[i].name, got, tests[i].expected, ok ? "PASS" : "FAIL");
        ok ? pass++ : fail++;
    }

    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}