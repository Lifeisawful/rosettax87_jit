#include <stdio.h>
#include <stdint.h>
#include <math.h>

static uint64_t as_u64(double d) { uint64_t u; __builtin_memcpy(&u, &d, 8); return u; }

// ---------------------------------------------------------------------------
// Per-test enable flags.
// ---------------------------------------------------------------------------
#ifndef TEST_FLD_M32FP
#  define TEST_FLD_M32FP  1
#endif
#ifndef TEST_FLD_M64FP
#  define TEST_FLD_M64FP  1
#endif
#ifndef TEST_FLD_STI_SIMPLE
#  define TEST_FLD_STI_SIMPLE  1
#endif
#ifndef TEST_FLD_ST0_DUP
#  define TEST_FLD_ST0_DUP  1
#endif
#ifndef TEST_FLD_STI_DEEP
#  define TEST_FLD_STI_DEEP  1
#endif

// ---------------------------------------------------------------------------
// FLD m32fp — D9 /0
// Push a float32 from memory onto the x87 stack, verify the widen to f64.
// 1.5f = 0x3FC00000 (f32) = 0x3FF8000000000000 (f64)
// ---------------------------------------------------------------------------
#if TEST_FLD_M32FP
static uint64_t test_fld_m32fp(void)
{
    double result;
    float src = 1.5f;
    __asm__ volatile (
        "flds %1\n"
        "fstpl %0\n"
        : "=m" (result)
        : "m"  (src)
    );
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------
// FLD m64fp — DD /0
// Push a float64 from memory. No conversion — bit pattern must be exact.
// pi = 0x400921FB54442D18
// ---------------------------------------------------------------------------
#if TEST_FLD_M64FP
static uint64_t test_fld_m64fp(void)
{
    double result;
    double src = 3.14159265358979311600;   /* bit pattern: 0x400921FB54442D18 */
    __asm__ volatile (
        "fldl %1\n"
        "fstpl %0\n"
        : "=m" (result)
        : "m"  (src)
    );
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------
// FLD ST(i) — simple case: FLD ST(1) with two distinct values on stack.
// Stack before: ST(0)=2.0, ST(1)=1.0
// FLD ST(1) pushes a copy of ST(1)=1.0:  ST(0)=1.0, ST(1)=2.0, ST(2)=1.0
// Pop ST(0) → result = 1.0
// expected: 0x3FF0000000000000
// ---------------------------------------------------------------------------
#if TEST_FLD_STI_SIMPLE
static uint64_t test_fld_sti_simple(void)
{
    double result;
    __asm__ volatile (
        "fld1\n"                    // ST(0) = 1.0
        "fld1\n" "fld1\n" "faddp\n" // ST(0) = 2.0, ST(1) = 1.0
        "fld %%st(1)\n"             // D9 C1: push copy of ST(1)=1.0
                                    // Stack: ST(0)=1.0, ST(1)=2.0, ST(2)=1.0
        "fstpl %0\n"                // pop ST(0)=1.0
        : "=m" (result)
    );
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------
// FLD ST(0) — duplicate the top of stack.
// Stack before: ST(0)=3.0
// FLD ST(0): ST(0)=3.0, ST(1)=3.0
// faddp → 6.0
// expected: 0x4018000000000000
// ---------------------------------------------------------------------------
#if TEST_FLD_ST0_DUP
static uint64_t test_fld_st0_dup(void)
{
    double result;
    __asm__ volatile (
        "fld1\n" "fld1\n" "faddp\n" // ST(0) = 2.0
        "fld1\n" "faddp\n"          // ST(0) = 3.0
        "fld %%st(0)\n"             // D9 C0: duplicate top → ST(0)=3.0, ST(1)=3.0
        "faddp\n"                   // 3.0 + 3.0 = 6.0
        "fstpl %0\n"
        : "=m" (result)
    );
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------
// FLD ST(i) — deeper index: FLD ST(2) with three values on stack.
// Stack before: ST(0)=3.0, ST(1)=2.0, ST(2)=1.0
// FLD ST(2) pushes 1.0.
// Pop it → 1.0.
// expected: 0x3FF0000000000000
// ---------------------------------------------------------------------------
#if TEST_FLD_STI_DEEP
static uint64_t test_fld_sti_deep(void)
{
    double result;
    __asm__ volatile (
        "fld1\n"                    // ST(0) = 1.0
        "fld1\n" "fld1\n" "faddp\n" // ST(0) = 2.0, ST(1) = 1.0
        "fld1\n" "fld1\n" "faddp\n" // ST(0) = 2.0, ...
        "fld1\n" "faddp\n"          // ST(0) = 3.0, ST(1) = 2.0, ST(2) = 1.0
        "fld %%st(2)\n"             // D9 C2: push copy of ST(2)=1.0
        "fstpl %0\n"                // pop ST(0)=1.0; stack depth = 3 again
        // clean up remaining 3 values
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------

typedef struct { const char* name; uint64_t (*fn)(void); uint64_t expected; } TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FLD_M32FP
        { "fld m32fp     1.5f widen to f64  ", test_fld_m32fp,    0x3FF8000000000000ULL },
#endif
#if TEST_FLD_M64FP
        { "fld m64fp     pi bit-exact       ", test_fld_m64fp,    0x400921FB54442D18ULL },
#endif
#if TEST_FLD_STI_SIMPLE
        { "fld st(1)     copy ST(1)=1.0     ", test_fld_sti_simple, 0x3FF0000000000000ULL },
#endif
#if TEST_FLD_ST0_DUP
        { "fld st(0)     duplicate top      ", test_fld_st0_dup,  0x4018000000000000ULL },
#endif
#if TEST_FLD_STI_DEEP
        { "fld st(2)     copy ST(2)=1.0     ", test_fld_sti_deep, 0x3FF0000000000000ULL },
#endif
    };

    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        uint64_t got = tests[i].fn();
        int ok = (got == tests[i].expected);
        printf("%s  got=%016llx  expected=%016llx  %s\n",
               tests[i].name, (unsigned long long)got,
               (unsigned long long)tests[i].expected, ok ? "PASS" : "FAIL");
        ok ? pass++ : fail++;
    }

    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}