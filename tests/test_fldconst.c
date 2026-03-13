#include <stdio.h>
#include <stdint.h>

static uint64_t as_u64(double d) { uint64_t u; __builtin_memcpy(&u, &d, 8); return u; }

// ---------------------------------------------------------------------------
// Per-test enable flags.
// ---------------------------------------------------------------------------
#ifndef TEST_FLDZ
#  define TEST_FLDZ   1
#endif
#ifndef TEST_FLD1
#  define TEST_FLD1   1
#endif
#ifndef TEST_FLDL2E
#  define TEST_FLDL2E 1
#endif
#ifndef TEST_FLDL2T
#  define TEST_FLDL2T 1
#endif
#ifndef TEST_FLDLG2
#  define TEST_FLDLG2 1
#endif
#ifndef TEST_FLDLN2
#  define TEST_FLDLN2 1
#endif
#ifndef TEST_FLDPI
#  define TEST_FLDPI  1
#endif

// ---------------------------------------------------------------------------
// Each test pushes the constant and pops it to a double in memory.
// We compare the raw bit pattern, not the floating-point value, so a
// wrong rounding or truncation is caught exactly.
// ---------------------------------------------------------------------------

#if TEST_FLDZ
static uint64_t test_fldz(void)
{
    double result;
    __asm__ volatile ("fldz\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLD1
static uint64_t test_fld1(void)
{
    double result;
    __asm__ volatile ("fld1\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLDL2E
static uint64_t test_fldl2e(void)
{
    double result;
    __asm__ volatile ("fldl2e\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLDL2T
static uint64_t test_fldl2t(void)
{
    double result;
    __asm__ volatile ("fldl2t\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLDLG2
static uint64_t test_fldlg2(void)
{
    double result;
    __asm__ volatile ("fldlg2\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLDLN2
static uint64_t test_fldln2(void)
{
    double result;
    __asm__ volatile ("fldln2\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

#if TEST_FLDPI
static uint64_t test_fldpi(void)
{
    double result;
    __asm__ volatile ("fldpi\n" "fstpl %0\n" : "=m" (result));
    return as_u64(result);
}
#endif

// ---------------------------------------------------------------------------

typedef struct { const char* name; uint64_t (*fn)(void); uint64_t expected; } TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FLDZ
        { "fldz   +0.0      ", test_fldz,   0x0000000000000000ULL },
#endif
#if TEST_FLD1
        { "fld1   +1.0      ", test_fld1,   0x3FF0000000000000ULL },
#endif
#if TEST_FLDL2E
        { "fldl2e log2(e)   ", test_fldl2e, 0x3FF71547652B82FEULL },
#endif
#if TEST_FLDL2T
        { "fldl2t log2(10)  ", test_fldl2t, 0x400A934F0979A371ULL },
#endif
#if TEST_FLDLG2
        { "fldlg2 log10(2)  ", test_fldlg2, 0x3FD34413509F79FFULL },
#endif
#if TEST_FLDLN2
        { "fldln2 ln(2)     ", test_fldln2, 0x3FE62E42FEFA39EFULL },
#endif
#if TEST_FLDPI
        { "fldpi  pi        ", test_fldpi,  0x400921FB54442D18ULL },
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