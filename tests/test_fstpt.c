// test_fstpt.c — test harness for FSTP m80fp (DB /7, aka FSTPT)
//
// Pushes a known double onto the x87 stack via FLD, then uses FSTPT to
// store it as 80-bit extended precision. We verify the raw 10-byte bit
// pattern to catch exponent bias, sign, integer-bit, and mantissa errors.
//
// This is the inverse of test_fld_m80fp.c (which tests FLD m80fp → double).
//
// Compile:
//   clang -arch x86_64 -O0 -g -o test_fstpt test_fstpt.c

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 10-byte f80 result packed into two integers for comparison
typedef struct { uint64_t mantissa; uint16_t exponent; } F80;

static F80 as_f80(const unsigned char buf[10])
{
    F80 r;
    memcpy(&r.mantissa, buf, 8);
    memcpy(&r.exponent, buf + 8, 2);
    return r;
}

// Per-test enable flags
#ifndef TEST_FSTPT_ONE
#  define TEST_FSTPT_ONE     1
#endif
#ifndef TEST_FSTPT_NEG
#  define TEST_FSTPT_NEG     1
#endif
#ifndef TEST_FSTPT_FRAC
#  define TEST_FSTPT_FRAC    1
#endif
#ifndef TEST_FSTPT_PI
#  define TEST_FSTPT_PI      1
#endif
#ifndef TEST_FSTPT_SQRT2
#  define TEST_FSTPT_SQRT2   1
#endif
#ifndef TEST_FSTPT_INF_POS
#  define TEST_FSTPT_INF_POS 1
#endif
#ifndef TEST_FSTPT_INF_NEG
#  define TEST_FSTPT_INF_NEG 1
#endif
#ifndef TEST_FSTPT_ZERO_POS
#  define TEST_FSTPT_ZERO_POS 1
#endif
#ifndef TEST_FSTPT_ZERO_NEG
#  define TEST_FSTPT_ZERO_NEG 1
#endif
#ifndef TEST_FSTPT_LARGE
#  define TEST_FSTPT_LARGE   1
#endif
#ifndef TEST_FSTPT_SMALL
#  define TEST_FSTPT_SMALL   1
#endif

// ---------------------------------------------------------------------------
// Helper: push a double via FLD m64fp, then store via FSTPT m80fp.
// Returns the 10-byte result in an F80 struct.
// ---------------------------------------------------------------------------
static F80 store_f64_as_f80(volatile double *src)
{
    unsigned char buf[10];
    __asm__ volatile (
        "fldl %1\n"
        "fstpt %0\n"
        : "=m" (buf)
        : "m"  (*src)
    );
    return as_f80(buf);
}

// ---------------------------------------------------------------------------
// Test cases
//
// Expected f80 layout (little-endian):
//   bytes 0-7: mantissa (64-bit, explicit integer bit at bit 63)
//   bytes 8-9: [15]=sign | [14:0]=exponent (bias 16383)
//
// double → f80 exponent: f80_exp = f64_exp - 1023 + 16383 = f64_exp + 15360
// double mantissa 52-bit → f80 mantissa 63-bit: shift left 11, set bit 63
// ---------------------------------------------------------------------------

// +1.0: f64 exp=1023 → f80 exp=16383=0x3FFF, mantissa=0x8000000000000000
#if TEST_FSTPT_ONE
static int test_fstpt_one(void)
{
    volatile double src = 1.0;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0x3FFF);
}
#endif

// -1.0: sign bit set → exponent word = 0xBFFF
#if TEST_FSTPT_NEG
static int test_fstpt_neg(void)
{
    volatile double src = -1.0;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0xBFFF);
}
#endif

// 1.5: mantissa has fraction bit → 0xC000000000000000
#if TEST_FSTPT_FRAC
static int test_fstpt_frac(void)
{
    volatile double src = 1.5;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0xC000000000000000ULL && r.exponent == 0x3FFF);
}
#endif

// pi: exp=1024 → f80 exp=16384=0x4000, mantissa=0xC90FDAA22168C000
// (double has 52 mantissa bits → shifted left 11 into 63-bit field + integer bit)
#if TEST_FSTPT_PI
static int test_fstpt_pi(void)
{
    volatile double src = 3.14159265358979323846;
    F80 r = store_f64_as_f80(&src);
    // f64 bits: 0x400921FB54442D18
    // mantissa = (0x00921FB54442D18 << 11) | 0x8000000000000000
    //          = 0xC90FDAA22168C000
    return (r.mantissa == 0xC90FDAA22168C000ULL && r.exponent == 0x4000);
}
#endif

// sqrt(2): exp=1023 → f80 exp=16383=0x3FFF
#if TEST_FSTPT_SQRT2
static int test_fstpt_sqrt2(void)
{
    volatile double src = 1.4142135623730950488;
    F80 r = store_f64_as_f80(&src);
    // f64 bits: 0x3FF6A09E667F3BCD
    // mantissa = (0x006A09E667F3BCD << 11) | 0x8000000000000000
    //          = 0xB504F333F9DE6800
    return (r.mantissa == 0xB504F333F9DE6800ULL && r.exponent == 0x3FFF);
}
#endif

// +inf: exponent = 0x7FFF, mantissa = 0x8000000000000000
#if TEST_FSTPT_INF_POS
static int test_fstpt_inf_pos(void)
{
    volatile double src = __builtin_inf();
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0x7FFF);
}
#endif

// -inf: exponent = 0xFFFF, mantissa = 0x8000000000000000
#if TEST_FSTPT_INF_NEG
static int test_fstpt_inf_neg(void)
{
    volatile double src = -__builtin_inf();
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0xFFFF);
}
#endif

// +0.0: all zero (zero/denorm path)
#if TEST_FSTPT_ZERO_POS
static int test_fstpt_zero_pos(void)
{
    volatile double src = 0.0;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x0000000000000000ULL && r.exponent == 0x0000);
}
#endif

// -0.0: mantissa=0, exponent=0x8000 (sign only)
#if TEST_FSTPT_ZERO_NEG
static int test_fstpt_zero_neg(void)
{
    volatile double src = -0.0;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x0000000000000000ULL && r.exponent == 0x8000);
}
#endif

// Large value: 2^1023 (max normal exponent)
// f64 exp=2046 → f80 exp=2046+15360=17406=0x43FE
#if TEST_FSTPT_LARGE
static int test_fstpt_large(void)
{
    volatile double src = 0x1p+1023;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0x43FE);
}
#endif

// Small value: 2^-1022 (min normal exponent)
// f64 exp=1 → f80 exp=1+15360=15361=0x3C01
#if TEST_FSTPT_SMALL
static int test_fstpt_small(void)
{
    volatile double src = 0x1p-1022;
    F80 r = store_f64_as_f80(&src);
    return (r.mantissa == 0x8000000000000000ULL && r.exponent == 0x3C01);
}
#endif

// ---------------------------------------------------------------------------

typedef struct { const char* name; int (*fn)(void); } TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FSTPT_ONE
        { "fstpt  +1.0             ", test_fstpt_one },
#endif
#if TEST_FSTPT_NEG
        { "fstpt  -1.0  sign bit   ", test_fstpt_neg },
#endif
#if TEST_FSTPT_FRAC
        { "fstpt  1.5   fraction   ", test_fstpt_frac },
#endif
#if TEST_FSTPT_PI
        { "fstpt  pi    exp+mant   ", test_fstpt_pi },
#endif
#if TEST_FSTPT_SQRT2
        { "fstpt  sqrt2 many bits  ", test_fstpt_sqrt2 },
#endif
#if TEST_FSTPT_INF_POS
        { "fstpt  +inf  exp=7FFF   ", test_fstpt_inf_pos },
#endif
#if TEST_FSTPT_INF_NEG
        { "fstpt  -inf  exp=FFFF   ", test_fstpt_inf_neg },
#endif
#if TEST_FSTPT_ZERO_POS
        { "fstpt  +0.0  zero path  ", test_fstpt_zero_pos },
#endif
#if TEST_FSTPT_ZERO_NEG
        { "fstpt  -0.0  neg zero   ", test_fstpt_zero_neg },
#endif
#if TEST_FSTPT_LARGE
        { "fstpt  2^1023 max exp   ", test_fstpt_large },
#endif
#if TEST_FSTPT_SMALL
        { "fstpt  2^-1022 min exp  ", test_fstpt_small },
#endif
    };

    int pass = 0, fail = 0;
    int n = (int)(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < n; i++) {
        int ok = tests[i].fn();
        printf("%s  %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        ok ? pass++ : fail++;
    }

    printf("\n%d/%d passed\n", pass, n);
    return fail ? 1 : 0;
}
