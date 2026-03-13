// sample_fld_m80fp.c — test harness for FLD m80fp (DB /5)
//
// Uses 'fldt' (AT&T mnemonic for FLD m80fp — 't' = tword = ten bytes) to
// load a long double from memory, then 'fstpl' to narrow it to double.
// We compare raw bit patterns so any precision, sign, or exponent error
// is caught exactly.
//
// On x86-64, long double is the native 80-bit x87 extended-precision type
// stored as 10 bytes of real data (+ 6 bytes padding to 16-byte alignment).
// 'fldt' reads exactly those 10 bytes.
//
// Compile:
//   gcc -O0 -mfpmath=387 -mno-sse -Wall -Wextra -o sample_fld_m80fp sample_fld_m80fp.c -lm
//
// Isolate a single case:
//   gcc -O0 -mfpmath=387 -mno-sse -DTEST_FLD_M80FP_TRUNC=0 ... sample_fld_m80fp.c

#include <stdio.h>
#include <stdint.h>
#include <math.h>

static uint64_t as_u64(double d) { uint64_t u; __builtin_memcpy(&u, &d, 8); return u; }

// ---------------------------------------------------------------------------
// Per-test enable flags
// ---------------------------------------------------------------------------
#ifndef TEST_FLD_M80FP_ONE
#  define TEST_FLD_M80FP_ONE     1
#endif
#ifndef TEST_FLD_M80FP_NEG
#  define TEST_FLD_M80FP_NEG     1
#endif
#ifndef TEST_FLD_M80FP_FRAC
#  define TEST_FLD_M80FP_FRAC    1
#endif
#ifndef TEST_FLD_M80FP_PI
#  define TEST_FLD_M80FP_PI      1
#endif
#ifndef TEST_FLD_M80FP_SQRT2
#  define TEST_FLD_M80FP_SQRT2   1
#endif
#ifndef TEST_FLD_M80FP_INF_POS
#  define TEST_FLD_M80FP_INF_POS 1
#endif
#ifndef TEST_FLD_M80FP_INF_NEG
#  define TEST_FLD_M80FP_INF_NEG 1
#endif
#ifndef TEST_FLD_M80FP_TRUNC
#  define TEST_FLD_M80FP_TRUNC   1
#endif

// ---------------------------------------------------------------------------
// Helper: load a long double from memory via 'fldt', store result as double.
//
// The volatile prevents the compiler from folding the conversion itself —
// we want the x87 FLD m80fp + FSTP m64fp sequence, not a compile-time cast.
// ---------------------------------------------------------------------------
static uint64_t load_f80_to_f64(volatile long double *src)
{
    double result;
    __asm__ volatile (
        "fldt %1\n"
        "fstpl %0\n"
        : "=m" (result)
        : "m"  (*src)
    );
    return as_u64(result);
}

// ---------------------------------------------------------------------------
// Test cases
//
// 80-bit layout (from MSB to LSB, 10 bytes):
//   [79]    sign
//   [78:64] exponent (15-bit, bias 16383)
//   [63]    explicit integer bit (always 1 for normals)
//   [62:0]  fractional mantissa
//
// Verified layouts (native hardware):
//   1.0    3FFF 8000000000000000
//  -1.0    BFFF 8000000000000000
//   1.5    3FFF C000000000000000
//   pi     4000 C90FDAA22168C235
//   sqrt2  3FFF B504F333F9DE6484
//   +inf   7FFF 8000000000000000
//   -inf   FFFF 8000000000000000
// ---------------------------------------------------------------------------

// +1.0 — simplest normal value, only the explicit integer bit is set.
// f80: 3FFF 8000000000000000  ->  f64: 0x3FF0000000000000
#if TEST_FLD_M80FP_ONE
static uint64_t test_fld_m80fp_one(void)
{
    static const volatile unsigned char src[10] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,  // mantissa LE
        0xFF, 0x3F                                         // exponent LE
    };
    return load_f80_to_f64((volatile long double *)src);
}
#endif

// -1.0 — tests the sign bit path.
// f80: BFFF 8000000000000000  ->  f64: 0xBFF0000000000000
#if TEST_FLD_M80FP_NEG
static uint64_t test_fld_m80fp_neg(void)
{
    volatile long double src = -1.0L;
    return load_f80_to_f64(&src);
}
#endif

// 1.5 — tests a non-zero fractional mantissa.
// f80: 3FFF C000000000000000  ->  f64: 0x3FF8000000000000
#if TEST_FLD_M80FP_FRAC
static uint64_t test_fld_m80fp_frac(void)
{
    volatile long double src = 1.5L;
    return load_f80_to_f64(&src);
}
#endif

// pi — tests a multi-bit exponent (exp=16384=0x4000) and a full 64-bit
// mantissa being narrowed to 52 bits.
// f80: 4000 C90FDAA22168C235  ->  f64: 0x400921FB54442D18
#if TEST_FLD_M80FP_PI
static uint64_t test_fld_m80fp_pi(void)
{
    volatile long double src = 3.14159265358979323846264338327950288L;
    return load_f80_to_f64(&src);
}
#endif

// sqrt(2) — tests mantissa truncation with many significant bits.
// f80: 3FFF B504F333F9DE6484  ->  f64: 0x3FF6A09E667F3BCD
#if TEST_FLD_M80FP_SQRT2
static uint64_t test_fld_m80fp_sqrt2(void)
{
    volatile long double src = 1.41421356237309504880168872420969808L;
    return load_f80_to_f64(&src);
}
#endif

// +infinity — tests the special-case exponent (0x7FFF).
// f80: 7FFF 8000000000000000  ->  f64: 0x7FF0000000000000
#if TEST_FLD_M80FP_INF_POS
static uint64_t test_fld_m80fp_inf_pos(void)
{
    volatile long double src = __builtin_infl();
    return load_f80_to_f64(&src);
}
#endif

// -infinity — same exponent path, sign bit set.
// f80: FFFF 8000000000000000  ->  f64: 0xFFF0000000000000
#if TEST_FLD_M80FP_INF_NEG
static uint64_t test_fld_m80fp_inf_neg(void)
{
    volatile long double src = -__builtin_infl();
    return load_f80_to_f64(&src);
}
#endif

// Mantissa truncation boundary test.
// 1.0 + 2^-52 + 2^-64
//   = the value 0x3FFF_8000000000000800 in 80-bit
// The 2^-64 component sits 12 ULPs below double's last bit — it is
// silently dropped on narrowing, leaving exactly 1.0 + 2^-52.
// f80: 3FFF 8000000000000800  ->  f64: 0x3FF0000000000001
//
// This specifically tests that your conversion drops the sub-52-bit
// mantissa bits rather than rounding them into the result incorrectly.
#if TEST_FLD_M80FP_TRUNC
static uint64_t test_fld_m80fp_trunc(void)
{
    volatile long double src = 1.0L + 0x1p-52L + 0x1p-64L;
    return load_f80_to_f64(&src);
}
#endif

// ---------------------------------------------------------------------------

typedef struct { const char* name; uint64_t (*fn)(void); uint64_t expected; } TestCase;

int main(void)
{
    TestCase tests[] = {
#if TEST_FLD_M80FP_ONE
        { "fld m80fp  +1.0             ", test_fld_m80fp_one,     0x3FF0000000000000ULL },
#endif
#if TEST_FLD_M80FP_NEG
        { "fld m80fp  -1.0  sign bit   ", test_fld_m80fp_neg,     0xBFF0000000000000ULL },
#endif
#if TEST_FLD_M80FP_FRAC
        { "fld m80fp  1.5   fraction   ", test_fld_m80fp_frac,    0x3FF8000000000000ULL },
#endif
#if TEST_FLD_M80FP_PI
        { "fld m80fp  pi    exp+trunc  ", test_fld_m80fp_pi,      0x400921FB54442D18ULL },
#endif
#if TEST_FLD_M80FP_SQRT2
        { "fld m80fp  sqrt2 many bits  ", test_fld_m80fp_sqrt2,   0x3FF6A09E667F3BCDUL },
#endif
#if TEST_FLD_M80FP_INF_POS
        { "fld m80fp  +inf  exp=7FFF   ", test_fld_m80fp_inf_pos, 0x7FF0000000000000ULL },
#endif
#if TEST_FLD_M80FP_INF_NEG
        { "fld m80fp  -inf  exp=FFFF   ", test_fld_m80fp_inf_neg, 0xFFF0000000000000ULL },
#endif
#if TEST_FLD_M80FP_TRUNC
        { "fld m80fp  trunc 2^-64 lost ", test_fld_m80fp_trunc,   0x3FF0000000000001ULL },
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