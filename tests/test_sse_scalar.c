/*
 * test_sse_scalar.c — OPT-A3: scalar movsd/movss consumed into x87 IR runs
 * (opt-in ROSETTA_X87_TRANSPARENT_SSE=1; without the flag these stay
 * Rosetta-translated and the tests must still pass).
 *
 * Covers:
 *   - the fstp/movsd seam: store-forward into the xmm write, and the
 *     store-forward OUT of a movsd store into a later fld;
 *   - x86 load-form semantics: movsd zeroes xmm bits 127:64, movss zeroes
 *     127:32 (verified by reading the full register back with movups);
 *   - the reg<->reg merge form (NOT consumed — upper bits must be preserved);
 *   - stores from an xmm whose value the run never saw (direct register
 *     store path);
 *   - bit-exactness through the forwarding paths (NaN payloads);
 *   - high registers (xmm8+, REX encoding).
 *
 * Build: clang -arch x86_64 -O0 -o test_sse_scalar test_sse_scalar.c -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_d(const char *name, double got, double expected) {
    if (memcmp(&got, &expected, sizeof(double)) != 0) {
        printf("FAIL  %-56s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f(const char *name, float got, float expected) {
    if (memcmp(&got, &expected, sizeof(float)) != 0) {
        printf("FAIL  %-56s  got=%.9g  expected=%.9g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u64(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=0x%016llx  expected=0x%016llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ── A: the fstp/movsd seam (both hops) ─────────────────────────────────── */

/* fadd -> fstp t -> movsd xmm0,t -> movsd r,xmm0: with consumption the two
 * reloads collapse to register moves; either way r == a+b bit-exactly. */
__attribute__((noinline)) static double seam_fstp_movsd(double a, double b) {
    volatile double t = 0.0, r = 0.0;
    __asm__ volatile(
        "fldl  %2\n\t"
        "faddl %3\n\t"
        "fstpl %1\n\t"
        "movsd %1, %%xmm0\n\t"
        "movsd %%xmm0, %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a), "m"(b)
        : "st", "xmm0");
    return r;
}

/* movsd store forwarded into a later fld (same block, more x87 follows). */
__attribute__((noinline)) static double movsd_store_then_fld(double a) {
    volatile double t = 0.0, r = 0.0;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fstpl %1\n\t"
        "movsd %1, %%xmm1\n\t"
        "movsd %%xmm1, %1\n\t"
        "fldl  %1\n\t"
        "fadd  %%st(0), %%st(0)\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a)
        : "st", "xmm1");
    return r;
}

/* f32 flavor: fstps/movss round trip. */
__attribute__((noinline)) static float seam_fstp_movss(float a, float b) {
    volatile float t = 0.0f, r = 0.0f;
    __asm__ volatile(
        "flds  %2\n\t"
        "fadds %3\n\t"
        "fstps %1\n\t"
        "movss %1, %%xmm2\n\t"
        "movss %%xmm2, %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a), "m"(b)
        : "st", "xmm2");
    return r;
}

/* NaN payload bit-exactness through the forwarding path. */
__attribute__((noinline)) static uint64_t seam_nan_bits(void) {
    volatile uint64_t in = 0x7FF8DEADBEEF1234ULL;
    volatile uint64_t t = 0, r = 0;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fstpl %1\n\t"
        "movsd %1, %%xmm3\n\t"
        "movsd %%xmm3, %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(in)
        : "st", "xmm3");
    return r;
}

/* ── B: load-form upper-bit zeroing ─────────────────────────────────────── */

/* Fill xmm0 with a full 128-bit pattern, then a CONSUMED movsd load; read
 * the whole register back with movups. Bits 127:64 must be zero. */
__attribute__((noinline)) static void movsd_zeroes_upper(uint64_t out[2], double a) {
    volatile uint64_t pat[2] = {0x1111111122222222ULL, 0x3333333344444444ULL};
    volatile double t = 0.0;
    __asm__ volatile(
        "movups %2, %%xmm0\n\t"
        "fldl  %3\n\t"
        "fstpl %1\n\t"
        "movsd %1, %%xmm0\n\t"
        "movups %%xmm0, %0\n\t"
        : "=m"(*(volatile uint64_t(*)[2])out), "+m"(t)
        : "m"(pat), "m"(a)
        : "st", "xmm0", "memory");
}

/* Same for movss: bits 127:32 zero. */
__attribute__((noinline)) static void movss_zeroes_upper(uint64_t out[2], float a) {
    volatile uint64_t pat[2] = {0x5555555566666666ULL, 0x7777777788888888ULL};
    volatile float t = 0.0f;
    __asm__ volatile(
        "movups %2, %%xmm4\n\t"
        "flds  %3\n\t"
        "fstps %1\n\t"
        "movss %1, %%xmm4\n\t"
        "movups %%xmm4, %0\n\t"
        : "=m"(*(volatile uint64_t(*)[2])out), "+m"(t)
        : "m"(pat), "m"(a)
        : "st", "xmm4", "memory");
}

/* ── C: reg<->reg merge form (NOT consumed — semantics must survive) ────── */

/* movsd xmm5,xmm6 copies the low 64 and PRESERVES xmm5's upper 64. */
__attribute__((noinline)) static void movsd_regreg_merges(uint64_t out[2]) {
    volatile uint64_t pat5[2] = {0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL};
    volatile uint64_t pat6[2] = {0xCCCCCCCCCCCCCCCCULL, 0xDDDDDDDDDDDDDDDDULL};
    volatile double t = 0.0;
    __asm__ volatile(
        "movups %1, %%xmm5\n\t"
        "movups %2, %%xmm6\n\t"
        "fld1\n\t"
        "fstpl %3\n\t"
        "movsd %%xmm6, %%xmm5\n\t"
        "movups %%xmm5, %0\n\t"
        : "=m"(*(volatile uint64_t(*)[2])out), "+m"(pat5), "+m"(pat6), "+m"(t)
        :
        : "st", "xmm5", "xmm6", "memory");
}

/* ── D: store from an xmm the run never wrote (direct register path) ────── */

__attribute__((noinline)) static double movsd_store_unknown(double a) {
    volatile double t = 0.0, r = 0.0;
    /* xmm7 is set OUTSIDE the x87 run (before the fld). */
    __asm__ volatile(
        "movsd %2, %%xmm7\n\t"
        "fldl  %2\n\t"
        "fld   %%st(0)\n\t"
        "faddp\n\t"
        "fstpl %1\n\t"
        "movsd %%xmm7, %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a)
        : "st", "xmm7");
    return r;  /* r = original a, t = 2a */
}

/* ── E: high registers (REX) ────────────────────────────────────────────── */

__attribute__((noinline)) static double seam_xmm12(double a, double b) {
    volatile double t = 0.0, r = 0.0;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fmull %3\n\t"
        "fstpl %1\n\t"
        "movsd %1, %%xmm12\n\t"
        "movsd %%xmm12, %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a), "m"(b)
        : "st", "xmm12");
    return r;
}

int main(void) {
    check_d("A/fstp->movsd->movsd seam", seam_fstp_movsd(1.5, 2.25), 3.75);
    check_d("A/movsd store forwarded into fld", movsd_store_then_fld(2.5), 5.0);
    check_f("A/fstps->movss->movss seam", seam_fstp_movss(1.5f, 0.75f), 2.25f);
    check_u64("A/NaN payload bit-exact through seam", seam_nan_bits(),
              0x7FF8DEADBEEF1234ULL);

    uint64_t out[2] = {0, 0};
    double a = 6.5;
    movsd_zeroes_upper(out, a);
    uint64_t abits;
    memcpy(&abits, &a, 8);
    check_u64("B/movsd load: low 64 = value", out[0], abits);
    check_u64("B/movsd load zeroes bits 127:64", out[1], 0);

    float f = 3.25f;
    movss_zeroes_upper(out, f);
    uint32_t fbits;
    memcpy(&fbits, &f, 4);
    check_u64("B/movss load: low 32 = value, 63:32 zero", out[0],
              (uint64_t)fbits);
    check_u64("B/movss load zeroes bits 127:64", out[1], 0);

    movsd_regreg_merges(out);
    check_u64("C/movsd reg,reg copies low 64", out[0], 0xCCCCCCCCCCCCCCCCULL);
    check_u64("C/movsd reg,reg preserves upper 64", out[1],
              0xBBBBBBBBBBBBBBBBULL);

    check_d("D/store from un-tracked xmm", movsd_store_unknown(4.5), 4.5);
    check_d("E/xmm12 seam (REX)", seam_xmm12(3.0, 7.0), 21.0);

    if (failures) {
        printf("%d test(s) FAILED.\n", failures);
        return 1;
    }
    printf("All tests PASSED.\n");
    return 0;
}
