/*
 * test_seam.c — OPT-SEAM: TOP/tag state deferred across intra-block run
 * breaks (ROSETTA_X87_DISABLE_SEAM=1 reverts to flushing at every break).
 *
 * Every shape puts a run-transparent integer/SSE instruction between x87
 * runs inside one basic block, then observes the architectural state through
 * a channel that works under BOTH native Rosetta and this runtime:
 *   - computed values that must survive the seam (st[] memory is always
 *     written; only the status/tag words defer);
 *   - fnstsw TOP field (bits 11-13) after a seam — the consuming run must
 *     fold the carried delta before anything reads TOP;
 *   - fnstenv's tag word after seams — deferred set-valid/set-empty batches
 *     must materialize before any x87-family observer;
 *   - fxam after a seam — a runtime-routine observer (not a run member)
 *     that forces the seam flush path.
 *
 * Build: clang -arch x86_64 -O0 -o test_seam test_seam.c -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_d(const char *name, double got, double expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

#define TOP_OF(sw) (((sw) >> 11) & 7)

/* ── A: values across seam chains ───────────────────────────────────────── */

/* split3 shape: three 1-instruction runs separated by integer stores.
 * The whole fld -> fmul -> fstp chain must survive two seams. */
__attribute__((noinline)) static double seam_split3(double a, double b) {
    volatile int d = 0;
    volatile double r;
    __asm__ volatile(
        "fldl  %2\n\t"
        "movl  $0, %1\n\t"
        "fmull %3\n\t"
        "movl  $0, %1\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+m"(d)
        : "m"(a), "m"(b)
        : "cc", "st");
    return r;
}

/* Deeper stack across a seam: two pushes, seam, arithmetic + two pops.
 * The consuming run's slot reads must fold the carried TOP delta. */
__attribute__((noinline)) static double seam_two_push(double a, double b) {
    volatile int d = 0;
    volatile double r;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fldl  %3\n\t"
        "movl  $1, %1\n\t"
        "faddp %%st(0), %%st(1)\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+m"(d)
        : "m"(a), "m"(b)
        : "cc", "st");
    return r;
}

/* SSE instructions as the gap (the game-profile movsd seam). */
__attribute__((noinline)) static double seam_sse_gap(double a, double b) {
    volatile double t = 0.0, r;
    __asm__ volatile(
        "fldl  %2\n\t"
        "movsd %3, %%xmm4\n\t"
        "movsd %%xmm4, %1\n\t"
        "fmull %1\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+m"(t)
        : "m"(a), "m"(b)
        : "cc", "st", "xmm4");
    return r;
}

/* Flag-live dec between runs (the WoW CreateRenderLists shape): dec's ZF is
 * consumed by the loop branch, so it can never be inlined into a run. */
__attribute__((noinline)) static double seam_dec_loop(double a, double b, int n) {
    volatile double acc = 0.0;
    __asm__ volatile(
        "movl %3, %%ecx\n"
        "1:\n\t"
        "fldl  %1\n\t"
        "fmull %2\n\t"
        "decl  %%ecx\n\t"
        "faddl %0\n\t"
        "fstpl %0\n\t"
        "jnz 1b\n\t"
        : "+m"(acc)
        : "m"(a), "m"(b), "ri"(n)
        : "ecx", "cc", "st");
    return acc;
}

/* ── B: TOP observation through fnstsw after a seam ─────────────────────── */

/* Push two values with a seam in the middle; the fnstsw in the third run
 * must report TOP = 6 (two live pushes) with the carried delta folded. */
__attribute__((noinline)) static void seam_fnstsw_top(uint16_t sw[2], double a) {
    volatile int d = 0;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"
        "movl  $0, %1\n\t"
        "fldl  %2\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "fstp  %%st(0)\n\t"
        "movl  $0, %1\n\t"
        "fstp  %%st(0)\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        :
        : "r"(sw), "m"(d), "m"(a)
        : "ax", "cc", "st", "memory");
}

/* ── C: tag observation through fnstenv after seams ─────────────────────── */

/* One live slot after a push/seam/push/seam/pop dance: the deferred
 * set-valid and set-empty updates must cancel/materialize correctly before
 * fnstenv (an x87-family non-member) reads the tag word. Slot 7 valid, all
 * others empty -> tag = 0x3FFF. */
__attribute__((noinline)) static void seam_fnstenv_tags(uint32_t env[7], double a) {
    volatile int d = 0;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"
        "movl  $0, %1\n\t"
        "fldl  %2\n\t"
        "movl  $0, %1\n\t"
        "fstp  %%st(0)\n\t"
        "fnstenv (%0)\n\t"
        "fldcw (%0)\n\t"       /* fnstenv masks exceptions; restore CW */
        "fstp  %%st(0)\n\t"
        :
        : "r"(env), "m"(d), "m"(a)
        : "cc", "st", "memory");
}

/* ── D: fxam right after a seam (runtime-routine observer, flush path) ──── */

/* fxam classifies ST(0) from the REAL tag word. After fld across a seam it
 * must see a valid normal (C3C2C0 = 010 -> 0x0400); after the pop, empty
 * (C3C0 = 0x4100; native may also set C1). */
__attribute__((noinline)) static void seam_fxam(uint16_t sw[2], double a) {
    volatile int d = 0;
    __asm__ volatile(
        "fninit\n\t"
        "fldl  %2\n\t"
        "movl  $0, %1\n\t"
        "fxam\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 0(%0)\n\t"
        "fstp  %%st(0)\n\t"
        "movl  $0, %1\n\t"
        "fxam\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, 2(%0)\n\t"
        :
        : "r"(sw), "m"(d), "m"(a)
        : "ax", "cc", "st", "memory");
}

/* ── E: compare + fnstsw across a seam ──────────────────────────────────── */

/* The bench_fusion_fcom_fstsw shape: compare run, seam, pop run. The
 * compare's C-bits and the folded TOP must both survive. */
__attribute__((noinline)) static uint16_t seam_fcom_pop(double a, double b) {
    volatile int d = 0;
    uint16_t sw;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fldl  %3\n\t"
        "fcom  %%st(1)\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %0\n\t"
        "movl  $0, %1\n\t"
        "fstp  %%st(0)\n\t"
        "fstp  %%st(0)\n\t"
        : "=m"(sw), "+m"(d)
        : "m"(a), "m"(b)
        : "ax", "cc", "st");
    return sw;
}

int main(void) {
    check_d("A/split3 value across two seams", seam_split3(3.0, 4.0), 12.0);
    check_d("A/two pushes across seam, faddp", seam_two_push(1.5, 2.25), 3.75);
    check_d("A/SSE movsd gap", seam_sse_gap(3.0, 5.0), 15.0);
    check_d("A/flag-live dec loop, 4 iters", seam_dec_loop(2.0, 3.0, 4), 24.0);
    check_d("A/flag-live dec loop, 1 iter", seam_dec_loop(2.0, 3.0, 1), 6.0);

    uint16_t sw2[2] = {0, 0};
    seam_fnstsw_top(sw2, 1.5);
    check_u16("B/fnstsw TOP after seam (2 pushes)", TOP_OF(sw2[0]), 6);
    check_u16("B/fnstsw TOP after both pops", TOP_OF(sw2[1]), 0);

    uint32_t env[7];
    memset(env, 0, sizeof(env));
    seam_fnstenv_tags(env, 2.5);
    check_u16("C/fnstenv tag word: slot 7 valid, rest empty",
              (uint16_t)(env[2] & 0xFFFF), 0x3FFF);

    uint16_t fx[2] = {0, 0};
    seam_fxam(fx, 2.5);
    /* fxam: C3/C2/C0 in bits 14/10/8; ignore C1 (sign) and TOP. */
    check_u16("D/fxam normal after seam", (uint16_t)(fx[0] & 0x4500), 0x0400);
    check_u16("D/fxam empty after pop+seam", (uint16_t)(fx[1] & 0x4500), 0x4100);

    uint16_t sw = seam_fcom_pop(2.0, 3.0);  /* ST0=3 > ST1=2: C3=C2=C0=0 */
    check_u16("E/fcom C-bits across seam (3 > 2)", (uint16_t)(sw & 0x4500), 0);
    check_u16("E/fcom TOP in fnstsw (2 pushes)", TOP_OF(sw), 6);

    if (failures) {
        printf("%d test(s) FAILED.\n", failures);
        return 1;
    }
    printf("All tests PASSED.\n");
    return 0;
}
