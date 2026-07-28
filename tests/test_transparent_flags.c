/*
 * test_transparent_flags.c — TRANSPARENT_FLAGS: xor r,r zero idiom inside
 * x87 runs.
 *
 * Under ROSETTA_X87_TRANSPARENT_FLAGS=1 a self-xor whose flag results are
 * provably dead (Rosetta's flag_liveness == 0) is consumed mid-run as
 * GuestMovRI 0 instead of ending IR consumption.  The consumed form emits no
 * flag writes, so correctness depends entirely on the liveness gate.  These
 * tests pin down both sides:
 *   - consumed: register is zeroed, surrounding x87 results unchanged
 *   - flags LIVE (a jcc/setcc/fcmov reads them before redefinition): the
 *     idiom must NOT be consumed — the xor's architectural flag effects
 *     (ZF=1, CF=0, PF=1, SF=0, OF=0) must be observable
 *
 * The mixed fp/int shapes mirror the hot decline cluster in the WoW binary
 * (matrix-scale: fld/fmul/fst interleaved with xor+mov zero-stores).
 *
 * Build: clang -arch x86_64 -O0 -o test_transparent_flags test_transparent_flags.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

static void check_u(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%llx  expected=0x%llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f(const char *name, float got, float expected) {
    uint32_t a, b;
    memcpy(&a, &got, 4); memcpy(&b, &expected, 4);
    if (a != b) {
        printf("FAIL  %-55s  got=%.9g  expected=%.9g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* WoW matrix-scale shape: fld/fmul/fst run with xor+mov zero-stores in the
 * middle.  Flags die at the trailing `test` — the xor is consumable. */
static void wow_scale_shape(float s, float *v /* [4]: in-out, [3] zeroed */,
                            uint32_t *zeroed) {
    uint32_t z;
    __asm__ volatile(
        "flds %2\n"
        "xorl %%eax, %%eax\n"        /* zero idiom, flags dead (test below) */
        "fmuls (%1)\n"
        "movl %%eax, 12(%1)\n"       /* zero-store through eax */
        "fsts (%1)\n"
        "flds %2\n"
        "fmuls 4(%1)\n"
        "fstps 4(%1)\n"
        "flds %2\n"
        "fmuls 8(%1)\n"
        "fstps 8(%1)\n"
        "fstp %%st(0)\n"
        "movl %%eax, %0\n"
        "testl %%eax, %%eax\n"       /* full EFLAGS redefinition */
        : "=r"(z) : "r"(v), "m"(s) : "eax", "memory", "cc");
    *zeroed = z;
}

/* 64-bit form: xor rax,rax mid-run (W-write zero-extend covers r64). */
static uint64_t zero64_mid_run(double *a /* [2] */) {
    uint64_t r = 0xDEADBEEFCAFEF00DULL;
    __asm__ volatile(
        "fldl (%1)\n"
        "xorq %%rax, %%rax\n"
        "faddl 8(%1)\n"
        "fstpl (%1)\n"
        "movq %%rax, %0\n"
        "testq %%rax, %%rax\n"
        : "=r"(r) : "r"(a) : "rax", "memory", "cc");
    return r;
}

/* Flags LIVE: a setz reads ZF right after the xor — must not be consumed;
 * the xor's ZF=1 must be observable. */
static uint32_t flags_live_setz(double *a) {
    uint32_t r;
    __asm__ volatile(
        "cmpl $1, %2\n"              /* ZF=0 beforehand (1 != 2) */
        "fldl (%1)\n"
        "xorl %%eax, %%eax\n"        /* ZF=1 — read below, NOT dead */
        "fchs\n"
        "fstpl (%1)\n"
        "setz %%al\n"                /* observes the xor's ZF */
        "movl %%eax, %0\n"
        : "=r"(r) : "r"(a), "r"(2) : "eax", "memory", "cc");
    return r;  /* al = 1 iff the xor's ZF survived */
}

/* Flags LIVE via CF: jnc after the xor (CF=0 from xor; CF=1 beforehand). */
static uint32_t flags_live_carry(double *a) {
    uint32_t r;
    __asm__ volatile(
        "movl $0, %0\n"
        "cmpl $5, %2\n"              /* 2 < 5 -> CF=1 beforehand */
        "fldl (%1)\n"
        "xorl %%ecx, %%ecx\n"        /* CF=0 — read below, NOT dead */
        "fabs\n"
        "fstpl (%1)\n"
        "jc 1f\n"                    /* taken only if xor's CF clear lost */
        "movl $1, %0\n"              /* correct path: CF==0 */
        "1:\n"
        : "+r"(r) : "r"(a), "r"(2) : "ecx", "memory", "cc");
    return r;  /* 1 iff the xor's CF=0 survived */
}

/* fcomi + xor + fcmovb: the fcmov reads CF/ZF/PF — the xor between them
 * redefines exactly those flags, so it must not be consumed AND its own
 * flag writes must be materialized (fcmovb sees the xor's CF=0). */
static double fcomi_xor_fcmov(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %2\n"                  /* st1 = b */
        "fldl %1\n"                  /* st0 = a */
        "fcomi %%st(1), %%st\n"      /* CF = (a < b) */
        "xorl %%edx, %%edx\n"        /* CF=0 — overrides the compare! */
        "fcmovb %%st(1), %%st\n"     /* never moves: CF is 0 */
        "fstpl %0\n"
        "fstp %%st(0)\n"
        : "=m"(out) : "m"(a), "m"(b) : "edx", "cc");
    return out;  /* always a: the xor killed the fcomi's CF */
}

int main(void) {
    float v[4] = {2.0f, 3.0f, 4.0f, 55.5f};
    uint32_t z = 0x12345678;
    wow_scale_shape(1.5f, v, &z);
    check_f("wow-shape: v[0] = 2*1.5", v[0], 3.0f);
    check_f("wow-shape: v[1] = 3*1.5", v[1], 4.5f);
    check_f("wow-shape: v[2] = 4*1.5", v[2], 6.0f);
    check_f("wow-shape: v[3] zero-stored via eax", v[3], 0.0f);
    check_u("wow-shape: eax zeroed", z, 0);

    double d[2] = {1.25, 2.5};
    check_u("xor rax,rax mid-run", zero64_mid_run(d), 0);
    check_u("  (fp result intact)", d[0] == 3.75, 1);

    double s = 7.0;
    check_u("flags live: setz observes xor's ZF=1", flags_live_setz(&s), 1);
    check_u("  (fchs applied)", s == -7.0, 1);

    double c = -3.0;
    check_u("flags live: jc observes xor's CF=0", flags_live_carry(&c), 1);
    check_u("  (fabs applied)", c == 3.0, 1);

    check_u("fcomi/xor/fcmovb: xor's CF=0 wins", fcomi_xor_fcmov(1.0, 9.0) == 1.0, 1);

    if (failures == 0)
        printf("ALL TESTS PASSED (11 tests)\n");
    else
        printf("%d TESTS FAILED\n", failures);
    return failures != 0;
}
