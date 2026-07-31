/*
 * test_transparent_pushpop.c — TRANSPARENT_PUSHPOP: push/pop consumed inside
 * x87 runs.
 *
 * Under ROSETTA_X87_TRANSPARENT_PUSHPOP=1 push r / push imm / pop r are
 * consumed mid-run as single writeback instructions on guest RSP (Rosetta's
 * own lowering shape), instead of ending IR consumption.  push/pop are
 * flag-neutral so there is no liveness gate; the risks are stack-pointer
 * bookkeeping and the mem-CSE model (a push writes [rsp-slot], so the whole
 * CSE table is dropped conservatively).
 *
 * Shapes mirror the WoW epilogue idiom at 0x5cd28c:
 *   fld; pop edi; fadd; pop esi; fstp
 *
 * Build: clang -arch x86_64 -O0 -o test_transparent_pushpop test_transparent_pushpop.c
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

static void check_d(const char *name, double got, double expected) {
    uint64_t a, b;
    memcpy(&a, &got, 8); memcpy(&b, &expected, 8);
    if (a != b) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* WoW 0x5cd28c epilogue shape: pops interleaved with the x87 chain.  The
 * pushes seed the stack before the run; the pops inside the run must return
 * them in LIFO order while the fp chain computes across them. */
static double epilogue_shape(double *m, uint64_t *r1, uint64_t *r2) {
    double out;
    __asm__ volatile(
        "pushq $0x1111\n"
        "pushq %%rax\n"
        "fldl (%3)\n"
        "popq %%rdi\n"           /* = rax's value */
        "faddl 8(%3)\n"
        "popq %%rsi\n"           /* = 0x1111 */
        "fstpl %0\n"
        "movq %%rdi, %1\n"
        "movq %%rsi, %2\n"
        : "=m"(out), "=m"(*r1), "=m"(*r2)
        : "r"(m), "a"(0xABCD1234CAFE5678ULL)
        : "rdi", "rsi", "memory");
    return out;
}

/* Balanced push/pop pair fully inside one run; value round-trips through the
 * stack slot while the fp value stays live across both. */
static uint64_t roundtrip_mid_run(double *m, uint64_t v) {
    uint64_t r;
    __asm__ volatile(
        "fldl (%2)\n"
        "pushq %1\n"
        "fchs\n"
        "popq %0\n"
        "fstpl (%2)\n"
        : "=r"(r) : "r"(v), "r"(m) : "memory");
    return r;
}

/* push imm forms: positive imm32 and sign-extended imm8. */
static void push_imm_forms(uint64_t *a, uint64_t *b, double *m) {
    __asm__ volatile(
        "fldl (%2)\n"
        "pushq $0x12345678\n"
        "fabs\n"
        "pushq $-5\n"
        "fchs\n"
        "popq %%rcx\n"
        "fstpl (%2)\n"
        "popq %%rdx\n"
        "movq %%rcx, %0\n"
        "movq %%rdx, %1\n"
        : "=m"(*a), "=m"(*b) : "r"(m) : "rcx", "rdx", "memory");
}

/* Decline path: push %rsp stores the OLD rsp value (and Rt==Rn writeback is
 * unpredictable, so build refuses it) — semantics must match native. */
static uint64_t push_rsp_semantics(double *m) {
    uint64_t pushed, before;
    __asm__ volatile(
        "movq %%rsp, %1\n"
        "fldl (%2)\n"
        "pushq %%rsp\n"
        "fchs\n"
        "popq %0\n"
        "fstpl (%2)\n"
        : "=&r"(pushed), "=&r"(before) : "r"(m) : "memory");
    return pushed == before;  /* x86: push rsp stores the pre-push value */
}

/* The pushed slot is really written: read it back through an explicit load
 * before popping (exercises push-store + guest-load through rsp). */
static uint64_t pushed_slot_visible(double *m) {
    uint64_t seen;
    __asm__ volatile(
        "movq $0x00C0FFEE, %%rcx\n"
        "fldl (%1)\n"
        "pushq %%rcx\n"
        "fsqrt\n"
        "movq (%%rsp), %0\n"     /* read the slot the push just wrote */
        "fstpl (%1)\n"
        "popq %%rcx\n"
        /* "=&r": %0 is written before the last read of %1 — without the
         * early-clobber clang shared rax between them (fstpl through the
         * 0xC0FFEE it had just loaded into %0; crashed since the test was
         * introduced, masked by the empty-output suite hole). */
        : "=&r"(seen) : "r"(m) : "rcx", "memory");
    return seen;
}

int main(void) {
    double m[2] = {1.5, 2.25};
    uint64_t r1 = 0, r2 = 0;
    check_d("epilogue shape: fp chain", epilogue_shape(m, &r1, &r2), 3.75);
    check_u("epilogue shape: pop 1 (pushed rax)", r1, 0xABCD1234CAFE5678ULL);
    check_u("epilogue shape: pop 2 (pushed imm)", r2, 0x1111);

    double d = 4.0;
    check_u("push/pop roundtrip mid-run", roundtrip_mid_run(&d, 0xFEEDFACE0BADF00DULL),
            0xFEEDFACE0BADF00DULL);
    check_d("  (fchs applied)", d, -4.0);

    uint64_t a = 0, b = 0;
    double e = -9.0;
    push_imm_forms(&a, &b, &e);
    check_u("push imm8 sign-extended (LIFO first)", a, 0xFFFFFFFFFFFFFFFBULL);
    check_u("push imm32", b, 0x12345678);
    check_d("  (|x| then neg)", e, -9.0);

    double f = 2.0;
    check_u("push rsp declines, old-value semantics hold", push_rsp_semantics(&f), 1);
    check_d("  (fchs applied)", f, -2.0);

    double g = 16.0;
    check_u("pushed slot visible to a load", pushed_slot_visible(&g), 0x00C0FFEE);
    check_d("  (fsqrt applied)", g, 4.0);

    if (failures == 0)
        printf("ALL TESTS PASSED (11 tests)\n");
    else
        printf("%d TESTS FAILED\n", failures);
    return failures != 0;
}
