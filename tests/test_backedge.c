/*
 * test_backedge.c — OPT-BE: self-loop back edges retargeted past the priming
 * st[] load in decode-verified accumulator blocks
 * (ROSETTA_X87_DISABLE_BACKEDGE=1 reverts to stock back edges).
 *
 * The transform keeps the slot store (store-through) and skips only the
 * reload on the back-edge path, so every shape here checks VALUE fidelity
 * over long loops — under both native Rosetta and this runtime, whichever
 * path (patched or declined) the block takes:
 *   - plain fadd/fmul/fsub accumulators (the qualifying shape);
 *   - accumulators with extra guest-memory traffic in the body (stores
 *     can't alias X87State — must still qualify and stay exact);
 *   - an operand REWRITTEN by the loop body each iteration (the operand
 *     load is after the skip target, so it must be re-executed);
 *   - a parked ST(1) below the accumulator (entry TOP differs from 0);
 *   - fnstsw inside the loop (state read in the body — decline shape);
 *   - fld/faddp inside the loop (tag traffic in the body — decline shape);
 *   - re-entry and nested-loop shapes (every entry must re-prime through
 *     the full prefix).
 *
 * Expected values are exact in double arithmetic (sums of 0.5, products of
 * 2.0, etc.), so plain == comparison is used throughout.
 *
 * Build: clang -arch x86_64 -O0 -o test_backedge test_backedge.c -lm
 */
#include <stdint.h>
#include <stdio.h>

static int failures = 0;

static void check_d(const char *name, double got, double expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ── the qualifying shape: fldz; 1: faddl m; dec; jnz ───────────────────── */

__attribute__((noinline)) static double acc_fadd(double step, int n) {
    double r;
    __asm__ volatile(
        "fldz\n\t"
        "1:\n\t"
        "faddl %2\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n)
        : "m"(step)
        : "cc");
    return r;
}

__attribute__((noinline)) static double acc_fmul(double f, int n) {
    double r;
    __asm__ volatile(
        "fld1\n\t"
        "1:\n\t"
        "fmull %2\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n)
        : "m"(f)
        : "cc");
    return r;
}

__attribute__((noinline)) static double acc_fsub(double start, double step, int n) {
    double r;
    __asm__ volatile(
        "fldl  %2\n\t"
        "1:\n\t"
        "fsubl %3\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n)
        : "m"(start), "m"(step)
        : "cc");
    return r;
}

/* Guest store in the body: the loop also writes the counter to memory each
 * iteration. Guest memory cannot alias X87State, so this must stay a
 * qualifying shape — and stay exact. */
__attribute__((noinline)) static double acc_with_guest_store(double step, int n) {
    double r;
    volatile int sink = 0;
    __asm__ volatile(
        "fldz\n\t"
        "1:\n\t"
        "faddl %3\n\t"
        "movl  %1, %2\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n), "+m"(sink)
        : "m"(step)
        : "cc");
    return r;
}

/* The operand itself changes every iteration: body stores i (as int) into a
 * slot read back through fildl-free path — here simply alternate the operand
 * between two doubles by overwriting it from a register-held pattern. The
 * operand load sits AFTER the skip target and must be re-executed. */
__attribute__((noinline)) static double acc_mutating_operand(int n) {
    double r;
    double operand = 1.0;
    uint64_t two = 0x4000000000000000ull; /* 2.0 */
    __asm__ volatile(
        "fldz\n\t"
        "1:\n\t"
        "faddl %2\n\t"
        "movq  %3, %2\n\t" /* operand = 2.0 from iteration 2 on */
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n), "+m"(operand)
        : "r"(two)
        : "cc");
    return r; /* 1.0 + 2.0*(n-1) */
}

/* Parked ST(1) below the accumulator: entry TOP differs from the plain
 * shape; the parked slot must be untouched by the patched loop. */
__attribute__((noinline)) static double acc_parked_st1(double parked, double step, int n) {
    double r;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fldz\n\t"
        "1:\n\t"
        "faddl %3\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "faddp %%st(0), %%st(1)\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n)
        : "m"(parked), "m"(step)
        : "cc");
    return r; /* parked + step*n */
}

/* fnstsw inside the loop: a state read in the body — decline shape, value
 * must still be exact and TOP must read back correct after the loop. */
__attribute__((noinline)) static double acc_fnstsw_inside(double step, int n, uint16_t *sw_out) {
    double r;
    uint16_t sw;
    __asm__ volatile(
        "fldz\n\t"
        "1:\n\t"
        "faddl %3\n\t"
        "fnstsw %%ax\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fnstsw %2\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n), "=m"(sw)
        : "m"(step)
        : "cc", "ax");
    *sw_out = sw;
    return r;
}

/* fld/faddp pair inside the loop: push/pop tag traffic in the body —
 * decline shape, semantically the same accumulation. */
__attribute__((noinline)) static double acc_fld_faddp(double step, int n) {
    double r;
    __asm__ volatile(
        "fldz\n\t"
        "1:\n\t"
        "fldl  %2\n\t"
        "faddp %%st(0), %%st(1)\n\t"
        "decl  %1\n\t"
        "jnz   1b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(n)
        : "m"(step)
        : "cc");
    return r;
}

/* Nested: outer loop re-enters the inner accumulator loop repeatedly; every
 * entry lands on the block head and must re-prime through the full prefix. */
__attribute__((noinline)) static double acc_nested(double step, int inner, int outer) {
    double r;
    __asm__ volatile(
        "fldz\n\t"
        "2:\n\t"
        "movl  %2, %%ecx\n\t"
        "1:\n\t"
        "faddl %3\n\t"
        "decl  %%ecx\n\t"
        "jnz   1b\n\t"
        "decl  %1\n\t"
        "jnz   2b\n\t"
        "fstpl %0\n\t"
        : "=m"(r), "+r"(outer)
        : "r"(inner), "m"(step)
        : "cc", "ecx");
    return r;
}

int main(void) {
    const int N = 100000;

    check_d("acc_fadd 0.5 x 100000", acc_fadd(0.5, N), 50000.0);
    check_d("acc_fadd 1.25 x 12345", acc_fadd(1.25, 12345), 15431.25);
    check_d("acc_fmul 2.0 x 50", acc_fmul(2.0, 50), 1125899906842624.0);
    check_d("acc_fsub 100000 - 0.25 x 100000", acc_fsub(100000.0, 0.25, N), 75000.0);
    check_d("acc_with_guest_store", acc_with_guest_store(0.5, N), 50000.0);
    check_d("acc_mutating_operand", acc_mutating_operand(N), 1.0 + 2.0 * (N - 1));
    check_d("acc_parked_st1", acc_parked_st1(7.5, 0.5, N), 7.5 + 50000.0);

    uint16_t sw = 0xffff;
    check_d("acc_fnstsw_inside value", acc_fnstsw_inside(0.5, N, &sw), 50000.0);
    /* One value on the stack when fnstsw ran -> TOP == 7. */
    check_d("acc_fnstsw_inside TOP", (double)((sw >> 11) & 7), 7.0);

    check_d("acc_fld_faddp", acc_fld_faddp(0.5, N), 50000.0);
    check_d("acc_nested 100x1000", acc_nested(0.5, 1000, 100), 50000.0);

    /* Re-entry: same translated fragment, fresh priming each call. */
    check_d("re-entry a", acc_fadd(2.0, 1000), 2000.0);
    check_d("re-entry b", acc_fadd(4.0, 500), 2000.0);
    check_d("re-entry c", acc_fmul(0.5, 20), 1.0 / 1048576.0);

    if (failures == 0) {
        printf("ALL PASS  (0 failures)\n");
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
