/*
 * test_store_forward.c — end-to-end test for store-forwarding conflict detection
 *
 * These tests exercise the pattern where Rosetta's store-forwarding elision
 * can cause stale reads:
 *
 *   MOVSD [rbp-N], xmmK    <- SysV ABI param spill (Rosetta may elide ARM STR)
 *   FLD   [rbp-N]          <- fusion emits ARM LDR (reads stale if STR elided)
 *   FADDP / FCOMP / FSTP   <- fusion partner
 *
 * The fix (is_memory_fld_with_store_conflict) detects the preceding non-x87
 * store to the same address and rejects the fusion, falling back to safe
 * non-fused translation.
 *
 * We can't force Rosetta's forwarding from test code, but these functions
 * maximize the probability by using double params (SysV xmm0/xmm1 -> MOVSD
 * spill) with minimal instructions between the spill and FLD reload.
 *
 * Build:  clang -arch x86_64 -O0 -o test_store_forward test_store_forward.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_f64(const char *name, double got, double expected)
{
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected)
{
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ========================================================================= */
/* 2-instruction fusions: FLD [mem] + FADDP / FSUBP / FSTP                  */
/* ========================================================================= */

/*
 * FLD + FADDP:  ST(0) = a + a = 2*a
 *
 * At -O0 the compiler spills `a` (xmm0) to [rbp-8] with MOVSD, then the
 * inline asm does FLD [rbp-8].  Minimal gap between store and reload.
 */
__attribute__((noinline))
static double fld_faddp(double a)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"                       /* FLD [a] — may conflict with param spill */
        "fldl %1\n"                       /* FLD [a] again */
        "faddp %%st, %%st(1)\n"           /* a + a */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a)
    );
    return result;
}

/*
 * FLD + FSUBP:  ST(0) = a - a = 0.0
 */
__attribute__((noinline))
static double fld_fsubp(double a)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"
        "fldl %1\n"
        "fsubrp %%st, %%st(1)\n"          /* GAS AT&T: fsubrp encodes FSUBP */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a)
    );
    return result;
}

/*
 * FLD + FSTP m64:  load a from memory, store to result.  Should be identity.
 */
__attribute__((noinline))
static double fld_fstp(double a)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a)
    );
    return result;
}

/* ========================================================================= */
/* 3-instruction fusions: FLD + FCOMP + FSTSW, FLD + FADD + FSTP            */
/* ========================================================================= */

/*
 * FLD + FCOMP + FSTSW:  compare a with 0.0, return status word.
 * For a > 0:  C3=0 C2=0 C0=0 → AX = 0x3x00 (status bits in 0x4500 mask = 0x0000)
 */
__attribute__((noinline))
static uint16_t fld_fcomp_fstsw(double a)
{
    uint16_t sw;
    __asm__ volatile (
        "fldz\n"                          /* ST(0) = 0.0 */
        "fldl %1\n"                       /* ST(0) = a, ST(1) = 0.0 */
        "fcomp %%st(1)\n"                 /* compare a vs 0.0, pop */
        "fnstsw %0\n"
        "fstp %%st(0)\n"                  /* clean stack */
        : "=m" (sw)
        : "m" (a)
    );
    return sw & 0x4500;                   /* mask to condition bits C0,C2,C3 */
}

/*
 * FLD + FADD + FSTP (3-instr fusion):  ST(0) += a  →  result = existing + a
 * We load 1.0 first, then add a via FLD+FADD+FSTP.  Result = 1.0 + a.
 */
__attribute__((noinline))
static double fld_arith_fstp(double a)
{
    double result;
    __asm__ volatile (
        "fld1\n"                          /* ST(0) = 1.0 */
        "fldl %1\n"                       /* ST(0) = a, ST(1) = 1.0 */
        "faddp %%st, %%st(1)\n"           /* ST(0) = 1.0 + a */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a)
    );
    return result;
}

/* ========================================================================= */
/* Two-parameter tests: both params go through MOVSD spill                   */
/* ========================================================================= */

/*
 * FLD + FADDP with two spilled params:  result = a + b
 */
__attribute__((noinline))
static double fld_faddp_two_params(double a, double b)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"                       /* ST(0) = a */
        "fldl %2\n"                       /* ST(0) = b, ST(1) = a */
        "faddp %%st, %%st(1)\n"           /* ST(0) = a + b */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a), "m" (b)
    );
    return result;
}

/*
 * FLD + FSUBP with two spilled params:  result = a - b
 */
__attribute__((noinline))
static double fld_fsubp_two_params(double a, double b)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"                       /* ST(0) = a */
        "fldl %2\n"                       /* ST(0) = b, ST(1) = a */
        "fsubrp %%st, %%st(1)\n"          /* GAS: fsubrp encodes FSUBP: ST(1)-ST(0) = a-b */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a), "m" (b)
    );
    return result;
}

/*
 * FLD + FMULP with two spilled params:  result = a * b
 */
__attribute__((noinline))
static double fld_fmulp_two_params(double a, double b)
{
    double result;
    __asm__ volatile (
        "fldl %1\n"                       /* ST(0) = a */
        "fldl %2\n"                       /* ST(0) = b, ST(1) = a */
        "fmulp %%st, %%st(1)\n"           /* ST(0) = a * b */
        "fstpl %0\n"
        : "=m" (result)
        : "m" (a), "m" (b)
    );
    return result;
}

/* ========================================================================= */
/* Entry point                                                               */
/* ========================================================================= */

int main(void)
{
    printf("=== Store-forwarding conflict: 2-instr fusions ===\n");

    /* Multiple calls with different values to defeat lucky zero-init */
    check_f64("FLD+FADDP  fld_faddp(3.0) = 6.0",
              fld_faddp(3.0), 6.0);
    check_f64("FLD+FADDP  fld_faddp(7.5) = 15.0",
              fld_faddp(7.5), 15.0);
    check_f64("FLD+FADDP  fld_faddp(-2.25) = -4.5",
              fld_faddp(-2.25), -4.5);

    check_f64("FLD+FSUBP  fld_fsubp(42.0) = 0.0",
              fld_fsubp(42.0), 0.0);
    check_f64("FLD+FSUBP  fld_fsubp(-1.5) = 0.0",
              fld_fsubp(-1.5), 0.0);

    check_f64("FLD+FSTP   fld_fstp(3.14159) = 3.14159",
              fld_fstp(3.14159265358979), 3.14159265358979);
    check_f64("FLD+FSTP   fld_fstp(-99.5) = -99.5",
              fld_fstp(-99.5), -99.5);
    check_f64("FLD+FSTP   fld_fstp(1e300) = 1e300",
              fld_fstp(1e300), 1e300);

    printf("\n=== Store-forwarding conflict: 3-instr fusions ===\n");

    /* FCOMP: a > 0 → C3=0 C2=0 C0=0 → masked = 0x0000 */
    check_u16("FLD+FCOMP+FSTSW  fld_fcomp_fstsw(5.0) flags",
              fld_fcomp_fstsw(5.0), 0x0000);
    /* a < 0 → C0=1 → masked = 0x0100 */
    check_u16("FLD+FCOMP+FSTSW  fld_fcomp_fstsw(-3.0) flags",
              fld_fcomp_fstsw(-3.0), 0x0100);
    /* a == 0 → C3=1 → masked = 0x4000 */
    check_u16("FLD+FCOMP+FSTSW  fld_fcomp_fstsw(0.0) flags",
              fld_fcomp_fstsw(0.0), 0x4000);

    check_f64("FLD+FADD+FSTP  fld_arith_fstp(2.5) = 3.5",
              fld_arith_fstp(2.5), 3.5);
    check_f64("FLD+FADD+FSTP  fld_arith_fstp(-1.0) = 0.0",
              fld_arith_fstp(-1.0), 0.0);
    check_f64("FLD+FADD+FSTP  fld_arith_fstp(0.0) = 1.0",
              fld_arith_fstp(0.0), 1.0);

    printf("\n=== Store-forwarding conflict: two-param fusions ===\n");

    check_f64("FLD+FADDP  two_params(3.0, 4.0) = 7.0",
              fld_faddp_two_params(3.0, 4.0), 7.0);
    check_f64("FLD+FADDP  two_params(-1.5, 2.5) = 1.0",
              fld_faddp_two_params(-1.5, 2.5), 1.0);

    check_f64("FLD+FSUBP  two_params(10.0, 3.0) = 7.0",
              fld_fsubp_two_params(10.0, 3.0), 7.0);
    check_f64("FLD+FSUBP  two_params(1.0, 1.0) = 0.0",
              fld_fsubp_two_params(1.0, 1.0), 0.0);

    check_f64("FLD+FMULP  two_params(3.0, 4.0) = 12.0",
              fld_fmulp_two_params(3.0, 4.0), 12.0);
    check_f64("FLD+FMULP  two_params(-2.0, 5.0) = -10.0",
              fld_fmulp_two_params(-2.0, 5.0), -10.0);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
