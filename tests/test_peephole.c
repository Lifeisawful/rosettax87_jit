/*
 * test_peephole.c — validate peephole fusion patterns
 *
 * Build:  gcc -O0 -mfpmath=387 -o test_peephole test_peephole.c
 *
 * Each test exercises a specific 2-instruction pair that the peephole
 * optimizer may fuse.  The expected values are computed by hand from
 * the x87 semantics.
 *
 * Pattern 1:  FLD variant + FADDP/FSUBP/FSUBRP/FMULP/FDIVP/FDIVRP ST(1)
 * Pattern 2:  FLD variant + FSTP ST(1) or FSTP m32/m64
 * Pattern 3:  FXCH ST(1) + FADDP/FSUBP/FMULP/FDIVP ST(1)
 * Pattern 4:  FXCH ST(1) + FSTP ST(1)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;

static uint32_t as_u32(float f)  { uint32_t u; memcpy(&u, &f, 4); return u; }
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_f32(const char *name, float got, float expected)
{
    if (as_u32(got) != as_u32(expected)) {
        printf("FAIL  %-55s  got=%.10g (0x%08x)  expected=%.10g (0x%08x)\n",
               name, got, as_u32(got), expected, as_u32(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f64(const char *name, double got, double expected)
{
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ========================================================================= */
/* Pattern 1: FLD + popping arithmetic fusion                                */
/* ========================================================================= */

/* FLD ST(i) + FADDP ST(1)
 * Stack: ST(0)=5.0, ST(1)=3.0.  FLD ST(1) pushes 3.0 → ST(0)=3.0, ST(1)=5.0, ST(2)=3.0.
 * FADDP ST(1): ST(1)=5.0+3.0=8.0, pop → ST(0)=8.0, ST(1)=3.0.
 * Net from the perspective of the pre-FLD stack: ST(0) = old_ST(0) + old_ST(1) = 5+3 = 8.
 * We read ST(0) then pop to get to 3.0.
 */
static float test_p1_fld_reg_faddp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* ST(0)=5.0, ST(1)=3.0 */
        "fld %%st(1)\n"       /* push 3.0 */
        "faddp %%st, %%st(1)\n" /* 5.0 + 3.0 = 8.0 */
        "fstps %0\n"
        "fstp %%st(0)\n"      /* clean stack */
        : "=m" (result)
    );
    return result;
}

/* FLD ST(0) + FSUBP ST(1)
 * FSUBP ST(1),ST(0) computes new_ST(1) - new_ST(0).
 * FLD ST(0) duplicates ST(0). After push: new_ST(0)=A, new_ST(1)=A.
 * FSUBP: A - A = 0.0.
 * Start with ST(0)=7.0.  Net: ST(0) = 0.0.
 */
static float test_p1_fld_st0_fsubp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* ST(0)=7.0 */
        "fld %%st(0)\n"
        "fsubp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FLD ST(1) + FSUBRP ST(1)
 * Stack before: ST(0)=10.0, ST(1)=3.0.
 * FLD ST(1): push 3.0 → ST(0)=3.0, ST(1)=10.0, ST(2)=3.0.
 *
 * NOTE: GAS AT&T syntax swaps fsubrp↔fsubp for register popping forms.
 * `fsubrp %st, %st(1)` actually encodes FSUBP (DE E0+i).
 * FSUBP: ST(1) - ST(0) = 10.0 - 3.0 = 7.0.
 */
static float test_p1_fld_reg_fsubrp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 — will be ST(1) */
        /* build 10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* ST(0)=10.0, ST(1)=3.0 */
        "fld %%st(1)\n"
        "fsubrp %%st, %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* FLD ST(1) + FMULP ST(1)
 * Stack: ST(0)=5.0, ST(1)=3.0.
 * FLD ST(1) pushes 3.0.  FMULP: 5.0 * 3.0 = 15.0.
 */
static float test_p1_fld_reg_fmulp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        /* ST(0)=5.0, ST(1)=3.0 */
        "fld %%st(1)\n"
        "fmulp %%st, %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* FLD ST(1) + FDIVP ST(1)
 * Stack: ST(0)=6.0, ST(1)=3.0.
 * FLD ST(1) pushes 3.0 → new_ST(0)=3.0, new_ST(1)=6.0.
 *
 * NOTE: GAS AT&T swaps fdivp↔fdivrp for register popping forms.
 * `fdivp %st, %st(1)` actually encodes FDIVRP (DE F8+i).
 * FDIVRP: ST(0)/ST(1) = 3.0/6.0 = 0.5.
 */
static float test_p1_fld_reg_fdivp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        /* ST(0)=6.0, ST(1)=3.0 */
        "fld %%st(1)\n"
        "fdivp %%st, %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* FLD ST(1) + FDIVRP ST(1)
 * Stack: ST(0)=6.0, ST(1)=3.0.
 * FLD ST(1) pushes 3.0 → new_ST(0)=3.0, new_ST(1)=6.0.
 *
 * NOTE: GAS AT&T swaps fdivp↔fdivrp for register popping forms.
 * `fdivrp %st, %st(1)` actually encodes FDIVP (DE F0+i).
 * FDIVP: ST(1)/ST(0) = 6.0/3.0 = 2.0.
 */
static float test_p1_fld_reg_fdivrp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        /* ST(0)=6.0, ST(1)=3.0 */
        "fld %%st(1)\n"
        "fdivrp %%st, %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* FLD m64fp + FADDP ST(1)
 * ST(0)=1.0.  FLD m64 pushes 2.5.  FADDP: 1.0 + 2.5 = 3.5.
 */
static float test_p1_fld_m64_faddp(void)
{
    float result;
    double mem = 2.5;
    __asm__ volatile (
        "fld1\n"
        "fldl %1\n"
        "faddp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
        : "m" (mem)
    );
    return result;
}

/* FLD m32fp + FMULP ST(1)
 * ST(0)=3.0.  FLD m32 pushes 4.0.  FMULP: 3.0 * 4.0 = 12.0.
 */
static float test_p1_fld_m32_fmulp(void)
{
    float result, mem = 4.0f;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "flds %1\n"
        "fmulp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
        : "m" (mem)
    );
    return result;
}

/* FLDZ + FADDP ST(1)
 * ST(0)=7.0.  FLDZ pushes 0.0.  FADDP: 7.0 + 0.0 = 7.0.
 */
static float test_p1_fldz_faddp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 7.0 */
        "fldz\n"
        "faddp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FLD1 + FMULP ST(1)
 * ST(0)=5.0.  FLD1 pushes 1.0.  FMULP: 5.0 * 1.0 = 5.0.
 */
static float test_p1_fld1_fmulp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n"
        "fmulp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FILD m32 + FADDP ST(1)
 * ST(0)=1.5 (loaded from memory).  FILD pushes 10.  FADDP: 1.5 + 10.0 = 11.5.
 */
static float test_p1_fild_m32_faddp(void)
{
    float result;
    float start = 1.5f;
    int32_t ival = 10;
    __asm__ volatile (
        "flds %1\n"
        "fildl %2\n"
        "faddp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
        : "m" (start), "m" (ival)
    );
    return result;
}

/* ========================================================================= */
/* Pattern 2: FLD + FSTP fusion (copy elimination)                           */
/* ========================================================================= */

/* FLD ST(2) + FSTP ST(1)
 * Stack: ST(0)=1.0, ST(1)=2.0, ST(2)=3.0.
 * FLD ST(2) pushes 3.0 → new ST(0)=3.0, ST(1)=1.0, ST(2)=2.0, ST(3)=3.0.
 * FSTP ST(1): store 3.0→ST(1), pop → ST(0)=3.0, ST(1)=2.0, ST(2)=3.0.
 * Net: ST(0) = old_ST(2) = 3.0.
 */
static float test_p2_fld_reg_fstp_st1(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        "fld1\n"                                   /* 1.0 */
        /* ST(0)=1.0, ST(1)=2.0, ST(2)=3.0 */
        "fld %%st(2)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* FLD m64 + FSTP ST(1)
 * ST(0)=1.0.  FLD m64 pushes 9.25.  FSTP ST(1): overwrite, pop → ST(0) = 9.25.
 */
static float test_p2_fld_m64_fstp_st1(void)
{
    float result;
    double mem = 9.25;
    __asm__ volatile (
        "fld1\n"
        "fldl %1\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
        : "m" (mem)
    );
    return result;
}

/* FLD m64 + FSTP m64 (memory-to-memory copy)
 * Loads 3.14 from src, stores to dst.  Stack unchanged (push+pop cancel).
 */
static void test_p2_fld_m64_fstp_m64(double *dst, const double *src)
{
    __asm__ volatile (
        "fldl %1\n"
        "fstpl %0\n"
        : "=m" (*dst)
        : "m" (*src)
    );
}

/* FLD m32 + FSTP m32 (memory-to-memory copy, f32)
 * Loads 2.5f from src, stores to dst.
 */
static void test_p2_fld_m32_fstp_m32(float *dst, const float *src)
{
    __asm__ volatile (
        "flds %1\n"
        "fstps %0\n"
        : "=m" (*dst)
        : "m" (*src)
    );
}

/* FLDZ + FSTP ST(1)
 * ST(0)=7.0.  FLDZ pushes 0.0.  FSTP ST(1): overwrite, pop → ST(0) = 0.0.
 */
static float test_p2_fldz_fstp_st1(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 7.0 */
        "fldz\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* ========================================================================= */
/* Pattern 3: FXCH ST(1) + popping arithmetic fusion                         */
/* ========================================================================= */

/* FXCH ST(1) + FADDP ST(1)  — commutative, FXCH is a no-op
 * ST(0)=2.0, ST(1)=3.0.  FXCH swaps. FADDP: 2.0+3.0=5.0.
 */
static float test_p3_fxch_faddp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=3.0 */
        "fxch %%st(1)\n"
        "faddp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FXCH ST(1) + FMULP ST(1)  — commutative
 * ST(0)=4.0, ST(1)=3.0.  4*3=12.
 */
static float test_p3_fxch_fmulp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 4.0 */
        /* ST(0)=4.0, ST(1)=3.0 */
        "fxch %%st(1)\n"
        "fmulp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FXCH ST(1) + FSUBP ST(1)  — non-commutative
 * ST(0)=2.0, ST(1)=5.0.
 * FXCH: ST(0)=5.0, ST(1)=2.0.
 *
 * NOTE: GAS AT&T swaps fsubp↔fsubrp for register popping forms.
 * `fsubp %st, %st(1)` actually encodes FSUBRP (DE E8+i).
 * FSUBRP: ST(0)-ST(1) = 5.0-2.0 = 3.0.
 */
static float test_p3_fxch_fsubp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=5.0 */
        "fxch %%st(1)\n"
        "fsubp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FXCH ST(1) + FSUBRP ST(1)
 * ST(0)=2.0, ST(1)=5.0.
 * FXCH: ST(0)=5.0, ST(1)=2.0.
 *
 * NOTE: GAS AT&T swaps fsubp↔fsubrp for register popping forms.
 * `fsubrp %st, %st(1)` actually encodes FSUBP (DE E0+i).
 * FSUBP: ST(1)-ST(0) = 2.0-5.0 = -3.0.
 */
static float test_p3_fxch_fsubrp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=5.0 */
        "fxch %%st(1)\n"
        "fsubrp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FXCH ST(1) + FDIVP ST(1)
 * ST(0)=2.0, ST(1)=6.0.
 * FXCH: ST(0)=6.0, ST(1)=2.0.
 *
 * NOTE: GAS AT&T swaps fdivp↔fdivrp for register popping forms.
 * `fdivp %st, %st(1)` actually encodes FDIVRP (DE F8+i).
 * FDIVRP: ST(0)/ST(1) = 6.0/2.0 = 3.0.
 */
static float test_p3_fxch_fdivp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=6.0 */
        "fxch %%st(1)\n"
        "fdivp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* FXCH ST(1) + FDIVRP ST(1)
 * ST(0)=2.0, ST(1)=6.0.
 * FXCH: ST(0)=6.0, ST(1)=2.0.
 *
 * NOTE: GAS AT&T swaps fdivp↔fdivrp for register popping forms.
 * `fdivrp %st, %st(1)` actually encodes FDIVP (DE F0+i).
 * FDIVP: ST(1)/ST(0) = 2.0/6.0 = 0.333...
 */
static float test_p3_fxch_fdivrp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=6.0 */
        "fxch %%st(1)\n"
        "fdivrp %%st, %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* ========================================================================= */
/* Pattern 4: FXCH ST(1) + FSTP ST(1) → just pop                            */
/* ========================================================================= */

/* ST(0)=2.0, ST(1)=5.0.
 * FXCH: ST(0)=5.0, ST(1)=2.0.
 * FSTP ST(1): store 5.0→ST(1), pop → new ST(0) = 5.0.
 * Equivalent to: just pop → new ST(0) = 5.0.
 */
static float test_p4_fxch_fstp_st1(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=5.0 */
        "fxch %%st(1)\n"
        "fstp %%st(1)\n"
        "fstps %0\n"
        : "=m" (result)
    );
    return result;
}

/* Same pattern but verify ST(1) is correctly preserved below.
 * ST(0)=2.0, ST(1)=5.0, ST(2)=9.0.
 * FXCH+FSTP ST(1) → pop → new ST(0)=5.0, new ST(1)=9.0.
 * Verify both.
 */
static void test_p4_fxch_fstp_st1_deep(float *r0, float *r1)
{
    __asm__ volatile (
        /* build stack: ST(0)=2.0, ST(1)=5.0, ST(2)=9.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 9.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld1\n fld1\n faddp\n"                   /* 2.0 */
        /* ST(0)=2.0, ST(1)=5.0, ST(2)=9.0 */
        "fxch %%st(1)\n"
        "fstp %%st(1)\n"
        /* now ST(0)=5.0, ST(1)=9.0 */
        "fstps %0\n"
        "fstps %1\n"
        : "=m" (*r0), "=m" (*r1)
    );
}

/* ========================================================================= */
/* Combined: 3-instruction sequence that uses multiple patterns              */
/* ========================================================================= */

/* FLD ST(1) + FADDP + FSTP m32  (pattern 1 then normal FSTP)
 * This confirms fusion doesn't break subsequent instructions.
 * ST(0)=4.0, ST(1)=6.0.  FLD ST(1)+FADDP: 4+6=10.  FSTP m32: store 10.0.
 */
static float test_combined_fld_faddp_fstp(void)
{
    float result;
    __asm__ volatile (
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 6.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 4.0 */
        /* ST(0)=4.0, ST(1)=6.0 */
        "fld %%st(1)\n"
        "faddp %%st, %%st(1)\n"
        "fstps %0\n"
        "fstp %%st(0)\n"
        : "=m" (result)
    );
    return result;
}

/* ========================================================================= */
/* Entry point                                                               */
/* ========================================================================= */

int main(void)
{
    printf("=== Pattern 1: FLD + popping arithmetic ===\n");
    check_f32("P1  FLD ST(1) + FADDP            5+3=8",
              test_p1_fld_reg_faddp(), 8.0f);
    check_f32("P1  FLD ST(0) + FSUBP            7-7=0",
              test_p1_fld_st0_fsubp(), 0.0f);
    check_f32("P1  FLD ST(1) + FSUBRP           (GAS→FSUBP) 10-3=7",
              test_p1_fld_reg_fsubrp(), 7.0f);
    check_f32("P1  FLD ST(1) + FMULP            5*3=15",
              test_p1_fld_reg_fmulp(), 15.0f);
    check_f32("P1  FLD ST(1) + FDIVP            (GAS→FDIVRP) 3/6=0.5",
              test_p1_fld_reg_fdivp(), 0.5f);
    check_f32("P1  FLD ST(1) + FDIVRP           (GAS→FDIVP) 6/3=2",
              test_p1_fld_reg_fdivrp(), 2.0f);
    check_f32("P1  FLD m64 + FADDP              1+2.5=3.5",
              test_p1_fld_m64_faddp(), 3.5f);
    check_f32("P1  FLD m32 + FMULP              3*4=12",
              test_p1_fld_m32_fmulp(), 12.0f);
    check_f32("P1  FLDZ + FADDP                 7+0=7",
              test_p1_fldz_faddp(), 7.0f);
    check_f32("P1  FLD1 + FMULP                 5*1=5",
              test_p1_fld1_fmulp(), 5.0f);
    check_f32("P1  FILD m32 + FADDP             1.5+10=11.5",
              test_p1_fild_m32_faddp(), 11.5f);

    printf("\n=== Pattern 2: FLD + FSTP copy elimination ===\n");
    check_f32("P2  FLD ST(2) + FSTP ST(1)       copy reg 3.0",
              test_p2_fld_reg_fstp_st1(), 3.0f);
    check_f32("P2  FLD m64 + FSTP ST(1)         load 9.25",
              test_p2_fld_m64_fstp_st1(), 9.25f);
    {
        double src = 3.14159265358979, dst = 0.0;
        test_p2_fld_m64_fstp_m64(&dst, &src);
        check_f64("P2  FLD m64 + FSTP m64           mem copy 3.14159",
                  dst, src);
    }
    {
        float src = 2.5f, dst = 0.0f;
        test_p2_fld_m32_fstp_m32(&dst, &src);
        check_f32("P2  FLD m32 + FSTP m32           mem copy 2.5",
                  dst, src);
    }
    check_f32("P2  FLDZ + FSTP ST(1)            zero ST(0)",
              test_p2_fldz_fstp_st1(), 0.0f);

    printf("\n=== Pattern 3: FXCH ST(1) + popping arithmetic ===\n");
    check_f32("P3  FXCH + FADDP                  2+3=5",
              test_p3_fxch_faddp(), 5.0f);
    check_f32("P3  FXCH + FMULP                  4*3=12",
              test_p3_fxch_fmulp(), 12.0f);
    check_f32("P3  FXCH + FSUBP   (GAS→FSUBRP)   5-2=3",
              test_p3_fxch_fsubp(), 3.0f);
    check_f32("P3  FXCH + FSUBRP  (GAS→FSUBP)   2-5=-3",
              test_p3_fxch_fsubrp(), -3.0f);
    check_f32("P3  FXCH + FDIVP   (GAS→FDIVRP)  6/2=3",
              test_p3_fxch_fdivp(), 3.0f);
    check_f32("P3  FXCH + FDIVRP  (GAS→FDIVP)   2/6=0.333",
              test_p3_fxch_fdivrp(), 1.0f/3.0f);

    printf("\n=== Pattern 4: FXCH ST(1) + FSTP ST(1) = pop ===\n");
    check_f32("P4  FXCH + FSTP ST(1)             pop → 5.0",
              test_p4_fxch_fstp_st1(), 5.0f);
    {
        float r0 = 0, r1 = 0;
        test_p4_fxch_fstp_st1_deep(&r0, &r1);
        check_f32("P4  FXCH + FSTP ST(1) deep       ST(0)=5.0",
                  r0, 5.0f);
        check_f32("P4  FXCH + FSTP ST(1) deep       ST(1)=9.0",
                  r1, 9.0f);
    }

    printf("\n=== Combined sequences ===\n");
    check_f32("Combined  FLD ST(1)+FADDP+FSTP    4+6=10",
              test_combined_fld_faddp_fstp(), 10.0f);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}