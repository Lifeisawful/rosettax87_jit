/*
 * test_peephole7.c -- validate memory-operand FCOMP in fld_fcomp_fstsw fusion
 *                     and OPT-D push-pop tag cancellation correctness
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_peephole7 test_peephole7.c
 *
 * Section A:  FLD + FCOMPS/FCOMPL m32/m64 + FNSTSW AX  (3-instr fusion
 *             with memory-operand FCOMP -- the new path added by 35b00f9)
 *
 * Section B:  OPT-D tag cancellation in cache runs -- verifies that
 *             push-pop pairs inside longer x87 sequences produce correct
 *             values and leave the stack in the right state.
 *
 * Section C:  Net-zero fusion + surrounding OPT-D -- exercises the fix
 *             from 53db3b1 where net-zero fusions must not break the
 *             full cancellation of surrounding unfused instructions.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static uint32_t as_u32(float f)  { uint32_t u; memcpy(&u, &f, 4); return u; }
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-60s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f32(const char *name, float got, float expected) {
    if (as_u32(got) != as_u32(expected)) {
        printf("FAIL  %-60s  got=%.10g (0x%08x)  expected=%.10g (0x%08x)\n",
               name, got, as_u32(got), expected, as_u32(expected));
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f64(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-60s  got=%.15g  expected=%.15g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ========================================================================= */
/* Section A: FLD + FCOMPS/FCOMPL mem + FNSTSW AX  (memory-operand fusion)   */
/* ========================================================================= */

/* --- FLD m64 + FCOMPS m32 + FNSTSW --- */

/* GT: FLD [5.0] / FCOMPS [3.0f] -> 5 > 3 -> GT (0x0000) */
static uint16_t test_fld_fcomps_m32_gt(void) {
    double val = 5.0;
    float  cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* LT: FLD [1.0] / FCOMPS [3.0f] -> 1 < 3 -> LT (0x0100) */
static uint16_t test_fld_fcomps_m32_lt(void) {
    double val = 1.0;
    float  cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* EQ: FLD [3.0] / FCOMPS [3.0f] -> 3 == 3 -> EQ (0x4000) */
static uint16_t test_fld_fcomps_m32_eq(void) {
    double val = 3.0;
    float  cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* UN: FLD [NaN] / FCOMPS [1.0f] -> unordered (0x4500) */
static uint16_t test_fld_fcomps_m32_un(void) {
    double val = __builtin_nan("");
    float  cmp = 1.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FLD m64 + FCOMPL m64 + FNSTSW --- */

/* GT: FLD [7.0] / FCOMPL [2.0] -> 7 > 2 -> GT */
static uint16_t test_fld_fcompl_m64_gt(void) {
    double val = 7.0;
    double cmp = 2.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* LT: FLD [2.0] / FCOMPL [7.0] -> 2 < 7 -> LT */
static uint16_t test_fld_fcompl_m64_lt(void) {
    double val = 2.0;
    double cmp = 7.0;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* EQ: FLD [4.5] / FCOMPL [4.5] -> EQ */
static uint16_t test_fld_fcompl_m64_eq(void) {
    double val = 4.5;
    double cmp = 4.5;
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* UN: FLD [1.0] / FCOMPL [NaN] -> unordered */
static uint16_t test_fld_fcompl_m64_un(void) {
    double val = 1.0;
    double cmp = __builtin_nan("");
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FLD m32 + FCOMPS m32 + FNSTSW (m32 source for FLD) --- */

/* GT: FLD [9.0f] / FCOMPS [2.0f] -> GT */
static uint16_t test_flds_fcomps_m32_gt(void) {
    float val = 9.0f;
    float cmp = 2.0f;
    uint16_t sw;
    __asm__ volatile(
        "flds %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* LT: FLD [1.0f] / FCOMPS [5.0f] -> LT */
static uint16_t test_flds_fcomps_m32_lt(void) {
    float val = 1.0f;
    float cmp = 5.0f;
    uint16_t sw;
    __asm__ volatile(
        "flds %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FLD ST(i) + FCOMPS m32 + FNSTSW (register source for FLD) --- */

/* FLD ST(0) + FCOMPS [cmp] + FNSTSW.  ST(0)=5.0, cmp=3.0f -> GT */
static uint16_t test_fld_reg_fcomps_m32_gt(void) {
    float cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n" /* 5.0 */
        "fld %%st(0)\n"
        "fcomps %1\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* FLD ST(0) + FCOMPS [cmp] + FNSTSW.  ST(0)=2.0, cmp=8.0f -> LT */
static uint16_t test_fld_reg_fcomps_m32_lt(void) {
    float cmp = 8.0f;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n" /* 2.0 */
        "fld %%st(0)\n"
        "fcomps %1\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FLD1/FLDZ + FCOMPS m32 + FNSTSW (constant source for FLD) --- */

/* FLD1 + FCOMPS [0.5f] + FNSTSW -> 1 > 0.5 -> GT */
static uint16_t test_fld1_fcomps_m32_gt(void) {
    float cmp = 0.5f;
    uint16_t sw;
    __asm__ volatile(
        "fld1\n"
        "fcomps %1\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* FLDZ + FCOMPS [1.0f] + FNSTSW -> 0 < 1 -> LT */
static uint16_t test_fldz_fcomps_m32_lt(void) {
    float cmp = 1.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldz\n"
        "fcomps %1\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* FLDZ + FCOMPS [0.0f] + FNSTSW -> 0 == 0 -> EQ */
static uint16_t test_fldz_fcomps_m32_eq(void) {
    float cmp = 0.0f;
    uint16_t sw;
    __asm__ volatile(
        "fldz\n"
        "fcomps %1\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FILD m32 + FCOMPS m32 + FNSTSW (integer source for FLD) --- */

/* FILD [10] + FCOMPS [3.0f] + FNSTSW -> 10 > 3 -> GT */
static uint16_t test_fild_fcomps_m32_gt(void) {
    int32_t ival = 10;
    float cmp = 3.0f;
    uint16_t sw;
    __asm__ volatile(
        "fildl %1\n"
        "fcomps %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(ival), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- FLD + FCOMPL m64 + FNSTSW with m32 FLD source --- */

/* FLD [2.5f] + FCOMPL [2.5] + FNSTSW -> EQ */
static uint16_t test_flds_fcompl_m64_eq(void) {
    float  val = 2.5f;
    double cmp = 2.5;
    uint16_t sw;
    __asm__ volatile(
        "flds %1\n"
        "fcompl %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(val), "m"(cmp) : "ax");
    return sw & 0x4500;
}

/* --- Stack correctness: verify FLD+FCOMP_mem+FNSTSW is net-zero --- */

/* Push 99.0, then FLD [5.0] + FCOMPS [3.0f] + FNSTSW.
 * After fusion, ST(0) should be 99.0 (net zero stack effect). */
static double test_fld_fcomps_stack_intact(void) {
    double base = 99.0;
    double val  = 5.0;
    float  cmp  = 3.0f;
    double result;
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"       /* push 99.0 */
        "fldl %3\n"       /* push 5.0 -- will be consumed by fusion */
        "fcomps %4\n"     /* compare 5.0 vs 3.0f, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %1\n"
        "fstpl %0\n"      /* should read 99.0 */
        : "=m"(result), "=m"(sw)
        : "m"(base), "m"(val), "m"(cmp)
        : "ax");
    return result;
}

/* Same for FCOMPL m64 */
static double test_fld_fcompl_stack_intact(void) {
    double base = 77.0;
    double val  = 2.0;
    double cmp  = 9.0;
    double result;
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"       /* push 77.0 */
        "fldl %3\n"       /* push 2.0 */
        "fcompl %4\n"     /* compare 2.0 vs 9.0, pop */
        "fnstsw %%ax\n"
        "movw %%ax, %1\n"
        "fstpl %0\n"      /* should read 77.0 */
        : "=m"(result), "=m"(sw)
        : "m"(base), "m"(val), "m"(cmp)
        : "ax");
    return result;
}

/* ========================================================================= */
/* Section B: OPT-D tag cancellation in cache runs                           */
/* ========================================================================= */

/*
 * Multiple FLD+FADDP pairs in a single cache run.
 * Each pair is a push-pop that should get OPT-D cancellation.
 * Final value verifies all arithmetic is correct despite deferred tags.
 *
 * ST(0)=10.0.  Then: FLD [2.0]/FADDP (=12), FLD [3.0]/FADDP (=15),
 *                     FLD [5.0]/FADDP (=20).
 * Result: 20.0.
 */
static float test_optd_chain_fld_faddp(void) {
    float result;
    double a = 2.0, b = 3.0, c = 5.0;
    __asm__ volatile(
        /* build ST(0) = 10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* three consecutive FLD+FADDP pairs -- OPT-D should cancel each */
        "fldl %1\n faddp %%st, %%st(1)\n"  /* +2 = 12 */
        "fldl %2\n faddp %%st, %%st(1)\n"  /* +3 = 15 */
        "fldl %3\n faddp %%st, %%st(1)\n"  /* +5 = 20 */
        "fstps %0\n"
        : "=m"(result) : "m"(a), "m"(b), "m"(c));
    return result;
}

/*
 * Multiple FLD+FMULP pairs.
 * ST(0)=2.0.  FLD [3.0]/FMULP (=6), FLD [4.0]/FMULP (=24).
 * Result: 24.0.
 */
static float test_optd_chain_fld_fmulp(void) {
    float result;
    double a = 3.0, b = 4.0;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n" /* 2.0 */
        "fldl %1\n fmulp %%st, %%st(1)\n"  /* *3 = 6 */
        "fldl %2\n fmulp %%st, %%st(1)\n"  /* *4 = 24 */
        "fstps %0\n"
        : "=m"(result) : "m"(a), "m"(b));
    return result;
}

/*
 * Alternating FLD+FADDP and FLD+FSUBP.
 * ST(0)=10.0.  FLD [7.0]/FADDP (=17), FLD [5.0]/FSUBP (=12),
 *               FLD [3.0]/FADDP (=15).
 * Result: 15.0.
 */
static float test_optd_chain_mixed_arithp(void) {
    float result;
    double a = 7.0, b = 5.0, c = 3.0;
    __asm__ volatile(
        /* build ST(0) = 10.0 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fldl %1\n faddp %%st, %%st(1)\n"  /* +7 = 17 */
        "fldl %2\n fsubrp %%st, %%st(1)\n" /* 17-5 = 12 */
        "fldl %3\n faddp %%st, %%st(1)\n"  /* +3 = 15 */
        "fstps %0\n"
        : "=m"(result) : "m"(a), "m"(b), "m"(c));
    return result;
}

/*
 * FLD+FSTP pairs (copy through stack) -- OPT-D push-pop.
 * ST(0)=original=42.0.  FLD ST(0)/FSTP m64 copies to mem without
 * disturbing ST(0).  Do it twice.
 */
static void test_optd_chain_fld_fstp(double *dst1, double *dst2) {
    double original = 42.0;
    __asm__ volatile(
        "fldl %2\n"                        /* ST(0) = 42.0 */
        "fld %%st(0)\n fstpl %0\n"         /* copy #1 */
        "fld %%st(0)\n fstpl %1\n"         /* copy #2 */
        "fstp %%st(0)\n"                   /* clean up */
        : "=m"(*dst1), "=m"(*dst2) : "m"(original));
}

/*
 * FLD+FADDP with a 2-deep stack to check OPT-D doesn't corrupt ST(1).
 * ST(0)=10.0, ST(1)=100.0.  FLD [5.0]/FADDP -> ST(0)=15.0, ST(1)=100.0.
 * Verify both registers.
 */
static void test_optd_preserves_st1(float *r0, float *r1) {
    double five = 5.0;
    __asm__ volatile(
        /* build stack: ST(0)=10, ST(1)=100 */
        /* 100 first (will be ST(1)) */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fmulp %%st, %%st(1)\n"   /* 10 * 10 = 100 */
        /* push 10 on top */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        /* ST(0)=10, ST(1)=100 */
        "fldl %2\n faddp %%st, %%st(1)\n"  /* ST(0) = 10+5 = 15 */
        "fstps %0\n"  /* ST(0) -> r0, pop -> ST(0)=100 */
        "fstps %1\n"  /* ST(0) -> r1, pop */
        : "=m"(*r0), "=m"(*r1) : "m"(five));
}

/* ========================================================================= */
/* Section C: Net-zero fusions surrounded by OPT-D context                   */
/* ========================================================================= */

/*
 * Pattern: unfused FLD -> fused (FLD+FADDP) -> unfused FSTP
 *
 * The unfused FLD pushes with OPT-D deferred tag, the net-zero fusion
 * runs in the middle, and the unfused FSTP pops -- the push/pop should
 * fully cancel.
 *
 * Start empty.  FLD [A] (unfused push).  FLD [B] / FADDP (net-zero
 * fusion, ST(0) = A+B).  FSTP m64 (unfused pop, store A+B).
 * Stack: empty.
 */
static double test_netzero_surrounded_fld_arithp(void) {
    double a = 7.0, b = 3.0;
    double result;
    __asm__ volatile(
        "fldl %1\n"                         /* unfused FLD: push A=7 */
        "fldl %2\n"                         /* fused FLD+FADDP: push B=3 */
        "faddp %%st, %%st(1)\n"             /* ST(0) = 7+3 = 10, pop */
        "fstpl %0\n"                        /* unfused FSTP: store 10, pop */
        : "=m"(result) : "m"(a), "m"(b));
    return result;
}

/*
 * Pattern: unfused FLD -> fused (FLD+FSTP m64) -> unfused FSTP
 *
 * FLD [A] / { FLD [B] / FSTP m64 } / FSTP m64.
 * The middle FLD+FSTP is a net-zero copy fusion.
 * After: first dst = B, second dst = A.
 */
static void test_netzero_surrounded_fld_fstp(double *dst1, double *dst2) {
    double a = 11.0, b = 22.0;
    __asm__ volatile(
        "fldl %2\n"                         /* unfused FLD: push A=11 */
        "fldl %3\n"                         /* fused FLD+FSTP: push B=22 */
        "fstpl %0\n"                        /* store 22 to dst1, pop */
        "fstpl %1\n"                        /* unfused FSTP: store 11 to dst2, pop */
        : "=m"(*dst1), "=m"(*dst2) : "m"(a), "m"(b));
}

/*
 * Pattern: unfused FLD -> fused (FLD+FMULP) -> unfused FADDP
 *
 * ST(0)=base.  FLD [A] (unfused push).  FLD [B] / FMULP (net-zero:
 * ST(0) = A*B).  FADDP (unfused pop: ST(0) = base + A*B).
 *
 * base=100, A=3, B=5 -> 100 + 15 = 115.
 */
static float test_netzero_surrounded_fld_arithp_faddp(void) {
    float result;
    double a = 3.0, b = 5.0;
    __asm__ volatile(
        /* build base = 100 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fmulp %%st, %%st(1)\n"  /* 10*10 = 100 */
        /* now: ST(0)=100 */
        "fldl %1\n"                          /* unfused FLD: push 3 */
        "fldl %2\n"                          /* fused FLD+FMULP */
        "fmulp %%st, %%st(1)\n"             /* ST(0) = 3*5 = 15 */
        "faddp %%st, %%st(1)\n"             /* unfused FADDP: ST(0) = 100+15 = 115 */
        "fstps %0\n"
        : "=m"(result) : "m"(a), "m"(b));
    return result;
}

/*
 * Two consecutive net-zero fusions in a cache run, then a final store.
 *
 * ST(0)=1.0.  { FLD [2.0]/FADDP -> 3.0 }.  { FLD [4.0]/FMULP -> 12.0 }.
 * FSTP m32 -> 12.0.
 */
static float test_netzero_consecutive(void) {
    float result;
    double a = 2.0, b = 4.0;
    __asm__ volatile(
        "fld1\n"                             /* 1.0 */
        "fldl %1\n faddp %%st, %%st(1)\n"   /* 1+2 = 3 */
        "fldl %2\n fmulp %%st, %%st(1)\n"   /* 3*4 = 12 */
        "fstps %0\n"
        : "=m"(result) : "m"(a), "m"(b));
    return result;
}

/*
 * Net-zero fusion (FLD+FSUBP) sandwiched between two stack levels.
 * ST(0)=20, ST(1)=100.
 * { FLD [8.0] / FSUBRP -> 20-8=12 }.
 * FADDP -> ST(0) = 100+12 = 112.
 */
static float test_netzero_2deep_stack(void) {
    float result;
    double eight = 8.0;
    __asm__ volatile(
        /* build ST(1)=100, ST(0)=20 */
        /* 100 first: 10*10 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fmulp %%st, %%st(1)\n"  /* 10*10 = 100 */
        /* 20 on top: 10*2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"
        "fld1\n fld1\n faddp\n"  /* 2.0 */
        "fmulp %%st, %%st(1)\n"  /* 10*2 = 20 */
        /* ST(0)=20, ST(1)=100 */
        "fldl %1\n"                          /* FLD 8 -> fused with FSUBRP */
        "fsubrp %%st, %%st(1)\n"             /* ST(0) = 20-8 = 12 */
        "faddp %%st, %%st(1)\n"              /* ST(0) = 100+12 = 112 */
        "fstps %0\n"
        : "=m"(result) : "m"(eight));
    return result;
}

/* ========================================================================= */
/* Entry point                                                               */
/* ========================================================================= */

int main(void) {

    /* --- Section A: FLD + FCOMPS/FCOMPL mem + FNSTSW --- */

    printf("=== A1: FLD m64 + FCOMPS m32 + FNSTSW ===\n");
    check_u16("FLD m64 + FCOMPS m32  GT  5>3=0x0000",
              test_fld_fcomps_m32_gt(), 0x0000);
    check_u16("FLD m64 + FCOMPS m32  LT  1<3=0x0100",
              test_fld_fcomps_m32_lt(), 0x0100);
    check_u16("FLD m64 + FCOMPS m32  EQ  3=3=0x4000",
              test_fld_fcomps_m32_eq(), 0x4000);
    check_u16("FLD m64 + FCOMPS m32  UN  NaN=0x4500",
              test_fld_fcomps_m32_un(), 0x4500);

    printf("\n=== A2: FLD m64 + FCOMPL m64 + FNSTSW ===\n");
    check_u16("FLD m64 + FCOMPL m64  GT  7>2=0x0000",
              test_fld_fcompl_m64_gt(), 0x0000);
    check_u16("FLD m64 + FCOMPL m64  LT  2<7=0x0100",
              test_fld_fcompl_m64_lt(), 0x0100);
    check_u16("FLD m64 + FCOMPL m64  EQ  4.5=4.5=0x4000",
              test_fld_fcompl_m64_eq(), 0x4000);
    check_u16("FLD m64 + FCOMPL m64  UN  NaN=0x4500",
              test_fld_fcompl_m64_un(), 0x4500);

    printf("\n=== A3: FLD m32 + FCOMPS m32 + FNSTSW ===\n");
    check_u16("FLD m32 + FCOMPS m32  GT  9>2=0x0000",
              test_flds_fcomps_m32_gt(), 0x0000);
    check_u16("FLD m32 + FCOMPS m32  LT  1<5=0x0100",
              test_flds_fcomps_m32_lt(), 0x0100);

    printf("\n=== A4: FLD ST(i) + FCOMPS m32 + FNSTSW ===\n");
    check_u16("FLD ST(0) + FCOMPS m32  GT  5>3=0x0000",
              test_fld_reg_fcomps_m32_gt(), 0x0000);
    check_u16("FLD ST(0) + FCOMPS m32  LT  2<8=0x0100",
              test_fld_reg_fcomps_m32_lt(), 0x0100);

    printf("\n=== A5: FLD1/FLDZ + FCOMPS m32 + FNSTSW ===\n");
    check_u16("FLD1 + FCOMPS m32  GT  1>0.5=0x0000",
              test_fld1_fcomps_m32_gt(), 0x0000);
    check_u16("FLDZ + FCOMPS m32  LT  0<1=0x0100",
              test_fldz_fcomps_m32_lt(), 0x0100);
    check_u16("FLDZ + FCOMPS m32  EQ  0=0=0x4000",
              test_fldz_fcomps_m32_eq(), 0x4000);

    printf("\n=== A6: FILD + FCOMPS m32 + FNSTSW ===\n");
    check_u16("FILD m32 + FCOMPS m32  GT  10>3=0x0000",
              test_fild_fcomps_m32_gt(), 0x0000);

    printf("\n=== A7: FLD m32 + FCOMPL m64 + FNSTSW ===\n");
    check_u16("FLD m32 + FCOMPL m64  EQ  2.5=2.5=0x4000",
              test_flds_fcompl_m64_eq(), 0x4000);

    printf("\n=== A8: Stack correctness after FLD+FCOMP_mem+FNSTSW ===\n");
    check_f64("FLD+FCOMPS+FNSTSW net-zero: ST(0)=99.0 intact",
              test_fld_fcomps_stack_intact(), 99.0);
    check_f64("FLD+FCOMPL+FNSTSW net-zero: ST(0)=77.0 intact",
              test_fld_fcompl_stack_intact(), 77.0);

    /* --- Section B: OPT-D tag cancellation --- */

    printf("\n=== B1: Chained FLD+FADDP (OPT-D cancellation) ===\n");
    check_f32("3x FLD+FADDP chain: 10+2+3+5=20",
              test_optd_chain_fld_faddp(), 20.0f);

    printf("\n=== B2: Chained FLD+FMULP ===\n");
    check_f32("2x FLD+FMULP chain: 2*3*4=24",
              test_optd_chain_fld_fmulp(), 24.0f);

    printf("\n=== B3: Mixed FADDP/FSUBP chain ===\n");
    check_f32("FLD+FADDP, FLD+FSUBP, FLD+FADDP: 10+7-5+3=15",
              test_optd_chain_mixed_arithp(), 15.0f);

    printf("\n=== B4: Chained FLD+FSTP (copy pairs) ===\n");
    {
        double d1 = 0.0, d2 = 0.0;
        test_optd_chain_fld_fstp(&d1, &d2);
        check_f64("FLD+FSTP copy #1 = 42.0", d1, 42.0);
        check_f64("FLD+FSTP copy #2 = 42.0", d2, 42.0);
    }

    printf("\n=== B5: OPT-D preserves ST(1) ===\n");
    {
        float r0 = 0.0f, r1 = 0.0f;
        test_optd_preserves_st1(&r0, &r1);
        check_f32("FLD+FADDP result ST(0) = 15.0", r0, 15.0f);
        check_f32("Underlying ST(1) = 100.0 undisturbed", r1, 100.0f);
    }

    /* --- Section C: Net-zero fusions in OPT-D context --- */

    printf("\n=== C1: unfused FLD -> fused FLD+FADDP -> unfused FSTP ===\n");
    check_f64("FLD A / {FLD B + FADDP} / FSTP = 7+3=10",
              test_netzero_surrounded_fld_arithp(), 10.0);

    printf("\n=== C2: unfused FLD -> fused FLD+FSTP -> unfused FSTP ===\n");
    {
        double d1 = 0.0, d2 = 0.0;
        test_netzero_surrounded_fld_fstp(&d1, &d2);
        check_f64("dst1 (from fused FLD+FSTP) = 22.0", d1, 22.0);
        check_f64("dst2 (from unfused FSTP)   = 11.0", d2, 11.0);
    }

    printf("\n=== C3: unfused FLD -> fused FLD+FMULP -> unfused FADDP ===\n");
    check_f32("base + A*B = 100 + 3*5 = 115",
              test_netzero_surrounded_fld_arithp_faddp(), 115.0f);

    printf("\n=== C4: Two consecutive net-zero fusions ===\n");
    check_f32("1 + 2 = 3, * 4 = 12",
              test_netzero_consecutive(), 12.0f);

    printf("\n=== C5: Net-zero fusion with 2-deep stack ===\n");
    check_f32("(20-8) + 100 = 112",
              test_netzero_2deep_stack(), 112.0f);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
