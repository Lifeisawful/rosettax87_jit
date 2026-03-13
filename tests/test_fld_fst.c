/*
 * test_fld_fst.c — Exhaustive tests for all FLD/FILD/FLDconst load variants
 * and FST/FSTP store variants.
 *
 * Build: gcc -O0 -mfpmath=387 -o test_fld_fst test_fld_fst.c -lm
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-52s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_approx(const char *name, double got, double expected, double rel_eps) {
    double diff = got - expected;
    if (diff < 0) diff = -diff;
    double scale = expected < 0 ? -expected : expected;
    if (scale == 0) scale = 1.0;
    if (diff / scale > rel_eps) {
        printf("FAIL  %-52s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* === FLD ST(i) variants === */
static double fld_st0(void) {
    double r;
    __asm__ volatile("fld1\n fld %%st(0)\n fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}
static double fld_st1(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n"  /* ST(0)=2 */
        "fld1\n"                  /* ST(0)=1, ST(1)=2 */
        "fld %%st(1)\n"           /* ST(0)=2, ST(1)=1, ST(2)=2 */
        "fstpl %0\n fstp %%st(0)\n fstp %%st(0)\n" : "=m"(r));
    return r;
}
static double fld_st2(void) {
    double r;
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3 */
        "fld1\n fld1\n faddp\n"                   /* 2 */
        "fld1\n"                                   /* 1 */
        "fld %%st(2)\n"                            /* should be 3 */
        "fstpl %0\n fstp %%st(0)\n fstp %%st(0)\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* === FLD m32fp / m64fp === */
static double fld_m32(void) {
    double r; float mem = 3.25f;
    __asm__ volatile("flds %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}
static double fld_m64(void) {
    double r, mem = 1.23456789012345;
    __asm__ volatile("fldl %1\n fstpl %0\n" : "=m"(r) : "m"(mem));
    return r;
}

/* === All FLD constants === */
static double do_fldz(void)   { double r; __asm__ volatile("fldz\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fld1(void)   { double r; __asm__ volatile("fld1\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fldl2e(void) { double r; __asm__ volatile("fldl2e\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fldl2t(void) { double r; __asm__ volatile("fldl2t\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fldlg2(void) { double r; __asm__ volatile("fldlg2\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fldln2(void) { double r; __asm__ volatile("fldln2\n fstpl %0\n" : "=m"(r)); return r; }
static double do_fldpi(void)  { double r; __asm__ volatile("fldpi\n fstpl %0\n" : "=m"(r)); return r; }

/* === FILD m16/m32/m64 === */
static double fild_m16(int16_t v) {
    double r;
    __asm__ volatile("filds %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}
static double fild_m32(int32_t v) {
    double r;
    __asm__ volatile("fildl %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}
static double fild_m64(int64_t v) {
    double r;
    __asm__ volatile("fildll %1\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* === FST m32 / m64 (non-popping) === */
static float fst_m32(float val) {
    float r;
    __asm__ volatile(
        "flds %1\n"
        "fsts %0\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(val));
    return r;
}
static double fst_m64(double val) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fstl %0\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(val));
    return r;
}

/* === FSTP m32 / m64 === */
static float fstp_m32(float val) {
    float r;
    __asm__ volatile("flds %1\n fstps %0\n" : "=m"(r) : "m"(val));
    return r;
}
static double fstp_m64(double val) {
    double r;
    __asm__ volatile("fldl %1\n fstpl %0\n" : "=m"(r) : "m"(val));
    return r;
}

/* === FST_STACK / FSTP_STACK === */
static double fst_stack_st1(void) {
    double r;
    __asm__ volatile(
        "fldz\n"
        "fld1\n fld1\n faddp\n"  /* ST(0)=2, ST(1)=0 */
        "fst %%st(1)\n"           /* ST(1)=2, no pop */
        "faddp\n"                 /* 2+2=4 */
        "fstpl %0\n" : "=m"(r));
    return r;
}
static double fstp_stack_st0(void) {
    double r;
    __asm__ volatile(
        "fld1\n"
        "fld1\n fld1\n faddp\n"
        "fstp %%st(0)\n"          /* discard 2, ST(0)=1 */
        "fstpl %0\n" : "=m"(r));
    return r;
}
static double fstp_stack_st1(void) {
    double r;
    __asm__ volatile(
        "fld1\n"
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* ST(0)=3, ST(1)=1 */
        "fstp %%st(1)\n"                          /* copy 3→ST(1), pop → ST(0)=3 */
        "fstpl %0\n" : "=m"(r));
    return r;
}
static double fstp_stack_st2(void) {
    double r;
    __asm__ volatile(
        "fld1\n"                                   /* 1 */
        "fld1\n fld1\n faddp\n"                    /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"    /* 3 */
        /* ST(0)=3, ST(1)=2, ST(2)=1 */
        "fstp %%st(2)\n"                           /* copy 3→ST(2), pop → ST(0)=2, ST(1)=3 */
        "fstpl %0\n fstp %%st(0)\n" : "=m"(r));
    return r;
}

/* === Stack depth test — 8 values === */
static void stack_depth_8(double *results) {
    __asm__ volatile(
        "fld1\n"                                         /* 1 */
        "fld1\n fld1\n faddp\n"                          /* 2 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n"           /* 3 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 4 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 5 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 6 */
        "fld1\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n fld1\n faddp\n"  /* 7 */
        "fld1\n fadd %%st(1)\n"  /* 8: push 1, ST(0)+=ST(1)=7 → 8; stays at depth 8 */
        "fstpl %0\n fstpl %1\n fstpl %2\n fstpl %3\n"
        "fstpl %4\n fstpl %5\n fstpl %6\n fstpl %7\n"
        : "=m"(results[0]), "=m"(results[1]), "=m"(results[2]), "=m"(results[3]),
          "=m"(results[4]), "=m"(results[5]), "=m"(results[6]), "=m"(results[7])
    );
}

int main(void) {
    printf("=== FLD ST(i) ===\n");
    check("FLD ST(0)  dup 1.0", fld_st0(), 1.0);
    check("FLD ST(1)  load 2.0", fld_st1(), 2.0);
    check("FLD ST(2)  load 3.0", fld_st2(), 3.0);

    printf("\n=== FLD m32fp / m64fp ===\n");
    check("FLD m32fp  3.25", fld_m32(), 3.25);
    check("FLD m64fp  1.23456789012345", fld_m64(), 1.23456789012345);

    printf("\n=== FLD constants ===\n");
    check("FLDZ   0.0", do_fldz(), 0.0);
    check("FLD1   1.0", do_fld1(), 1.0);
    check_approx("FLDL2E log2(e)", do_fldl2e(), 1.4426950408889634, 1e-5);
    check_approx("FLDL2T log2(10)", do_fldl2t(), 3.3219280948873622, 1e-5);
    check_approx("FLDLG2 log10(2)", do_fldlg2(), 0.3010299956639812, 1e-5);
    check_approx("FLDLN2 ln(2)", do_fldln2(), 0.6931471805599453, 1e-5);
    check_approx("FLDPI  pi", do_fldpi(), 3.141592653589793, 1e-5);

    printf("\n=== FILD m16/m32/m64 ===\n");
    check("FILD m16  0", fild_m16(0), 0.0);
    check("FILD m16  42", fild_m16(42), 42.0);
    check("FILD m16  -1", fild_m16(-1), -1.0);
    check("FILD m16  32767", fild_m16(32767), 32767.0);
    check("FILD m16  -32768", fild_m16(-32768), -32768.0);
    check("FILD m32  0", fild_m32(0), 0.0);
    check("FILD m32  1000000", fild_m32(1000000), 1000000.0);
    check("FILD m32  -1", fild_m32(-1), -1.0);
    check("FILD m32  INT32_MAX", fild_m32(2147483647), 2147483647.0);
    check("FILD m32  INT32_MIN", fild_m32(-2147483647-1), -2147483648.0);
    check("FILD m64  0", fild_m64(0), 0.0);
    check("FILD m64  1e12", fild_m64(1000000000000LL), 1e12);
    check("FILD m64  -1", fild_m64(-1), -1.0);

    printf("\n=== FST m32 / m64 (non-popping) ===\n");
    check("FST m32  3.5", (double)fst_m32(3.5f), 3.5);
    check("FST m64  2.718", fst_m64(2.718), 2.718);

    printf("\n=== FSTP m32 / m64 ===\n");
    check("FSTP m32  1.25", (double)fstp_m32(1.25f), 1.25);
    check("FSTP m64  9.87", fstp_m64(9.87), 9.87);

    printf("\n=== FST_STACK / FSTP_STACK ===\n");
    check("FST ST(1)  copy no pop = 4.0", fst_stack_st1(), 4.0);
    check("FSTP ST(0) discard = 1.0", fstp_stack_st0(), 1.0);
    check("FSTP ST(1) copy+pop = 3.0", fstp_stack_st1(), 3.0);
    check("FSTP ST(2) copy+pop = 2.0", fstp_stack_st2(), 2.0);

    printf("\n=== Full stack depth (8 values) ===\n");
    {
        double r[8];
        stack_depth_8(r);
        for (int i = 0; i < 8; i++) {
            char name[64];
            snprintf(name, sizeof(name), "stack[%d] = %d.0", i, 8 - i);
            check(name, r[i], (double)(8 - i));
        }
    }

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
