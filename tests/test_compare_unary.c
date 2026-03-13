/*
 * test_compare_unary.c — Tests for comparisons, FSTSW, unary ops, FXCH, FISTP.
 *
 * Build: gcc -O0 -mfpmath=387 -o test_compare_unary test_compare_unary.c -lm
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check_d(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-52s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_i(const char *name, int64_t got, int64_t expected) {
    if (got != expected) {
        printf("FAIL  %-52s  got=%lld  expected=%lld\n", name, (long long)got, (long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}
static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-52s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ==== FCHS ==== */
static double do_fchs(double v) {
    double r;
    __asm__ volatile("fldl %1\n fchs\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FABS ==== */
static double do_fabs(double v) {
    double r;
    __asm__ volatile("fldl %1\n fabs\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FSQRT ==== */
static double do_fsqrt(double v) {
    double r;
    __asm__ volatile("fldl %1\n fsqrt\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FRNDINT ==== */
static double do_frndint(double v) {
    double r;
    __asm__ volatile("fldl %1\n frndint\n fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FXCH ==== */
static void do_fxch_st1(double *r0, double *r1) {
    __asm__ volatile(
        "fld1\n"
        "fld1\n fld1\n faddp\n" /* ST(0)=2, ST(1)=1 */
        "fxch %%st(1)\n"        /* ST(0)=1, ST(1)=2 */
        "fstpl %0\n fstpl %1\n"
        : "=m"(*r0), "=m"(*r1));
}
static void do_fxch_st2(double *r0, double *r1, double *r2) {
    __asm__ volatile(
        "fld1\n fld1\n faddp\n fld1\n faddp\n"  /* 3 */
        "fld1\n fld1\n faddp\n"                   /* 2 */
        "fld1\n"                                   /* 1 */
        /* ST(0)=1, ST(1)=2, ST(2)=3 */
        "fxch %%st(2)\n"                           /* ST(0)=3, ST(1)=2, ST(2)=1 */
        "fstpl %0\n fstpl %1\n fstpl %2\n"
        : "=m"(*r0), "=m"(*r1), "=m"(*r2));
}

/* ==== FCOM / FCOMP / FCOMPP + FSTSW AX ==== */

/* Extract C0(bit8), C2(bit10), C3(bit14) from AX after FSTSW */
static uint16_t fcom_flags(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"   /* ST(1) = b */
        "fldl %1\n"   /* ST(0) = a */
        "fcompp\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;  /* mask C3(14), C2(10), C0(8) */
}

/* FUCOMPP + FSTSW AX */
static uint16_t fucom_flags(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %1\n"
        "fucompp\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* FCOMP (single pop) */
static uint16_t fcomp_flags(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %1\n"
        "fcomp %%st(1)\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"  /* clean remaining */
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* FCOM (no pop) */
static uint16_t fcom_nopop_flags(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %1\n"
        "fcom %%st(1)\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* FCOM m64fp */
static uint16_t fcom_m64_flags(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "fcoml %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* FCOM m32fp */
static uint16_t fcom_m32_flags(float a_f, float b_f) {
    uint16_t sw;
    __asm__ volatile(
        "flds %1\n"
        "fcoms %2\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a_f), "m"(b_f) : "ax");
    return sw & 0x4500;
}

/* FSTSW m16 (memory store instead of AX) */
static uint16_t fstsw_m16(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %1\n"
        "fcompp\n"
        "fnstsw %0\n"
        : "=m"(sw) : "m"(a), "m"(b));
    return sw & 0x4500;
}

/* ==== FISTP ==== */
static int16_t do_fistp_m16(double v) {
    int16_t r;
    __asm__ volatile("fldl %1\n fistps %0\n" : "=m"(r) : "m"(v));
    return r;
}
static int32_t do_fistp_m32(double v) {
    int32_t r;
    __asm__ volatile("fldl %1\n fistpl %0\n" : "=m"(r) : "m"(v));
    return r;
}
static int64_t do_fistp_m64(double v) {
    int64_t r;
    __asm__ volatile("fldl %1\n fistpll %0\n" : "=m"(r) : "m"(v));
    return r;
}

/* ==== FCHS chain (multiple ops in sequence to test caching) ==== */
static double fchs_chain(double v) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fchs\n fchs\n fchs\n fchs\n fchs\n"  /* 5 negations = net negative */
        "fstpl %0\n" : "=m"(r) : "m"(v));
    return r;
}

int main(void) {
    printf("=== FCHS ===\n");
    check_d("FCHS  1.0 → -1.0", do_fchs(1.0), -1.0);
    check_d("FCHS  -5.5 → 5.5", do_fchs(-5.5), 5.5);
    check_d("FCHS  0.0 → -0.0", do_fchs(0.0), -0.0);
    check_d("FCHS chain 3.0 (5× neg) → -3.0", fchs_chain(3.0), -3.0);

    printf("\n=== FABS ===\n");
    check_d("FABS  -7.0 → 7.0", do_fabs(-7.0), 7.0);
    check_d("FABS  3.14 → 3.14", do_fabs(3.14), 3.14);
    check_d("FABS  0.0 → 0.0", do_fabs(0.0), 0.0);

    printf("\n=== FSQRT ===\n");
    check_d("FSQRT  4.0 → 2.0", do_fsqrt(4.0), 2.0);
    check_d("FSQRT  9.0 → 3.0", do_fsqrt(9.0), 3.0);
    check_d("FSQRT  1.0 → 1.0", do_fsqrt(1.0), 1.0);
    check_d("FSQRT  0.0 → 0.0", do_fsqrt(0.0), 0.0);
    check_d("FSQRT  2.0 → sqrt(2)", do_fsqrt(2.0), sqrt(2.0));

    printf("\n=== FRNDINT ===\n");
    check_d("FRNDINT  2.7 → 3.0 (round-to-nearest)", do_frndint(2.7), 3.0);
    check_d("FRNDINT  2.3 → 2.0", do_frndint(2.3), 2.0);
    check_d("FRNDINT  -1.5 → -2.0 (banker's rounding)", do_frndint(-1.5), -2.0);
    check_d("FRNDINT  0.5 → 0.0 (banker's rounding)", do_frndint(0.5), 0.0);
    check_d("FRNDINT  1.5 → 2.0 (banker's rounding)", do_frndint(1.5), 2.0);
    check_d("FRNDINT  -0.0 → -0.0", do_frndint(-0.0), -0.0);
    check_d("FRNDINT  100.0 → 100.0", do_frndint(100.0), 100.0);

    printf("\n=== FXCH ===\n");
    {
        double r0, r1;
        do_fxch_st1(&r0, &r1);
        check_d("FXCH ST(1)  r0=1 (was 2)", r0, 1.0);
        check_d("FXCH ST(1)  r1=2 (was 1)", r1, 2.0);
    }
    {
        double r0, r1, r2;
        do_fxch_st2(&r0, &r1, &r2);
        check_d("FXCH ST(2)  r0=3 (was 1)", r0, 3.0);
        check_d("FXCH ST(2)  r1=2 (unchanged)", r1, 2.0);
        check_d("FXCH ST(2)  r2=1 (was 3)", r2, 1.0);
    }

    printf("\n=== FCOM / FCOMP / FCOMPP + FSTSW ===\n");
    /* C3=0x4000, C2=0x0400, C0=0x0100 */
    /* GT: C3=0 C2=0 C0=0 = 0x0000 */
    /* LT: C3=0 C2=0 C0=1 = 0x0100 */
    /* EQ: C3=1 C2=0 C0=0 = 0x4000 */
    /* UN: C3=1 C2=1 C0=1 = 0x4500 */
    check_u16("FCOMPP  5>3  GT flags=0x0000", fcom_flags(5.0, 3.0), 0x0000);
    check_u16("FCOMPP  2<7  LT flags=0x0100", fcom_flags(2.0, 7.0), 0x0100);
    check_u16("FCOMPP  4==4 EQ flags=0x4000", fcom_flags(4.0, 4.0), 0x4000);
    check_u16("FCOMPP  NaN  UN flags=0x4500", fcom_flags(NAN, 1.0), 0x4500);

    check_u16("FUCOMPP 5>3  GT=0x0000", fucom_flags(5.0, 3.0), 0x0000);
    check_u16("FUCOMPP 2<7  LT=0x0100", fucom_flags(2.0, 7.0), 0x0100);
    check_u16("FUCOMPP 4==4 EQ=0x4000", fucom_flags(4.0, 4.0), 0x4000);
    check_u16("FUCOMPP NaN  UN=0x4500", fucom_flags(NAN, 1.0), 0x4500);

    check_u16("FCOMP ST(1) 5>3 GT=0x0000", fcomp_flags(5.0, 3.0), 0x0000);
    check_u16("FCOMP ST(1) 1<9 LT=0x0100", fcomp_flags(1.0, 9.0), 0x0100);
    check_u16("FCOMP ST(1) 6==6 EQ=0x4000", fcomp_flags(6.0, 6.0), 0x4000);

    check_u16("FCOM ST(1) 5>3 GT=0x0000", fcom_nopop_flags(5.0, 3.0), 0x0000);
    check_u16("FCOM ST(1) 1<9 LT=0x0100", fcom_nopop_flags(1.0, 9.0), 0x0100);

    check_u16("FCOM m64fp 5>3 GT=0x0000", fcom_m64_flags(5.0, 3.0), 0x0000);
    check_u16("FCOM m64fp 1<9 LT=0x0100", fcom_m64_flags(1.0, 9.0), 0x0100);
    check_u16("FCOM m64fp 4==4 EQ=0x4000", fcom_m64_flags(4.0, 4.0), 0x4000);

    check_u16("FCOM m32fp 5>3 GT=0x0000", fcom_m32_flags(5.0f, 3.0f), 0x0000);
    check_u16("FCOM m32fp 1<9 LT=0x0100", fcom_m32_flags(1.0f, 9.0f), 0x0100);

    check_u16("FSTSW m16  5>3 GT=0x0000", fstsw_m16(5.0, 3.0), 0x0000);
    check_u16("FSTSW m16  1<9 LT=0x0100", fstsw_m16(1.0, 9.0), 0x0100);

    printf("\n=== FISTP m16/m32/m64 ===\n");
    check_i("FISTP m16  3.0", do_fistp_m16(3.0), 3);
    check_i("FISTP m16  -7.0", do_fistp_m16(-7.0), -7);
    check_i("FISTP m16  0.0", do_fistp_m16(0.0), 0);
    check_i("FISTP m32  1000.0", do_fistp_m32(1000.0), 1000);
    check_i("FISTP m32  -999.0", do_fistp_m32(-999.0), -999);
    check_i("FISTP m32  2.5 (round-to-nearest=2)", do_fistp_m32(2.5), 2);
    check_i("FISTP m32  3.5 (round-to-nearest=4)", do_fistp_m32(3.5), 4);
    check_i("FISTP m64  1000000.0", do_fistp_m64(1000000.0), 1000000);
    check_i("FISTP m64  -1.0", do_fistp_m64(-1.0), -1);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
