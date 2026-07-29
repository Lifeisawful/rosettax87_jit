/*
 * test_ir_algebra.c — Tests for IR const dedup and FNeg folding.
 *
 * Covers: fldz/fld1/fldpi chains (const dedup reuses one node per run),
 * fchs double-negation, fchs folded into fadd/fsub operands, and
 * fchs-after-fmul (FNMUL rewrite), including sign-of-zero edge cases.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_ir_algebra test_ir_algebra.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;
static uint64_t as_u64(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

static void check(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ==== fldz chain: three pushes in one run (const dedup) ==== */
static void fldz_chain(double *o0, double *o1, double *o2) {
    __asm__ volatile(
        "fldz\n\t fstpl %0\n\t"
        "fldz\n\t fstpl %1\n\t"
        "fldz\n\t fstpl %2\n"
        : "=m"(*o0), "=m"(*o1), "=m"(*o2));
}

/* ==== fld1 chain mixed with fldz ==== */
static void fld1_fldz_mix(double *o0, double *o1, double *o2, double *o3) {
    __asm__ volatile(
        "fld1\n\t fstpl %0\n\t"
        "fldz\n\t fstpl %1\n\t"
        "fld1\n\t fstpl %2\n\t"
        "fldz\n\t fstpl %3\n"
        : "=m"(*o0), "=m"(*o1), "=m"(*o2), "=m"(*o3));
}

/* ==== fldpi twice: ConstF64 dedup, both stores must be bit-identical ==== */
static void fldpi_twice(double *o0, double *o1) {
    __asm__ volatile(
        "fldpi\n\t fstpl %0\n\t"
        "fldpi\n\t fstpl %1\n"
        : "=m"(*o0), "=m"(*o1));
}

/* ==== fldz used as an operand after dedup (three consumers) ==== */
static double fldz_arith(void) {
    double a = 5.5, out;
    __asm__ volatile(
        "fldz\n\t"
        "fldl %1\n\t"
        "faddp\n\t"           /* 0 + 5.5 */
        "fldz\n\t"
        "faddp\n\t"           /* 5.5 + 0 */
        "fstpl %0\n"
        : "=m"(out) : "m"(a));
    return out;               /* 5.5 */
}

/* ==== fchs; fchs — double negation must round-trip bit-exactly ==== */
static uint64_t fchs_double_neg(uint64_t in_bits) {
    double a, out;
    memcpy(&a, &in_bits, 8);
    __asm__ volatile(
        "fldl %1\n\t"
        "fchs\n\t"
        "fchs\n\t"
        "fstpl %0\n"
        : "=m"(out) : "m"(a));
    return as_u64(out);
}

/* ==== fld b; fchs; fadd a  →  a - b (FAdd(FNeg(b), a) folding) ==== */
static double fchs_then_fadd(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %2\n\t"          /* b */
        "fchs\n\t"             /* -b */
        "faddl %1\n\t"         /* -b + a */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b));
    return out;
}

/* ==== fld a; fld b; fchs; faddp  →  a - b ==== */
static double faddp_neg_rhs(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"          /* a */
        "fldl %2\n\t"          /* b */
        "fchs\n\t"             /* -b */
        "faddp\n\t"            /* a + (-b) */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b));
    return out;
}

/* ==== fld a; fld b; fchs; fsubp — AT&T fsubp computes (-b) - a ==== */
static double fsubp_neg_rhs(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"
        "fldl %2\n\t"
        "fchs\n\t"
        "fsubp\n\t"            /* (-b) - a  (AT&T operand order) */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b));
    return out;
}

/* ==== fld a; fld b; fchs; fsubrp — AT&T fsubrp computes a - (-b) ==== */
static double fsubrp_neg_rhs(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"
        "fldl %2\n\t"
        "fchs\n\t"
        "fsubrp\n\t"           /* a - (-b) = a + b */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b));
    return out;
}

/* ==== fmul then fchs → -(a*b) (FNMUL rewrite), incl. ±0 sign ==== */
static double fmul_fchs(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"
        "fmull %2\n\t"
        "fchs\n\t"
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b));
    return out;
}

/* ==== fld a; fmul b; fchs; fadd c  →  c - a*b  (must reach ONE FMSUB) ====
 * The FNeg has two possible folds: into the FMul below it (FNMUL) or into
 * the FAdd above it (FSub, which pass_fma then turns into FMSUB). Inputs
 * have lower node IDs, so a single forward loop would reach the FNeg first
 * and take FNMUL, stranding the FAdd — pass_fneg_fold therefore runs the
 * consumer folds to completion before any FNMUL rewrite. */
static double fmul_fchs_fadd(double a, double b, double c) {
    double out;
    __asm__ volatile(
        "fldl %1\n\t"
        "fmull %2\n\t"         /* a*b */
        "fchs\n\t"             /* -(a*b) */
        "faddl %3\n\t"         /* c - a*b */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b), "m"(c));
    return out;
}

/* ==== same shape, popping form: fld c; fld a; fmul b; fchs; faddp ==== */
static double fmul_fchs_faddp(double a, double b, double c) {
    double out;
    __asm__ volatile(
        "fldl %3\n\t"          /* c */
        "fldl %1\n\t"          /* a */
        "fmull %2\n\t"         /* a*b */
        "fchs\n\t"             /* -(a*b) */
        "faddp\n\t"            /* c + (-(a*b)) */
        "fstpl %0\n"
        : "=m"(out) : "m"(a), "m"(b), "m"(c));
    return out;
}

/* ==== fmul result used twice, then fchs: FNMUL must NOT fire ==== */
static void fmul_shared_fchs(double a, double b, double *neg, double *pos) {
    __asm__ volatile(
        "fldl %2\n\t"
        "fmull %3\n\t"         /* p = a*b */
        "fld %%st(0)\n\t"      /* dup p */
        "fchs\n\t"             /* -p */
        "fstpl %0\n\t"
        "fstpl %1\n"
        : "=m"(*neg), "=m"(*pos)
        : "m"(a), "m"(b));
}

int main(void) {
    {
        double a, b, c;
        fldz_chain(&a, &b, &c);
        check("fldz chain [0]", a, 0.0);
        check("fldz chain [1]", b, 0.0);
        check("fldz chain [2]", c, 0.0);
    }
    {
        double a, b, c, d;
        fld1_fldz_mix(&a, &b, &c, &d);
        check("fld1/fldz mix [0]", a, 1.0);
        check("fld1/fldz mix [1]", b, 0.0);
        check("fld1/fldz mix [2]", c, 1.0);
        check("fld1/fldz mix [3]", d, 0.0);
    }
    {
        double p0, p1;
        fldpi_twice(&p0, &p1);
        check("fldpi twice: equal", p0, p1);
        /* fldpi rounded to f64 */
        double pi_f64;
        uint64_t pi_bits = 0x400921FB54442D18ULL;
        memcpy(&pi_f64, &pi_bits, 8);
        check("fldpi twice: value", p0, pi_f64);
    }
    check("fldz as dedup'd operand", fldz_arith(), 5.5);

    /* double negation bit-exactness incl. signed zero and NaN payload */
    {
        struct { const char *name; uint64_t bits; } cases[] = {
            {"fchs;fchs on 3.5",  as_u64(3.5)},
            {"fchs;fchs on -0.0", 0x8000000000000000ULL},
            {"fchs;fchs on +0.0", 0x0000000000000000ULL},
            {"fchs;fchs on QNaN", 0x7FF800000DEAD00FULL},
        };
        for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
            uint64_t got = fchs_double_neg(cases[i].bits);
            if (got != cases[i].bits) {
                printf("FAIL  %-55s  got=%016llx expected=%016llx\n", cases[i].name,
                       (unsigned long long)got, (unsigned long long)cases[i].bits);
                failures++;
            } else {
                printf("PASS  %s\n", cases[i].name);
            }
        }
    }

    check("fchs+fadd → a-b", fchs_then_fadd(7.0, 2.5), 4.5);
    check("fchs+fadd → a-b (equal → +0)", fchs_then_fadd(2.5, 2.5), 0.0);
    check("faddp neg rhs → a-b", faddp_neg_rhs(10.0, 4.0), 6.0);
    /* a + (-b) with a==b: +0 regardless of form */
    check("faddp neg rhs (equal → +0)", faddp_neg_rhs(4.0, 4.0), 0.0);
    check("fsubp neg rhs → -(a+b)", fsubp_neg_rhs(3.0, 4.0), -7.0);
    check("fsubrp neg rhs → a+b", fsubrp_neg_rhs(3.0, 4.0), 7.0);

    check("fmul+fchs → -(a*b)", fmul_fchs(3.0, 4.0), -12.0);
    check("fmul+fchs sign of zero (+0*x → -0)", fmul_fchs(0.0, 5.0), -0.0);
    check("fmul+fchs sign of zero (-0*x → +0)", fmul_fchs(-0.0, 5.0), 0.0);
    /* Exact products, so the fused (FMSUB) and unfused forms agree bitwise. */
    check("fmul+fchs+fadd → c - a*b", fmul_fchs_fadd(3.0, 4.0, 20.0), 8.0);
    check("fmul+fchs+fadd negative result", fmul_fchs_fadd(3.0, 4.0, 2.0), -10.0);
    check("fmul+fchs+faddp → c - a*b", fmul_fchs_faddp(3.0, 4.0, 20.0), 8.0);

    {
        double neg, pos;
        fmul_shared_fchs(3.0, 5.0, &neg, &pos);
        check("shared fmul + fchs: negated copy", neg, -15.0);
        check("shared fmul + fchs: original", pos, 15.0);
    }

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
