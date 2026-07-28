/*
 * test_fprem.c — Tests for FPREM (truncating partial remainder) and FPREM1
 * (IEEE-754 nearest partial remainder), both now served by in-blob fast
 * stubs on the eligible input class (normal operands, |y| >= 2^-970,
 * exponent gap < 52); everything else takes the classic C legs.
 * ROSETTA_X87_DISABLE_{FPREM,FPREM1}_FAST=1 reverts to all-classic.
 *
 * Remainder values are exact by construction (fmod/remainder never round),
 * so value checks are bit-exact against the guest libm.
 *
 * Condition codes after a complete reduction (C2=0):
 *   C0 <- Q2, C1 <- Q0, C3 <- Q1 of the quotient's low 3 bits.
 * FPREM quotient bits are magnitude-based for all sign combinations.
 * FPREM1 with sign(x) != sign(y) reports the *signed* quotient's
 * two's-complement low bits under this runtime (openlibm remquo's *quo
 * convention), while other implementations report magnitude bits — those
 * checks accept either encoding (they differ only for odd quotients).
 *
 * Build: clang -arch x86_64 -O0 -o test_fprem test_fprem.c -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CC_MASK 0x4700u /* C3 | C2 | C1 | C0 */
#define CC_C0 0x0100u
#define CC_C1 0x0200u
#define CC_C2 0x0400u
#define CC_C3 0x4000u

static void check_bits(const char *name, double got, double expected) {
    if (memcmp(&got, &expected, sizeof(double)) != 0) {
        printf("FAIL  %-56s  got=%.17g(%016llx)  expected=%.17g(%016llx)\n", name,
               got, (unsigned long long)*(uint64_t *)&got, expected,
               (unsigned long long)*(uint64_t *)&expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-56s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Accept either of two encodings (this runtime's vs magnitude-based). */
static void check_u16_either(const char *name, uint16_t got, uint16_t a, uint16_t b) {
    if (got != a && got != b) {
        printf("FAIL  %-56s  got=0x%04x  expected=0x%04x or 0x%04x\n", name, got, a, b);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_true(const char *name, int cond) {
    if (!cond) {
        printf("FAIL  %s\n", name);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* ── primitives ─────────────────────────────────────────────────────────── */

static double do_fprem(double x, double y, uint16_t *sw) {
    double r;
    uint16_t s;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fldl  %3\n\t"
        "fprem\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %1\n\t"
        "fstpl %0\n\t"
        "fstp  %%st(0)\n\t"
        : "=m"(r), "=m"(s)
        : "m"(y), "m"(x)
        : "ax", "st", "st(1)");
    *sw = s;
    return r;
}

static double do_fprem1(double x, double y, uint16_t *sw) {
    double r;
    uint16_t s;
    __asm__ volatile(
        "fldl  %2\n\t"
        "fldl  %3\n\t"
        "fprem1\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %1\n\t"
        "fstpl %0\n\t"
        "fstp  %%st(0)\n\t"
        : "=m"(r), "=m"(s)
        : "m"(y), "m"(x)
        : "ax", "st", "st(1)");
    *sw = s;
    return r;
}

/* fprem with a chosen rounding-control field in the x87 control word;
 * fprem's result must be rounding-mode independent. */
static double do_fprem_rc(double x, double y, uint16_t rc) {
    double r;
    uint16_t cw, cw2;
    __asm__ volatile(
        "fnstcw %1\n\t"
        "movw  %1, %%ax\n\t"
        "andw  $0xF3FF, %%ax\n\t"
        "orw   %4, %%ax\n\t"
        "movw  %%ax, %2\n\t"
        "fldcw %2\n\t"
        "fldl  %3\n\t"
        "fldl  %5\n\t"
        "fprem\n\t"
        "fstpl %0\n\t"
        "fstp  %%st(0)\n\t"
        "fldcw %1\n\t"
        : "=m"(r), "=m"(cw), "=m"(cw2)
        : "m"(y), "r"((uint16_t)(rc << 10)), "m"(x)
        : "ax", "st", "st(1)");
    return r;
}

/* Software reduction loop (the guest idiom): FPREM until C2 clears. */
static double fprem_loop(double x, double y, int *iters) {
    double r = x;
    uint16_t sw;
    int n = 0;
    do {
        r = do_fprem(r, y, &sw);
        n++;
    } while ((sw & CC_C2) && n < 64);
    *iters = n;
    return r;
}

/* FPREM with live values in deeper stack slots; verifies ST(1)/ST(2)
 * survive and stay usable for arithmetic afterwards. */
static double fprem_stack_coherence(double x, double y, double c, double *st1_out) {
    double r, s1;
    __asm__ volatile(
        "fldl  %2\n\t"      /* st0 = c                     */
        "fldl  %3\n\t"      /* st0 = y, st1 = c            */
        "fldl  %4\n\t"      /* st0 = x, st1 = y, st2 = c   */
        "fprem\n\t"         /* st0 = rem(x,y)              */
        "faddp %%st(0), %%st(2)\n\t" /* c += rem; st0 = y  */
        "fstpl %0\n\t"      /* store y                     */
        "fstpl %1\n\t"      /* store c + rem               */
        : "=m"(s1), "=m"(r)
        : "m"(c), "m"(y), "m"(x)
        : "st", "st(1)", "st(2)");
    *st1_out = s1;
    return r;
}

/* FPREM on an empty stack: stack-underflow leg (IE|SF, indefinite NaN). */
static uint16_t fprem_empty(double *out) {
    double r;
    uint16_t s;
    __asm__ volatile(
        "fninit\n\t"
        "fprem\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %0\n\t"
        "fstpl %1\n\t"
        "fninit\n\t"
        : "=m"(s), "=m"(r)
        :
        : "ax", "st");
    *out = r;
    return s;
}

/* Expected CC bits from a known (magnitude) quotient. */
static uint16_t cc_from_q(long long q) {
    uint16_t sw = 0;
    if (q & 4) sw |= CC_C0;
    if (q & 1) sw |= CC_C1;
    if (q & 2) sw |= CC_C3;
    return sw;
}

int main(void) {
    uint16_t sw;
    double r;

    /* ── FPREM: values (bit-exact vs guest fmod) ────────────────────────── */
    check_bits("fprem(7.5, 2.0)", do_fprem(7.5, 2.0, &sw), fmod(7.5, 2.0));
    check_u16("fprem(7.5, 2.0) cc", sw & CC_MASK, cc_from_q(3)); /* C1|C3 */

    check_bits("fprem(-7.5, 2.0)", do_fprem(-7.5, 2.0, &sw), fmod(-7.5, 2.0));
    check_u16("fprem(-7.5, 2.0) cc (|Q| bits)", sw & CC_MASK, cc_from_q(3));

    check_bits("fprem(7.5, -2.0)", do_fprem(7.5, -2.0, &sw), fmod(7.5, -2.0));
    check_u16("fprem(7.5, -2.0) cc (|Q| bits)", sw & CC_MASK, cc_from_q(3));

    check_bits("fprem(-7.5, -2.0)", do_fprem(-7.5, -2.0, &sw), fmod(-7.5, -2.0));
    check_u16("fprem(-7.5, -2.0) cc (|Q| bits)", sw & CC_MASK, cc_from_q(3));

    /* all 8 quotient-bit patterns, y = 1.5, x = (q + 0.25) * y  */
    for (int q = 0; q < 8; q++) {
        char name[64];
        double x = (q + 0.25) * 1.5;
        snprintf(name, sizeof(name), "fprem(%g, 1.5) value", x);
        check_bits(name, do_fprem(x, 1.5, &sw), fmod(x, 1.5));
        snprintf(name, sizeof(name), "fprem(%g, 1.5) cc q=%d", x, q);
        check_u16(name, sw & CC_MASK, cc_from_q(q));
    }

    /* x < y: quotient 0, remainder = x */
    check_bits("fprem(0.75, 2.0) = x", do_fprem(0.75, 2.0, &sw), 0.75);
    check_u16("fprem(0.75, 2.0) cc q=0", sw & CC_MASK, 0);

    /* exact multiple: remainder +0, quotient bits still reported */
    r = do_fprem(6.0, 3.0, &sw);
    check_bits("fprem(6.0, 3.0) = +0", r, 0.0);
    check_true("fprem(6.0, 3.0) sign(+0)", !signbit(r));
    check_u16("fprem(6.0, 3.0) cc q=2", sw & CC_MASK, cc_from_q(2));

    r = do_fprem(-6.0, 3.0, &sw);
    check_bits("fprem(-6.0, 3.0) = -0", r, -0.0);
    check_true("fprem(-6.0, 3.0) sign(-0)", signbit(r));

    /* |x| == |y| */
    check_bits("fprem(2.5, 2.5) = +0", do_fprem(2.5, 2.5, &sw), 0.0);
    check_u16("fprem(2.5, 2.5) cc q=1", sw & CC_MASK, cc_from_q(1));

    /* non-trivial fractions: pi mod e, large-ish D still inside fast gate */
    check_bits("fprem(pi, e/8)", do_fprem(M_PI, M_E / 8, &sw), fmod(M_PI, M_E / 8));
    check_bits("fprem(1e15, 3.7)", do_fprem(1e15, 3.7, &sw), fmod(1e15, 3.7));
    check_u16("fprem(1e15, 3.7) complete (C2=0)", sw & CC_C2, 0);
    check_bits("fprem(ldexp(1.1,50), 1.375)", do_fprem(ldexp(1.1, 50), 1.375, &sw),
               fmod(ldexp(1.1, 50), 1.375));

    /* zero dividend */
    r = do_fprem(0.0, 3.0, &sw);
    check_bits("fprem(+0, 3.0) = +0", r, 0.0);
    check_u16("fprem(+0, 3.0) cc clear", sw & CC_MASK, 0);
    check_bits("fprem(-0.0, 3.0) = -0", do_fprem(-0.0, 3.0, &sw), -0.0);

    /* subnormal dividend (classic leg): x < y so remainder = x */
    check_bits("fprem(subnormal, 1.0) = x", do_fprem(ldexp(1.0, -1050), 1.0, &sw),
               ldexp(1.0, -1050));

    /* tiny divisor below the fast gate (e1 < 53): classic leg, exact */
    check_bits("fprem(1.0, 2^-980)", do_fprem(1.0, ldexp(1.0, -980), &sw),
               fmod(1.0, ldexp(1.0, -980)));
    /* divisor exactly at the gate edge (e1 == 53, |y| = 2^-970): fast path */
    check_bits("fprem(1.0, 2^-970)", do_fprem(1.0, ldexp(1.0, -970), &sw),
               fmod(1.0, ldexp(1.0, -970)));

    /* Inf/NaN legs */
    r = do_fprem(INFINITY, 2.0, &sw);
    check_true("fprem(Inf, 2.0) = NaN", isnan(r));
    r = do_fprem(3.0, 0.0, &sw);
    check_true("fprem(3.0, 0.0) = NaN", isnan(r));
    r = do_fprem(NAN, 2.0, &sw);
    check_true("fprem(NaN, 2.0) = NaN", isnan(r));
    check_bits("fprem(3.0, Inf) = x", do_fprem(3.0, INFINITY, &sw), 3.0);
    check_bits("fprem(-3.0, Inf) = x", do_fprem(-3.0, INFINITY, &sw), -3.0);

    /* D in [52, 64): above the fast gate, still a complete reduction */
    check_bits("fprem(1.3*2^55, 2.5)", do_fprem(ldexp(1.3, 55), 2.5, &sw),
               fmod(ldexp(1.3, 55), 2.5));
    check_u16("fprem(1.3*2^55, 2.5) complete (C2=0)", sw & CC_C2, 0);

    /* brute sweeps: near-integer quotients stress the divide-round-up
     * (quotient off-by-one) correction; aggregated to one check each */
    {
        int bad = 0;
        for (int k = 1; k <= 500; k++) {
            double x = k * 0.1;
            double g = do_fprem(x, 0.3, &sw);
            double e = fmod(x, 0.3);
            if (memcmp(&g, &e, 8) != 0) bad++;
            g = do_fprem(-x, 0.7, &sw);
            e = fmod(-x, 0.7);
            if (memcmp(&g, &e, 8) != 0) bad++;
            g = do_fprem(ldexp(x, 40), 0.3, &sw);
            e = fmod(ldexp(x, 40), 0.3);
            if (memcmp(&g, &e, 8) != 0) bad++;
        }
        check_true("fprem sweep (1500 cases)", bad == 0);
    }

    /* D >= 64: incomplete reduction (C2 set), then software loop converges */
    do_fprem(ldexp(1.5, 80), 2.0, &sw);
    check_u16("fprem(2^80, 2.0) incomplete (C2)", sw & CC_C2, CC_C2);
    {
        int iters = 0;
        double x = ldexp(1.5, 80);
        check_bits("fprem loop(1.5*2^80, 2.0)", fprem_loop(x, 2.0, &iters), fmod(x, 2.0));
        check_true("fprem loop terminates", iters < 64);
        x = ldexp(1.0, 1000);
        check_bits("fprem loop(2^1000, 3.0)", fprem_loop(x, 3.0, &iters), fmod(x, 3.0));
        check_true("fprem loop terminates (2^1000)", iters < 64);
    }

    /* rounding-control independence (incl. exact-multiple -0 fixup corner) */
    check_bits("fprem RC=chop (6.0, 3.0)", do_fprem_rc(6.0, 3.0, 3), 0.0);
    check_bits("fprem RC=down (6.0, 3.0)", do_fprem_rc(6.0, 3.0, 1), 0.0);
    check_bits("fprem RC=up   (7.5, 2.0)", do_fprem_rc(7.5, 2.0, 2), fmod(7.5, 2.0));
    check_bits("fprem RC=down (7.5, 2.0)", do_fprem_rc(7.5, 2.0, 1), fmod(7.5, 2.0));

    /* stack coherence: ST(1)/ST(2) intact and usable after fprem */
    {
        double st1 = 0.0;
        double sum = fprem_stack_coherence(7.5, 2.0, 10.0, &st1);
        check_bits("fprem stack: st1 == y", st1, 2.0);
        check_bits("fprem stack: st2 + rem", sum, 10.0 + fmod(7.5, 2.0));
    }

    /* empty stack: stack-underflow leg */
    {
        double out;
        uint16_t s = fprem_empty(&out);
        check_true("fprem(empty) sets IE", (s & 0x01) != 0);
        check_true("fprem(empty) sets SF", (s & 0x40) != 0);
        check_true("fprem(empty) = NaN", isnan(out));
    }

    /* ── FPREM1: values (bit-exact vs guest remainder) ──────────────────── */
    check_bits("fprem1(7.5, 2.0)", do_fprem1(7.5, 2.0, &sw), remainder(7.5, 2.0));
    check_u16("fprem1(7.5, 2.0) cc q=4", sw & CC_MASK, cc_from_q(4));

    check_bits("fprem1(7.0, 2.0)", do_fprem1(7.0, 2.0, &sw), remainder(7.0, 2.0));
    /* q = 4 (7/2 = 3.5, tie -> even 4), rem = -1 */
    check_u16("fprem1(7.0, 2.0) cc q=4 (tie->even)", sw & CC_MASK, cc_from_q(4));

    check_bits("fprem1(5.0, 2.0)", do_fprem1(5.0, 2.0, &sw), remainder(5.0, 2.0));
    /* q = 2 (2.5 tie -> even 2), rem = +1 */
    check_u16("fprem1(5.0, 2.0) cc q=2 (tie->even)", sw & CC_MASK, cc_from_q(2));

    check_bits("fprem1(0.5, 1.0)", do_fprem1(0.5, 1.0, &sw), remainder(0.5, 1.0));
    check_u16("fprem1(0.5, 1.0) cc q=0 (tie->even)", sw & CC_MASK, cc_from_q(0));

    check_bits("fprem1(1.5, 1.0)", do_fprem1(1.5, 1.0, &sw), remainder(1.5, 1.0));
    check_u16("fprem1(1.5, 1.0) cc q=2 (tie->even)", sw & CC_MASK, cc_from_q(2));

    check_bits("fprem1(2.7, 1.0)", do_fprem1(2.7, 1.0, &sw), remainder(2.7, 1.0));
    check_u16("fprem1(2.7, 1.0) cc q=3", sw & CC_MASK, cc_from_q(3));

    /* x < y/2: untouched */
    check_bits("fprem1(0.4, 1.0) = x", do_fprem1(0.4, 1.0, &sw), 0.4);
    check_u16("fprem1(0.4, 1.0) cc q=0", sw & CC_MASK, 0);

    /* negative-quotient encodings: accept this runtime's two's-complement
     * remquo bits or magnitude bits (differ only for odd quotients) */
    check_bits("fprem1(-6.0, 2.0)", do_fprem1(-6.0, 2.0, &sw), remainder(-6.0, 2.0));
    check_u16_either("fprem1(-6.0, 2.0) cc (q=-3)", sw & CC_MASK,
                     CC_C0 | CC_C1 /* -3 two's compl: 101 */,
                     cc_from_q(3) /* |q|: 011 */);
    check_bits("fprem1(-7.5, 2.0)", do_fprem1(-7.5, 2.0, &sw), remainder(-7.5, 2.0));
    check_u16_either("fprem1(-7.5, 2.0) cc (q=-4)", sw & CC_MASK,
                     cc_from_q(4) /* -4 low bits == |4| */, cc_from_q(4));
    check_bits("fprem1(7.5, -2.0)", do_fprem1(7.5, -2.0, &sw), remainder(7.5, -2.0));
    check_bits("fprem1(-2.7, 1.0)", do_fprem1(-2.7, 1.0, &sw), remainder(-2.7, 1.0));
    check_u16_either("fprem1(-2.7, 1.0) cc (q=-3)", sw & CC_MASK,
                     CC_C0 | CC_C1, cc_from_q(3));
    check_bits("fprem1(-7.5, -2.0)", do_fprem1(-7.5, -2.0, &sw), remainder(-7.5, -2.0));
    check_u16("fprem1(-7.5, -2.0) cc q=4 (same signs)", sw & CC_MASK, cc_from_q(4));

    /* exact multiple: sign(x) * 0 */
    r = do_fprem1(6.0, 3.0, &sw);
    check_bits("fprem1(6.0, 3.0) = +0", r, 0.0);
    r = do_fprem1(-6.0, 3.0, &sw);
    check_bits("fprem1(-6.0, 3.0) = -0", r, -0.0);

    /* irrational-ish operands */
    check_bits("fprem1(pi, e/8)", do_fprem1(M_PI, M_E / 8, &sw), remainder(M_PI, M_E / 8));
    check_bits("fprem1(1e15, 3.7)", do_fprem1(1e15, 3.7, &sw), remainder(1e15, 3.7));
    check_u16("fprem1(1e15, 3.7) complete (C2=0)", sw & CC_C2, 0);

    /* Inf/NaN/zero legs */
    r = do_fprem1(INFINITY, 2.0, &sw);
    check_true("fprem1(Inf, 2.0) = NaN", isnan(r));
    r = do_fprem1(3.0, 0.0, &sw);
    check_true("fprem1(3.0, 0.0) = NaN", isnan(r));
    check_bits("fprem1(3.0, Inf) = x", do_fprem1(3.0, INFINITY, &sw), 3.0);
    check_bits("fprem1(+0, 3.0) = +0", do_fprem1(0.0, 3.0, &sw), 0.0);

    /* D >= 64 incomplete + convergence via fprem1's own loop */
    do_fprem1(ldexp(1.5, 80), 2.0, &sw);
    check_u16("fprem1(2^80, 2.0) incomplete (C2)", sw & CC_C2, CC_C2);

    /* remainder can land exactly on +-y/2 through the fixup */
    check_bits("fprem1(2.5, 1.0) = 0.5", do_fprem1(2.5, 1.0, &sw), 0.5);
    check_bits("fprem1(3.5, 1.0) = -0.5", do_fprem1(3.5, 1.0, &sw), -0.5);

    /* brute sweep: near-half-integer quotients stress the nearest fixup
     * (bump vs keep, ties) — aggregated to one check */
    {
        int bad = 0;
        for (int k = 1; k <= 500; k++) {
            double x = k * 0.05;
            double g = do_fprem1(x, 0.3, &sw);
            double e = remainder(x, 0.3);
            if (memcmp(&g, &e, 8) != 0) bad++;
            g = do_fprem1(-x, 0.7, &sw);
            e = remainder(-x, 0.7);
            if (memcmp(&g, &e, 8) != 0) bad++;
            g = do_fprem1(ldexp(x, 40), 0.3, &sw);
            e = remainder(ldexp(x, 40), 0.3);
            if (memcmp(&g, &e, 8) != 0) bad++;
        }
        check_true("fprem1 sweep (1500 cases)", bad == 0);
    }

    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
