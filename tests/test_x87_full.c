/*
 * test_x87_full.c — Comprehensive tests for all translate_* functions
 * in TranslatorX87.cpp, covering every operand variant.
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_x87_full test_x87_full.c -lm
 *
 * Sections:
 *   1. FSUB/FSUBR/FDIV/FDIVR memory variants (m32/m64)
 *   2. Integer arithmetic m16 variants (FIADD/FISUB/FIMUL/FIDIV/FIDIVR/FISUBR)
 *   3. FIST (non-popping integer store)
 *   4. FRNDINT with all rounding modes
 *   5. FCOMI / FCOMIP / FUCOMI / FUCOMIP
 *   6. FCMOV (all 8 condition variants)
 *   7. FUCOMP / FUCOMPP
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static uint64_t as_u64(double d) {
    uint64_t u;
    memcpy(&u, &d, 8);
    return u;
}

static void check_d(const char *name, double got, double expected) {
    if (as_u64(got) != as_u64(expected)) {
        printf("FAIL  %-55s  got=%.17g  expected=%.17g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_i(const char *name, int64_t got, int64_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=%lld  expected=%lld\n", name, (long long)got,
               (long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04x  expected=0x%04x\n", name, got,
               expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* =========================================================================
 * Section 1: FSUB/FSUBR/FDIV/FDIVR memory variants
 * ========================================================================= */

/* NOTE on GAS AT&T mnemonics for memory-form sub/div:
 *   For MEMORY forms, GAS and Intel agree (no reversal):
 *     GAS "fsubs"  = Intel FSUB  m32  = ST(0) = ST(0) - m32   (D8 /4)
 *     GAS "fsubrs" = Intel FSUBR m32  = ST(0) = m32 - ST(0)   (D8 /5)
 *   The GAS/Intel reversal only affects REGISTER forms (fsubp/fsubrp).
 */

/* FSUB m32fp: ST(0) = ST(0) - m32.  D8 /4. */
static double do_fsub_m32(double a, float b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fsubs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FSUB m64fp: ST(0) = ST(0) - m64.  DC /4. */
static double do_fsub_m64(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fsubl %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FSUBR m32fp: ST(0) = m32 - ST(0).  D8 /5. */
static double do_fsubr_m32(double a, float b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fsubrs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FDIV m32fp: ST(0) = ST(0) / m32.  D8 /6. */
static double do_fdiv_m32(double a, float b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fdivs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FDIV m64fp: ST(0) = ST(0) / m64.  DC /6. */
static double do_fdiv_m64(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fdivl %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FDIVR m32fp: ST(0) = m32 / ST(0).  D8 /7. */
static double do_fdivr_m32(double a, float b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fdivrs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FDIVR m64fp: ST(0) = m64 / ST(0).  DC /7. */
static double do_fdivr_m64(double a, double b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fdivrl %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* =========================================================================
 * Section 2: Integer arithmetic m16 variants
 * ========================================================================= */

/* FIADD m16int: ST(0) = ST(0) + (int16)mem */
static double do_fiadd_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fiadds %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FISUB m16int: ST(0) = ST(0) - (int16)mem.  Intel DA /4 (m32), DE /4 (m16). */
static double do_fisub_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fisubs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FIMUL m16int: ST(0) = ST(0) * (int16)mem */
static double do_fimul_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fimuls %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FIDIV m16int: ST(0) = ST(0) / (int16)mem */
static double do_fidiv_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fidivs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FIDIVR m16int: ST(0) = (int16)mem / ST(0) */
static double do_fidivr_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fidivrs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FISUBR m16int: ST(0) = (int16)mem - ST(0) */
static double do_fisubr_m16(double a, int16_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fisubrs %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* FISUBR m32int: ST(0) = (int32)mem - ST(0) */
static double do_fisubr_m32(double a, int32_t b) {
    double r;
    __asm__ volatile(
        "fldl %1\n"
        "fisubrl %2\n"
        "fstpl %0\n"
        : "=m"(r) : "m"(a), "m"(b));
    return r;
}

/* =========================================================================
 * Section 3: FIST (non-popping integer store)
 * ========================================================================= */

/* FIST m16int: store ST(0) as int16, no pop */
static int16_t do_fist_m16(double v) {
    int16_t r;
    __asm__ volatile(
        "fldl %1\n"
        "fists %0\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(v));
    return r;
}

/* FIST m32int: store ST(0) as int32, no pop */
static int32_t do_fist_m32(double v) {
    int32_t r;
    __asm__ volatile(
        "fldl %1\n"
        "fistl %0\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(v));
    return r;
}

/* =========================================================================
 * Section 4: FRNDINT with all rounding modes (via FLDCW)
 * ========================================================================= */

/* Set x87 rounding mode via control word.
 * RC bits are [11:10]: 00=nearest, 01=down, 10=up, 11=truncate.
 */
static double do_frndint_rc(double v, int rc) {
    double r;
    uint16_t cw_new = (uint16_t)(0x037F | (rc << 10));
    uint16_t cw_old;
    __asm__ volatile(
        "fnstcw %3\n"
        "fldcw %2\n"
        "fldl %1\n"
        "frndint\n"
        "fstpl %0\n"
        "fldcw %3\n"
        : "=m"(r) : "m"(v), "m"(cw_new), "m"(cw_old));
    return r;
}

/* =========================================================================
 * Section 5: FCOMI / FCOMIP / FUCOMI / FUCOMIP
 *
 * These set EFLAGS directly (ZF, PF, CF), not the x87 status word.
 * We read the result via conditional branches.
 * ========================================================================= */

/* FCOMI: compare ST(0) vs ST(i), result in EFLAGS.
 * Returns: 1=GT, -1=LT, 0=EQ, 2=unordered */
static int do_fcomi(double a, double b) {
    int result;
    __asm__ volatile(
        "fldl %1\n"       /* ST(1) = b */
        "fldl %2\n"       /* ST(0) = a */
        "fcomi %%st(1), %%st(0)\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        "jp 4f\n"         /* PF=1 → unordered */
        "ja 1f\n"         /* CF=0,ZF=0 → GT */
        "jb 2f\n"         /* CF=1 → LT */
        "movl $0, %0\n"   /* ZF=1 → EQ */
        "jmp 5f\n"
        "1: movl $1, %0\n"
        "jmp 5f\n"
        "2: movl $-1, %0\n"
        "jmp 5f\n"
        "4: movl $2, %0\n"
        "5:\n"
        : "=r"(result) : "m"(b), "m"(a));
    return result;
}

/* FCOMIP: compare ST(0) vs ST(1), set EFLAGS, pop ST(0).
 * Returns: 1=GT, -1=LT, 0=EQ */
static int do_fcomip(double a, double b) {
    int result;
    __asm__ volatile(
        "fldl %1\n"       /* ST(1) = b */
        "fldl %2\n"       /* ST(0) = a */
        "fcomip %%st(1), %%st(0)\n"
        "fstp %%st(0)\n"  /* pop remaining */
        "ja 1f\n"
        "jb 2f\n"
        "movl $0, %0\n"
        "jmp 3f\n"
        "1: movl $1, %0\n"
        "jmp 3f\n"
        "2: movl $-1, %0\n"
        "3:\n"
        : "=r"(result) : "m"(b), "m"(a));
    return result;
}

/* FUCOMI: unordered compare, sets EFLAGS.
 * Returns: 1=GT, -1=LT, 0=EQ, 2=unordered */
static int do_fucomi(double a, double b) {
    int result;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fucomi %%st(1), %%st(0)\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        "jp 4f\n"
        "ja 1f\n"
        "jb 2f\n"
        "movl $0, %0\n"
        "jmp 5f\n"
        "1: movl $1, %0\n"
        "jmp 5f\n"
        "2: movl $-1, %0\n"
        "jmp 5f\n"
        "4: movl $2, %0\n"
        "5:\n"
        : "=r"(result) : "m"(b), "m"(a));
    return result;
}

/* FUCOMIP: unordered compare + pop, sets EFLAGS.
 * Returns: 1=GT, -1=LT, 0=EQ, 2=unordered */
static int do_fucomip(double a, double b) {
    int result;
    __asm__ volatile(
        "fldl %1\n"
        "fldl %2\n"
        "fucomip %%st(1), %%st(0)\n"
        "fstp %%st(0)\n"
        "jp 4f\n"
        "ja 1f\n"
        "jb 2f\n"
        "movl $0, %0\n"
        "jmp 5f\n"
        "1: movl $1, %0\n"
        "jmp 5f\n"
        "2: movl $-1, %0\n"
        "jmp 5f\n"
        "4: movl $2, %0\n"
        "5:\n"
        : "=r"(result) : "m"(b), "m"(a));
    return result;
}

/* =========================================================================
 * Section 6: FCMOV (all 8 condition variants)
 *
 * Use FCOMI to set EFLAGS, then FCMOV to conditionally move.
 * ========================================================================= */

/* Helper: push a=ST(1), b=ST(0), do FCOMI to set flags from a vs b,
 * then FCMOV variant, return ST(0). */

/* FCMOVB: move if CF=1 (below) */
static double do_fcmovb(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"       /* ST(2) = src (value to conditionally move) */
        "fldl %1\n"       /* ST(1) = flag_b */
        "fldl %2\n"       /* ST(0) = flag_a */
        /* FCOMI: compare flag_a vs flag_b → sets EFLAGS */
        "fcomi %%st(1), %%st(0)\n"
        /* Now ST(0)=flag_a, ST(1)=flag_b, ST(2)=src */
        "fcmovb %%st(2), %%st(0)\n"  /* if CF=1 (a<b): ST(0) = src */
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVNB: move if CF=0 (not below) */
static double do_fcmovnb(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fcomi %%st(1), %%st(0)\n"
        "fcmovnb %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVE: move if ZF=1 (equal) */
static double do_fcmove(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fcomi %%st(1), %%st(0)\n"
        "fcmove %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVNE: move if ZF=0 (not equal) */
static double do_fcmovne(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fcomi %%st(1), %%st(0)\n"
        "fcmovne %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVBE: move if CF=1 or ZF=1 (below or equal) */
static double do_fcmovbe(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fcomi %%st(1), %%st(0)\n"
        "fcmovbe %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVNBE: move if CF=0 and ZF=0 (not below or equal, i.e. above) */
static double do_fcmovnbe(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fcomi %%st(1), %%st(0)\n"
        "fcmovnbe %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVU: move if PF=1 (unordered — NaN comparison) */
static double do_fcmovu(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fucomi %%st(1), %%st(0)\n"
        "fcmovu %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* FCMOVNU: move if PF=0 (not unordered) */
static double do_fcmovnu(double flag_a, double flag_b, double src) {
    double r;
    __asm__ volatile(
        "fldl %3\n"
        "fldl %1\n"
        "fldl %2\n"
        "fucomi %%st(1), %%st(0)\n"
        "fcmovnu %%st(2), %%st(0)\n"
        "fstpl %0\n"
        "fstp %%st(0)\n"
        "fstp %%st(0)\n"
        : "=m"(r) : "m"(flag_b), "m"(flag_a), "m"(src));
    return r;
}

/* =========================================================================
 * Section 7: FUCOMP / FUCOMPP
 * ========================================================================= */

/* FUCOMP ST(1): unordered compare + pop.  Returns CC bits. */
static uint16_t do_fucomp(double a, double b) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %2\n"
        "fldl %1\n"
        "fucomp %%st(1)\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a), "m"(b) : "ax");
    return sw & 0x4500;
}

/* FUCOMPP: unordered compare + double pop.  Returns CC bits. */
static uint16_t do_fucompp(double a, double b) {
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

/* FTST: compare ST(0) vs 0.0.  Returns CC bits. */
static uint16_t do_ftst(double a) {
    uint16_t sw;
    __asm__ volatile(
        "fldl %1\n"
        "ftst\n"
        "fnstsw %%ax\n"
        "movw %%ax, %0\n"
        "fstp %%st(0)\n"
        : "=m"(sw) : "m"(a) : "ax");
    return sw & 0x4500;
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void) {
    /* ---- Section 1: FSUB/FSUBR/FDIV/FDIVR memory variants ---- */
    printf("=== FSUB/FSUBR/FDIV/FDIVR memory ===\n");

    check_d("FSUB m32   10.0 - 3.0f = 7.0",
            do_fsub_m32(10.0, 3.0f), 7.0);
    check_d("FSUB m32   1.0 - 0.5f = 0.5",
            do_fsub_m32(1.0, 0.5f), 0.5);
    check_d("FSUB m64   10.0 - 3.0 = 7.0",
            do_fsub_m64(10.0, 3.0), 7.0);
    check_d("FSUB m64   -5.0 - 2.0 = -7.0",
            do_fsub_m64(-5.0, 2.0), -7.0);

    check_d("FSUBR m32  10.0: 3.0f - 10.0 = -7.0",
            do_fsubr_m32(10.0, 3.0f), -7.0);
    check_d("FSUBR m32  1.0: 5.0f - 1.0 = 4.0",
            do_fsubr_m32(1.0, 5.0f), 4.0);

    check_d("FDIV m32   10.0 / 2.0f = 5.0",
            do_fdiv_m32(10.0, 2.0f), 5.0);
    check_d("FDIV m32   7.0 / 2.0f = 3.5",
            do_fdiv_m32(7.0, 2.0f), 3.5);
    check_d("FDIV m64   10.0 / 4.0 = 2.5",
            do_fdiv_m64(10.0, 4.0), 2.5);
    check_d("FDIV m64   1.0 / 3.0",
            do_fdiv_m64(1.0, 3.0), 1.0 / 3.0);

    check_d("FDIVR m32  10.0: 2.0f / 10.0 = 0.2",
            do_fdivr_m32(10.0, 2.0f), 2.0 / 10.0);
    check_d("FDIVR m64  4.0: 1.0 / 4.0 = 0.25",
            do_fdivr_m64(4.0, 1.0), 1.0 / 4.0);
    check_d("FDIVR m64  2.0: 10.0 / 2.0 = 5.0",
            do_fdivr_m64(2.0, 10.0), 10.0 / 2.0);

    /* ---- Section 2: Integer arithmetic m16 ---- */
    printf("\n=== Integer arithmetic m16 variants ===\n");

    check_d("FIADD m16  10.5 + 3 = 13.5",
            do_fiadd_m16(10.5, 3), 13.5);
    check_d("FIADD m16  -1.0 + (-5) = -6.0",
            do_fiadd_m16(-1.0, -5), -6.0);

    check_d("FISUB m16  10.5 - 3 = 7.5",
            do_fisub_m16(10.5, 3), 7.5);
    check_d("FISUB m16  1.0 - 7 = -6.0",
            do_fisub_m16(1.0, 7), -6.0);

    check_d("FIMUL m16  3.5 * 4 = 14.0",
            do_fimul_m16(3.5, 4), 14.0);
    check_d("FIMUL m16  -2.0 * 3 = -6.0",
            do_fimul_m16(-2.0, 3), -6.0);

    check_d("FIDIV m16  12.0 / 4 = 3.0",
            do_fidiv_m16(12.0, 4), 3.0);
    check_d("FIDIV m16  7.0 / 2 = 3.5",
            do_fidiv_m16(7.0, 2), 3.5);

    check_d("FIDIVR m16  5.0: 10 / 5.0 = 2.0",
            do_fidivr_m16(5.0, 10), 2.0);
    check_d("FIDIVR m16  4.0: 3 / 4.0 = 0.75",
            do_fidivr_m16(4.0, 3), 0.75);

    check_d("FISUBR m16  10.0: 3 - 10.0 = -7.0",
            do_fisubr_m16(10.0, 3), -7.0);
    check_d("FISUBR m16  1.0: 5 - 1.0 = 4.0",
            do_fisubr_m16(1.0, 5), 4.0);

    check_d("FISUBR m32  10.0: 3 - 10.0 = -7.0",
            do_fisubr_m32(10.0, 3), -7.0);
    check_d("FISUBR m32  2.5: 100 - 2.5 = 97.5",
            do_fisubr_m32(2.5, 100), 97.5);

    /* ---- Section 3: FIST (non-popping) ---- */
    printf("\n=== FIST (non-popping) ===\n");

    check_i("FIST m16  3.0 → 3",
            do_fist_m16(3.0), 3);
    check_i("FIST m16  -7.0 → -7",
            do_fist_m16(-7.0), -7);
    check_i("FIST m16  2.5 (round-to-nearest=2)",
            do_fist_m16(2.5), 2);
    check_i("FIST m16  3.5 (round-to-nearest=4)",
            do_fist_m16(3.5), 4);

    check_i("FIST m32  1000.0 → 1000",
            do_fist_m32(1000.0), 1000);
    check_i("FIST m32  -999.0 → -999",
            do_fist_m32(-999.0), -999);
    check_i("FIST m32  2.5 (round-to-nearest=2)",
            do_fist_m32(2.5), 2);

    /* ---- Section 4: FRNDINT rounding modes ---- */
    printf("\n=== FRNDINT rounding modes ===\n");

    /* RC=0: round to nearest (even) */
    check_d("FRNDINT RC=0 nearest  2.7 → 3.0",
            do_frndint_rc(2.7, 0), 3.0);
    check_d("FRNDINT RC=0 nearest  2.5 → 2.0 (banker's)",
            do_frndint_rc(2.5, 0), 2.0);
    check_d("FRNDINT RC=0 nearest  3.5 → 4.0 (banker's)",
            do_frndint_rc(3.5, 0), 4.0);
    check_d("FRNDINT RC=0 nearest  -1.5 → -2.0",
            do_frndint_rc(-1.5, 0), -2.0);

    /* RC=1: round down (toward -inf) */
    check_d("FRNDINT RC=1 down     2.7 → 2.0",
            do_frndint_rc(2.7, 1), 2.0);
    check_d("FRNDINT RC=1 down     2.3 → 2.0",
            do_frndint_rc(2.3, 1), 2.0);
    check_d("FRNDINT RC=1 down     -2.3 → -3.0",
            do_frndint_rc(-2.3, 1), -3.0);
    check_d("FRNDINT RC=1 down     -2.7 → -3.0",
            do_frndint_rc(-2.7, 1), -3.0);

    /* RC=2: round up (toward +inf) */
    check_d("FRNDINT RC=2 up       2.3 → 3.0",
            do_frndint_rc(2.3, 2), 3.0);
    check_d("FRNDINT RC=2 up       2.7 → 3.0",
            do_frndint_rc(2.7, 2), 3.0);
    check_d("FRNDINT RC=2 up       -2.3 → -2.0",
            do_frndint_rc(-2.3, 2), -2.0);
    check_d("FRNDINT RC=2 up       -2.7 → -2.0",
            do_frndint_rc(-2.7, 2), -2.0);

    /* RC=3: truncate (toward zero) */
    check_d("FRNDINT RC=3 trunc    2.7 → 2.0",
            do_frndint_rc(2.7, 3), 2.0);
    check_d("FRNDINT RC=3 trunc    2.3 → 2.0",
            do_frndint_rc(2.3, 3), 2.0);
    check_d("FRNDINT RC=3 trunc    -2.7 → -2.0",
            do_frndint_rc(-2.7, 3), -2.0);
    check_d("FRNDINT RC=3 trunc    -2.3 → -2.0",
            do_frndint_rc(-2.3, 3), -2.0);

    /* ---- Section 5: FCOMI / FCOMIP / FUCOMI / FUCOMIP ---- */
    printf("\n=== FCOMI / FCOMIP / FUCOMI / FUCOMIP ===\n");

    check_i("FCOMI  5>3 → GT(1)",   do_fcomi(5.0, 3.0), 1);
    check_i("FCOMI  2<7 → LT(-1)",  do_fcomi(2.0, 7.0), -1);
    check_i("FCOMI  4==4 → EQ(0)",  do_fcomi(4.0, 4.0), 0);
    check_i("FCOMI  NaN → UN(2)",   do_fcomi(__builtin_nan(""), 1.0), 2);

    check_i("FCOMIP 5>3 → GT(1)",   do_fcomip(5.0, 3.0), 1);
    check_i("FCOMIP 2<7 → LT(-1)",  do_fcomip(2.0, 7.0), -1);
    check_i("FCOMIP 4==4 → EQ(0)",  do_fcomip(4.0, 4.0), 0);

    check_i("FUCOMI 5>3 → GT(1)",   do_fucomi(5.0, 3.0), 1);
    check_i("FUCOMI 2<7 → LT(-1)",  do_fucomi(2.0, 7.0), -1);
    check_i("FUCOMI 4==4 → EQ(0)",  do_fucomi(4.0, 4.0), 0);
    check_i("FUCOMI NaN → UN(2)",   do_fucomi(__builtin_nan(""), 1.0), 2);

    check_i("FUCOMIP 5>3 → GT(1)",  do_fucomip(5.0, 3.0), 1);
    check_i("FUCOMIP 1<9 → LT(-1)", do_fucomip(1.0, 9.0), -1);
    check_i("FUCOMIP 6==6 → EQ(0)", do_fucomip(6.0, 6.0), 0);
    check_i("FUCOMIP NaN → UN(2)",  do_fucomip(__builtin_nan(""), 1.0), 2);

    /* ---- Section 6: FCMOV (all 8 conditions) ---- */
    printf("\n=== FCMOV (8 condition variants) ===\n");

    /* FCMOVB: move if below (a < b) */
    check_d("FCMOVB  a<b: should move (99)",
            do_fcmovb(1.0, 5.0, 99.0), 99.0);     /* 1<5 → CF=1 → move */
    check_d("FCMOVB  a>b: should NOT move (1)",
            do_fcmovb(5.0, 1.0, 99.0), 5.0);       /* 5>1 → CF=0 → no move */

    /* FCMOVNB: move if not below (a >= b) */
    check_d("FCMOVNB a>b: should move (99)",
            do_fcmovnb(5.0, 1.0, 99.0), 99.0);     /* 5>1 → CF=0 → move */
    check_d("FCMOVNB a<b: should NOT move (1)",
            do_fcmovnb(1.0, 5.0, 99.0), 1.0);      /* 1<5 → CF=1 → no move */
    check_d("FCMOVNB a==b: should move (99)",
            do_fcmovnb(3.0, 3.0, 99.0), 99.0);     /* 3==3 → CF=0 → move */

    /* FCMOVE: move if equal */
    check_d("FCMOVE  a==b: should move (99)",
            do_fcmove(3.0, 3.0, 99.0), 99.0);      /* 3==3 → ZF=1 → move */
    check_d("FCMOVE  a!=b: should NOT move (5)",
            do_fcmove(5.0, 3.0, 99.0), 5.0);       /* 5!=3 → ZF=0 → no move */

    /* FCMOVNE: move if not equal */
    check_d("FCMOVNE a!=b: should move (99)",
            do_fcmovne(5.0, 3.0, 99.0), 99.0);     /* 5!=3 → ZF=0 → move */
    check_d("FCMOVNE a==b: should NOT move (3)",
            do_fcmovne(3.0, 3.0, 99.0), 3.0);      /* 3==3 → ZF=1 → no move */

    /* FCMOVBE: move if below or equal */
    check_d("FCMOVBE a<b: should move (99)",
            do_fcmovbe(1.0, 5.0, 99.0), 99.0);     /* 1<5 → CF=1 → move */
    check_d("FCMOVBE a==b: should move (99)",
            do_fcmovbe(3.0, 3.0, 99.0), 99.0);     /* 3==3 → ZF=1 → move */
    check_d("FCMOVBE a>b: should NOT move (5)",
            do_fcmovbe(5.0, 1.0, 99.0), 5.0);      /* 5>1 → no → no move */

    /* FCMOVNBE: move if not below or equal (above) */
    check_d("FCMOVNBE a>b: should move (99)",
            do_fcmovnbe(5.0, 1.0, 99.0), 99.0);    /* 5>1 → above → move */
    check_d("FCMOVNBE a<b: should NOT move (1)",
            do_fcmovnbe(1.0, 5.0, 99.0), 1.0);     /* 1<5 → no move */
    check_d("FCMOVNBE a==b: should NOT move (3)",
            do_fcmovnbe(3.0, 3.0, 99.0), 3.0);     /* 3==3 → no move */

    /* FCMOVU: move if unordered (PF=1, i.e. NaN involved) */
    {
        double nan_val = __builtin_nan("");
        check_d("FCMOVU  NaN: should move (99)",
                do_fcmovu(nan_val, 1.0, 99.0), 99.0);   /* NaN → PF=1 → move */
        check_d("FCMOVU  ordered: should NOT move (5)",
                do_fcmovu(5.0, 1.0, 99.0), 5.0);        /* ordered → PF=0 → no move */
    }

    /* FCMOVNU: move if not unordered (PF=0) */
    {
        double nan_val = __builtin_nan("");
        check_d("FCMOVNU ordered: should move (99)",
                do_fcmovnu(5.0, 1.0, 99.0), 99.0);      /* ordered → PF=0 → move */
        check_d("FCMOVNU NaN: should NOT move (NaN)",
                do_fcmovnu(nan_val, 1.0, 99.0), nan_val); /* NaN → PF=1 → no move */
    }

    /* ---- Section 7: FUCOMP / FUCOMPP / FTST ---- */
    printf("\n=== FUCOMP / FUCOMPP / FTST ===\n");

    check_u16("FUCOMP  5>3 GT=0x0000",   do_fucomp(5.0, 3.0), 0x0000);
    check_u16("FUCOMP  2<7 LT=0x0100",   do_fucomp(2.0, 7.0), 0x0100);
    check_u16("FUCOMP  4==4 EQ=0x4000",  do_fucomp(4.0, 4.0), 0x4000);
    check_u16("FUCOMP  NaN UN=0x4500",   do_fucomp(__builtin_nan(""), 1.0), 0x4500);

    check_u16("FUCOMPP 5>3 GT=0x0000",   do_fucompp(5.0, 3.0), 0x0000);
    check_u16("FUCOMPP 2<7 LT=0x0100",   do_fucompp(2.0, 7.0), 0x0100);
    check_u16("FUCOMPP 4==4 EQ=0x4000",  do_fucompp(4.0, 4.0), 0x4000);
    check_u16("FUCOMPP NaN UN=0x4500",    do_fucompp(__builtin_nan(""), 1.0), 0x4500);

    check_u16("FTST  5.0 > 0  GT=0x0000", do_ftst(5.0), 0x0000);
    check_u16("FTST  -3.0 < 0 LT=0x0100", do_ftst(-3.0), 0x0100);
    check_u16("FTST  0.0 == 0 EQ=0x4000", do_ftst(0.0), 0x4000);
    check_u16("FTST  NaN      UN=0x4500", do_ftst(__builtin_nan("")), 0x4500);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
