/*
 * test_fldcw.c — Tests for FLDCW, FNSTCW, and FNOP in the IR pipeline.
 *
 * These instructions are common in 2000s-era game code:
 *   FLDCW  — load control word (set rounding mode, precision, exception masks)
 *   FNSTCW — store control word (read back current settings)
 *   FNOP   — no-op (used as pipeline filler / alignment)
 *
 * Key scenarios:
 *   1. FNSTCW round-trips: store CW → read it back, value matches.
 *   2. FLDCW changes rounding mode visible to a subsequent FISTP in the same run.
 *   3. FNOP in the middle of an arithmetic sequence doesn't break the run.
 *   4. FLDCW + FNSTCW + arithmetic all in one run.
 *
 * Build: clang -arch x86_64 -O0 -o test_fldcw test_fldcw.c
 */
#include <stdio.h>
#include <stdint.h>

static int failures = 0;

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%04X  expected=0x%04X\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_i32(const char *name, int32_t got, int32_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=%d  expected=%d\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f64(const char *name, double got, double expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=%g  expected=%g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Standard x87 control word values. */
#define CW_NEAREST  0x037F   /* RC=00  round to nearest (even) */
#define CW_FLOOR    0x077F   /* RC=01  round down               */
#define CW_CEIL     0x0B7F   /* RC=10  round up                 */
#define CW_TRUNC    0x0F7F   /* RC=11  truncate toward zero     */

/* ── Helpers used outside of IR runs (call site keeps them isolated) ─────── */

static void set_cw(uint16_t cw) {
    __asm__ volatile ("fldcw %0" : : "m"(cw));
}

static uint16_t get_cw(void) {
    uint16_t cw;
    __asm__ volatile ("fnstcw %0" : "=m"(cw));
    return cw;
}

/* ── 1. FNSTCW round-trip ─────────────────────────────────────────────────
 * Push a value so the run has ≥2 instructions, then FNSTCW.
 * The IR run is: FLD + FNSTCW (2 insns) — FNSTCW is inside the run.
 */
static uint16_t fnstcw_roundtrip(uint16_t cw_in) {
    uint16_t cw_out = 0;
    __asm__ volatile (
        "fldcw  %1\n\t"     /* set CW before run (outside run) */
        "fldz\n\t"          /* FLD  → starts run, ST(0)=0      */
        "fnstcw %0\n\t"     /* FNSTCW — inside run             */
        "fstp   %%st(0)\n"  /* clean up stack                  */
        : "=m"(cw_out)
        : "m"(cw_in)
    );
    return cw_out;
}

/* ── 2. FLDCW inside IR run changes RC for subsequent FISTP ──────────────
 * Pattern: FLD + FLDCW + FISTP  (3-insn run).
 * FLDCW updates control_word in X87State; the immediately following FISTP
 * re-reads it and uses the new RC.
 */
static int32_t fldcw_then_fistp(double val, uint16_t new_cw) {
    int32_t result = 0;
    __asm__ volatile (
        "fldl   %1\n\t"    /* FLD val  → ST(0)=val; run starts here */
        "fldcw  %2\n\t"    /* FLDCW new_cw — inside run             */
        "fistpl %0\n"      /* FISTP → *result using new RC          */
        : "=m"(result)
        : "m"(val), "m"(new_cw)
    );
    return result;
}

/* ── 3. FNOP inside arithmetic run ───────────────────────────────────────
 * FLD + FNOP + FLD + FADD + FSTP — FNOP should be a transparent no-op.
 */
static double fnop_in_arith_run(double a, double b) {
    double result = 0.0;
    __asm__ volatile (
        "fldl   %1\n\t"    /* FLD a                     */
        "fnop\n\t"         /* FNOP — no-op inside run   */
        "fldl   %2\n\t"    /* FLD b                     */
        "faddp\n\t"        /* ST(1) += ST(0), pop       */
        "fstpl  %0\n"      /* FSTP result               */
        : "=m"(result)
        : "m"(a), "m"(b)
    );
    return result;
}

/* ── 4. FLDCW + FNSTCW + arithmetic all in one run ───────────────────────
 * FLDCW new_cw + FNSTCW cw_out + FLD a + FLD b + FADDP + FSTP result.
 * Verifies that the CW written by FLDCW is what FNSTCW reads back.
 */
static double fldcw_fnstcw_arith(double a, double b,
                                  uint16_t new_cw, uint16_t *cw_out) {
    double result = 0.0;
    __asm__ volatile (
        "fldcw  %2\n\t"    /* FLDCW  — run starts here          */
        "fnstcw %1\n\t"    /* FNSTCW — read back CW             */
        "fldl   %3\n\t"    /* FLD a                             */
        "fldl   %4\n\t"    /* FLD b                             */
        "faddp\n\t"        /* a + b                             */
        "fstpl  %0\n"      /* FSTP result                       */
        : "=m"(result), "=m"(*cw_out)
        : "m"(new_cw), "m"(a), "m"(b)
    );
    return result;
}

/* ── 5. Multiple FNOPs in a row ──────────────────────────────────────────
 * FNOP sequences are used as timing/alignment filler in old games.
 */
static double fnop_x3(double a, double b) {
    double result = 0.0;
    __asm__ volatile (
        "fldl   %1\n\t"
        "fnop\n\t"
        "fnop\n\t"
        "fnop\n\t"
        "fldl   %2\n\t"
        "fmulp\n\t"
        "fstpl  %0\n"
        : "=m"(result)
        : "m"(a), "m"(b)
    );
    return result;
}

/* ── 6. FNSTCW + FLDCW restore pattern ──────────────────────────────────
 * Classic compiler-generated code: save CW, change it, restore it.
 * All in one IR run: FNSTCW save + FLDCW new + ... + FLDCW restore.
 */
static void fnstcw_save_fldcw_restore(uint16_t new_cw,
                                       uint16_t *saved, uint16_t *restored) {
    __asm__ volatile (
        "fnstcw %0\n\t"     /* save current CW           */
        "fldcw  %2\n\t"     /* load new CW               */
        "fnstcw %1\n"       /* read back to verify       */
        : "=m"(*saved), "=m"(*restored)
        : "m"(new_cw)
    );
}

/* ── 7. OPT-CF: MSVC ftol idiom — in-run CONSTANT control word ──────────
 * `mov m16, #CW; fldcw m16; fistp; fldcw restore` makes RC a translate-time
 * constant: the conversion must lower to a single statically-rounded FCVT
 * and still produce the mode's exact result. The restore then re-enters
 * dynamic-RC territory — the second conversion must use the RESTORED mode.
 */
/* The immediate must be literal in the asm — one function per mode. */
#define FTOL_CONST_FN(name, imm)                                        \
    static int32_t name(double val) {                                   \
        int32_t result = 0;                                             \
        uint16_t slot = 0;                                              \
        __asm__ volatile (                                              \
            "fldl   %2\n\t"                                             \
            "movw   $" #imm ", %1\n\t"                                  \
            "fldcw  %1\n\t"                                             \
            "fistpl %0\n"                                               \
            : "=m"(result), "=m"(slot)                                  \
            : "m"(val));                                                \
        return result;                                                  \
    }

FTOL_CONST_FN(ftol_const_trunc,   0x0f7f)  /* RC=11 truncate */
FTOL_CONST_FN(ftol_const_nearest, 0x037f)  /* RC=00 nearest  */
FTOL_CONST_FN(ftol_const_floor,   0x077f)  /* RC=01 floor    */
FTOL_CONST_FN(ftol_const_ceil,    0x0b7f)  /* RC=10 ceil     */

/* Constant store OVERWRITTEN by a second one — the fold must use the last. */
static int32_t ftol_const_overwrite(double val) {
    int32_t result = 0;
    uint16_t slot = 0;
    __asm__ volatile (
        "fldl   %2\n\t"
        "movw   $0x0f7f, %1\n\t"   /* truncate...                */
        "movw   $0x037f, %1\n\t"   /* ...overwritten: nearest    */
        "fldcw  %1\n\t"
        "fistpl %0\n"
        : "=m"(result), "=m"(slot)
        : "m"(val));
    return result;
}

/* Full MSVC _ftol shape with restore: the first conversion uses the folded
 * truncate mode; the conversion AFTER the (unknown-value) restore must use
 * the restored mode again. */
static void ftol_msvc_restore(double val, int32_t *r_trunc, int32_t *r_after) {
    uint16_t saved = 0, slot = 0;
    __asm__ volatile (
        "fnstcw %2\n\t"            /* save entry CW (nearest)          */
        "fldl   %4\n\t"
        "fldl   %4\n\t"
        "movw   $0x0f7f, %3\n\t"
        "fldcw  %3\n\t"            /* constant: truncate               */
        "fistpl %0\n\t"            /* static FCVTZS                    */
        "fldcw  %2\n\t"            /* restore (unknown value)          */
        "fistpl %1\n"              /* dynamic: restored mode (nearest) */
        : "=m"(*r_trunc), "=m"(*r_after), "=m"(saved), "=m"(slot)
        : "m"(val));
}

/* FRNDINT under a folded constant CW. */
static double frndint_const_floor(double val) {
    double result = 0.0;
    uint16_t slot = 0;
    __asm__ volatile (
        "fldl   %2\n\t"
        "movw   $0x077f, %1\n\t"
        "fldcw  %1\n\t"
        "frndint\n\t"
        "fstpl  %0\n"
        : "=m"(result), "=m"(slot)
        : "m"(val));
    return result;
}

int main(void) {
    uint16_t saved_cw = get_cw();

    /* ── 1. FNSTCW round-trips ─────────────────────────────────────────── */
    printf("=== FNSTCW round-trip ===\n");
    {
        check_u16("FNSTCW round-trip  CW_NEAREST",
                  fnstcw_roundtrip(CW_NEAREST), CW_NEAREST);
        check_u16("FNSTCW round-trip  CW_FLOOR",
                  fnstcw_roundtrip(CW_FLOOR),   CW_FLOOR);
        check_u16("FNSTCW round-trip  CW_CEIL",
                  fnstcw_roundtrip(CW_CEIL),    CW_CEIL);
        check_u16("FNSTCW round-trip  CW_TRUNC",
                  fnstcw_roundtrip(CW_TRUNC),   CW_TRUNC);
    }

    /* ── 2. FLDCW changes RC for FISTP in same run ─────────────────────── */
    printf("\n=== FLDCW in-run: RC visible to FISTP ===\n");
    {
        set_cw(CW_NEAREST);  /* baseline: nearest */
        check_i32("FLDCW→FLOOR  then FISTP  2.9 → 2",
                  fldcw_then_fistp(2.9,  CW_FLOOR), 2);
        check_i32("FLDCW→FLOOR  then FISTP -2.9 → -3",
                  fldcw_then_fistp(-2.9, CW_FLOOR), -3);
        check_i32("FLDCW→CEIL   then FISTP  2.1 → 3",
                  fldcw_then_fistp(2.1,  CW_CEIL),  3);
        check_i32("FLDCW→CEIL   then FISTP -2.1 → -2",
                  fldcw_then_fistp(-2.1, CW_CEIL),  -2);
        check_i32("FLDCW→TRUNC  then FISTP  2.9 → 2",
                  fldcw_then_fistp(2.9,  CW_TRUNC), 2);
        check_i32("FLDCW→TRUNC  then FISTP -2.9 → -2",
                  fldcw_then_fistp(-2.9, CW_TRUNC), -2);
        check_i32("FLDCW→NEAREST then FISTP 2.5 → 2",
                  fldcw_then_fistp(2.5,  CW_NEAREST), 2); /* ties to even */
    }

    /* ── 3. FNOP inside arithmetic run ─────────────────────────────────── */
    printf("\n=== FNOP inside arithmetic run ===\n");
    {
        set_cw(CW_NEAREST);
        check_f64("FNOP in run: 3.0 + 4.0 = 7.0",
                  fnop_in_arith_run(3.0, 4.0), 7.0);
        check_f64("FNOP in run: -1.5 + 2.5 = 1.0",
                  fnop_in_arith_run(-1.5, 2.5), 1.0);
        check_f64("FNOP in run: 0.0 + 0.0 = 0.0",
                  fnop_in_arith_run(0.0, 0.0), 0.0);
    }

    /* ── 4. FLDCW + FNSTCW + arithmetic in one run ─────────────────────── */
    printf("\n=== FLDCW + FNSTCW + arithmetic in one run ===\n");
    {
        uint16_t cw_out;
        double r;

        r = fldcw_fnstcw_arith(3.0, 4.0, CW_FLOOR, &cw_out);
        check_u16("FLDCW→FLOOR, FNSTCW reads back CW_FLOOR", cw_out, CW_FLOOR);
        check_f64("FLDCW→FLOOR, 3.0+4.0=7.0", r, 7.0);

        r = fldcw_fnstcw_arith(1.0, 2.0, CW_CEIL, &cw_out);
        check_u16("FLDCW→CEIL,  FNSTCW reads back CW_CEIL",  cw_out, CW_CEIL);
        check_f64("FLDCW→CEIL,  1.0+2.0=3.0", r, 3.0);
    }

    /* ── 5. Multiple FNOPs ──────────────────────────────────────────────── */
    printf("\n=== Multiple FNOPs ===\n");
    {
        set_cw(CW_NEAREST);
        check_f64("3x FNOP: 3.0 * 4.0 = 12.0", fnop_x3(3.0, 4.0), 12.0);
        check_f64("3x FNOP: 2.5 * 2.0 = 5.0",  fnop_x3(2.5, 2.0), 5.0);
    }

    /* ── 6. FNSTCW save / FLDCW restore pattern ─────────────────────────── */
    printf("\n=== FNSTCW save + FLDCW + FNSTCW verify ===\n");
    {
        set_cw(CW_NEAREST);
        uint16_t saved, restored;

        fnstcw_save_fldcw_restore(CW_TRUNC, &saved, &restored);
        check_u16("saved CW is CW_NEAREST", saved, CW_NEAREST);
        check_u16("restored reads CW_TRUNC", restored, CW_TRUNC);

        /* Reset so FNSTCW test below starts from NEAREST */
        set_cw(CW_NEAREST);
        fnstcw_save_fldcw_restore(CW_FLOOR, &saved, &restored);
        check_u16("saved CW_NEAREST before FLDCW→FLOOR", saved, CW_NEAREST);
        check_u16("restored reads CW_FLOOR", restored, CW_FLOOR);
    }

    /* ── 7. OPT-CF: constant control word (MSVC ftol) ───────────────────── */
    printf("\n=== OPT-CF: mov m16,#CW; fldcw; convert ===\n");
    {
        set_cw(CW_NEAREST);
        check_i32("ftol const trunc: 1.7 -> 1",    ftol_const_trunc(1.7), 1);
        check_i32("ftol const trunc: -1.7 -> -1",  ftol_const_trunc(-1.7), -1);
        check_i32("ftol const trunc: 2.5 -> 2",    ftol_const_trunc(2.5), 2);

        set_cw(CW_TRUNC);  /* entry mode must NOT leak into the fold */
        check_i32("ftol const nearest: 1.7 -> 2",  ftol_const_nearest(1.7), 2);
        check_i32("ftol const nearest: 2.5 -> 2 (ties-even)",
                  ftol_const_nearest(2.5), 2);
        check_i32("ftol const nearest: 3.5 -> 4 (ties-even)",
                  ftol_const_nearest(3.5), 4);

        set_cw(CW_NEAREST);
        check_i32("ftol const floor: 1.7 -> 1",    ftol_const_floor(1.7), 1);
        check_i32("ftol const floor: -1.7 -> -2",  ftol_const_floor(-1.7), -2);
        check_i32("ftol const ceil: 1.2 -> 2",     ftol_const_ceil(1.2), 2);
        check_i32("ftol const ceil: -1.2 -> -1",   ftol_const_ceil(-1.2), -1);

        set_cw(CW_NEAREST);
        check_i32("ftol const overwrite: last store wins (nearest 1.7 -> 2)",
                  ftol_const_overwrite(1.7), 2);

        set_cw(CW_NEAREST);
        int32_t r_trunc = 0, r_after = 0;
        ftol_msvc_restore(1.7, &r_trunc, &r_after);
        check_i32("ftol+restore: folded trunc 1.7 -> 1", r_trunc, 1);
        check_i32("ftol+restore: post-restore nearest 1.7 -> 2", r_after, 2);

        set_cw(CW_NEAREST);
        check_f64("frndint const floor: 2.7 -> 2.0",
                  frndint_const_floor(2.7), 2.0);
        check_f64("frndint const floor: -2.3 -> -3.0",
                  frndint_const_floor(-2.3), -3.0);
    }

    /* Restore original control word */
    set_cw(saved_cw);

    printf("\n%s  (%d failure%s)\n",
           failures == 0 ? "ALL PASS" : "SOME FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
