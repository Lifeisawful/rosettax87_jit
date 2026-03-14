/*
 * test_fcom_nzcv.c -- validate NZCV save/restore across FCOM flag mapping
 *
 * Build:  clang -arch x86_64 -O0 -g -o test_fcom_nzcv test_fcom_nzcv.c
 *
 * The translate_fcom path saves NZCV before FCMP and restores it afterward
 * (via MRS/MSR NZCV).  If the MRS encoding is wrong (0xD5334200 instead of
 * the correct 0xD53B4200), the save reads 0 and the restore zeroes out any
 * prior x86 ALU flags — breaking subsequent EFLAGS-dependent branches.
 *
 * Section A:  FCOM CC bits (GT/LT/EQ/UN) are mapped correctly for all four
 *             comparison outcomes.  CF is primed to 1 before each FCOM via a
 *             CMP, ensuring NZCV is non-zero at MRS time.
 *
 * Section B:  x86 CF survives across FCOM (direct MRS/MSR roundtrip check).
 *             Pattern: CMP sets CF=1 → FCOM → SETB reads CF.
 *             A wrong MRS encoding causes MSR to restore 0, clearing CF so
 *             SETB returns 0 instead of 1.
 */

#include <stdint.h>
#include <stdio.h>

static int failures = 0;

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-70s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_u8(const char *name, uint8_t got, uint8_t expected) {
    if (got != expected) {
        printf("FAIL  %-70s  got=%u  expected=%u\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* Read x87 status-word CC bits after a compare (mask to C0/C2/C3). */
#define READ_SW(var)                                        \
    uint16_t var;                                           \
    __asm__ volatile (                                      \
        "fnstsw %%ax\n"                                     \
        "andw $0x4500, %%ax\n"                              \
        "movw %%ax, %0\n"                                   \
        : "=m" (var) : : "ax"                               \
    )

/* =========================================================================
 * Section A: FCOM CC bits survive NZCV save/restore
 *
 * Before each FCOM we execute a CMP that sets CF=1 (0 < 1 unsigned).
 * This ensures NZCV is non-zero before the MRS.  A buggy MRS (reading 0)
 * would not corrupt the x87 CC results themselves here, but it would zero
 * the restored NZCV, which Section B detects.
 * ========================================================================= */

static uint16_t section_a_gt(void) {
    double st0 = 3.0, src = 1.0;
    /* prime CF=1 before FCOM */
    __asm__ volatile ("xorl %%eax, %%eax\n\t" "cmpl $1, %%eax\n" : : : "eax", "cc");
    __asm__ volatile ("fldl %0\n" : : "m" (st0));
    __asm__ volatile ("fcoml %0\n" : : "m" (src));
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

static uint16_t section_a_lt(void) {
    double st0 = 1.0, src = 3.0;
    __asm__ volatile ("xorl %%eax, %%eax\n\t" "cmpl $1, %%eax\n" : : : "eax", "cc");
    __asm__ volatile ("fldl %0\n" : : "m" (st0));
    __asm__ volatile ("fcoml %0\n" : : "m" (src));
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

static uint16_t section_a_eq(void) {
    double st0 = 2.0, src = 2.0;
    __asm__ volatile ("xorl %%eax, %%eax\n\t" "cmpl $1, %%eax\n" : : : "eax", "cc");
    __asm__ volatile ("fldl %0\n" : : "m" (st0));
    __asm__ volatile ("fcoml %0\n" : : "m" (src));
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

static uint16_t section_a_un(void) {
    double nan_val = __builtin_nan(""), src = 1.0;
    __asm__ volatile ("xorl %%eax, %%eax\n\t" "cmpl $1, %%eax\n" : : : "eax", "cc");
    __asm__ volatile ("fldl %0\n" : : "m" (nan_val));
    __asm__ volatile ("fcoml %0\n" : : "m" (src));
    READ_SW(cc);
    __asm__ volatile ("fstp %%st(0)\n" : : : "st");
    return cc;
}

/* =========================================================================
 * Section B: x86 CF survives across FCOM (MRS/MSR roundtrip smoke test)
 *
 * Pattern:
 *   1. XOR eax,eax + CMP eax,1 → CF=1 (unsigned 0 < 1)
 *   2. FCOM (JIT: MRS saves NZCV; FCMP; branchless CC map; MSR restores)
 *   3. SETB — reads CF; must be 1 if MSR restored NZCV correctly
 *
 * Wrong MRS encoding → MRS reads 0 → MSR restores CF=0 → SETB returns 0.
 * ========================================================================= */

/* FCOM ST(1) variant */
static uint8_t section_b_cf_survives_fcom(void) {
    double a = 1.0, b = 2.0;
    uint8_t result = 0;
    __asm__ volatile (
        "xorl  %%eax, %%eax\n\t"  /* eax = 0                   */
        "cmpl  $1, %%eax\n\t"     /* 0 < 1 unsigned → CF=1     */
        "fldl  %2\n\t"            /* push b=2.0                 */
        "fldl  %1\n\t"            /* push a=1.0; ST(1)=2.0      */
        "fcom  %%st(1)\n\t"       /* FCOM ST(1): MRS/MSR path   */
        "fstp  %%st(0)\n\t"       /* pop a                      */
        "fstp  %%st(0)\n\t"       /* pop b                      */
        "setb  %0\n"              /* CF should still be 1       */
        : "=r" (result)
        : "m" (a), "m" (b)
        : "eax", "cc", "st"
    );
    return result;
}

/* FCOML m64 variant (memory operand — same MRS/MSR path) */
static uint8_t section_b_cf_survives_fcoml(void) {
    double a = 1.0, b = 2.0;
    uint8_t result = 0;
    __asm__ volatile (
        "xorl  %%eax, %%eax\n\t"
        "cmpl  $1, %%eax\n\t"
        "fldl  %1\n\t"
        "fcoml %2\n\t"
        "fstp  %%st(0)\n\t"
        "setb  %0\n"
        : "=r" (result)
        : "m" (a), "m" (b)
        : "eax", "cc", "st"
    );
    return result;
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void) {
    /* Section A: CC bits */
    check_u16("A/fcom GT (3.0 > 1.0) => C3=0 C2=0 C0=0", section_a_gt(), 0x0000);
    check_u16("A/fcom LT (1.0 < 3.0) => C3=0 C2=0 C0=1", section_a_lt(), 0x0100);
    check_u16("A/fcom EQ (2.0 = 2.0) => C3=1 C2=0 C0=0", section_a_eq(), 0x4000);
    check_u16("A/fcom UN (NaN vs 1.0) => C3=1 C2=1 C0=1", section_a_un(), 0x4500);

    /* Section B: CF survives MRS/MSR roundtrip */
    check_u8("B/fcom  ST(1): CF=1 before FCOM is preserved after",
             section_b_cf_survives_fcom(), 1);
    check_u8("B/fcoml m64:  CF=1 before FCOML is preserved after",
             section_b_cf_survives_fcoml(), 1);

    if (failures == 0)
        printf("\nAll tests passed.\n");
    else
        printf("\n%d test(s) FAILED.\n", failures);

    return failures ? 1 : 0;
}
