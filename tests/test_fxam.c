/*
 * test_fxam.c — Tests for FXAM classification of x87 values.
 *
 * Build: clang -arch x86_64 -O0 -o test_fxam test_fxam.c -lm
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        printf("FAIL  %-52s  got=0x%04x  expected=0x%04x\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/*
 * FXAM condition code encoding (C3, C2, C0 — C1 is sign):
 *   Empty      C3=1  C2=0  C0=1  → 0x4100
 *   Zero       C3=1  C2=0  C0=0  → 0x4000
 *   Normal     C3=0  C2=1  C0=0  → 0x0400
 *   Infinity   C3=0  C2=1  C0=1  → 0x0500
 *   NaN        C3=0  C2=0  C0=1  → 0x0100
 *   Denormal   C3=1  C2=1  C0=0  → 0x4400
 *
 * C1 (0x0200) = sign bit of the value.
 * Mask 0x4700 extracts C3, C2, C1, C0.
 */

static uint16_t do_fxam(double v) {
    uint16_t sw;
    __asm__ volatile(
        "fldl  %1\n\t"
        "fxam\n\t"
        "fnstsw %%ax\n\t"
        "movw  %%ax, %0\n\t"
        "fstp  %%st(0)\n\t"
        : "=m"(sw)
        : "m"(v)
        : "ax", "st");
    return sw & 0x4700;
}

int main(void) {
    /* Zero */
    check_u16("fxam(+0.0)",  do_fxam(0.0),   0x4000);
    check_u16("fxam(-0.0)",  do_fxam(-0.0),  0x4200);

    /* Normal */
    check_u16("fxam(+1.0)",  do_fxam(1.0),   0x0400);
    check_u16("fxam(-1.0)",  do_fxam(-1.0),  0x0600);
    check_u16("fxam(+42.5)", do_fxam(42.5),  0x0400);

    /* Infinity */
    check_u16("fxam(+inf)",  do_fxam(INFINITY),  0x0500);
    check_u16("fxam(-inf)",  do_fxam(-INFINITY), 0x0700);

    /* NaN */
    check_u16("fxam(NaN)",   do_fxam(NAN),   0x0100);

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
