/*
 * test_nzcv_liveness.c — flag-liveness-assisted NZCV elision after runs.
 *
 * nzcv_dead_after_run consults Rosetta's flag-liveness dataflow
 * (IRInstr::flag_liveness) at partial/conditional flag definers the plain
 * whitelist walk must give up on: inc/dec (CF flows through), sahf (OF flows
 * through), CL-count shifts and rol/ror.
 *
 * Two directions:
 * 1. Pre-run flags that flow THROUGH the definer and are read afterwards
 *    must survive — the dataflow marks them live, the NZCV save/restore
 *    stays. These cases fail loudly if flag_liveness were untrustworthy at
 *    the definer (e.g. never written → 0 → spurious elision).
 * 2. When the flowed-through flag is dead the elision may fire — compare
 *    results consumed via fnstsw/sahf must still be exact.
 *
 * Compile (x86_64 target, e.g. under Rosetta):
 *   clang -arch x86_64 -O0 -o test_nzcv_liveness test_nzcv_liveness.c
 */

#include <stdio.h>

static int failures = 0;

#define CHECK(name, cond, got)                                          \
    do {                                                                \
        if (cond) {                                                     \
            printf("PASS %s\n", name);                                  \
        } else {                                                        \
            printf("FAIL %s (got %d)\n", name, (int)(got));             \
            failures++;                                                 \
        }                                                               \
    } while (0)

static double vals[2] = {1.5, 2.5};

/* Pre-run CF must survive the compare run AND the inc (which preserves CF):
   the dataflow sees CF live out of the inc → conservative pair kept. */
static int pre_cf_survives_inc(unsigned x) {
    int out;
    unsigned scratch = 0;
    unsigned short sw;
    __asm__ volatile(
        "cmpl   $1, %3\n\t"        /* pre-run CF: borrow iff x < 1 */
        "fldl   (%4)\n\t"
        "fcompl 8(%4)\n\t"         /* run: FCMP would clobber NZCV */
        "fnstsw %%ax\n\t"
        "movw   %%ax, %2\n\t"
        "incl   %1\n\t"            /* preserves CF; walk consults liveness */
        "setc   %%al\n\t"          /* reads the PRE-RUN CF */
        "movzbl %%al, %0\n\t"
        : "=r"(out), "+r"(scratch), "=m"(sw)
        : "r"(x), "r"(vals)
        : "ax", "cc", "memory");
    return out;
}

/* Pre-run OF must survive the run AND the sahf (which writes SF/ZF/AF/PF/CF
   from AH but preserves OF): OF live out of sahf → pair kept. */
static int pre_of_survives_sahf(int x) {
    int out;
    __asm__ volatile(
        "cmpl   $1, %1\n\t"        /* x=INT_MIN → OF=1; x=0 → OF=0 */
        "fldl   (%2)\n\t"
        "fcompl 8(%2)\n\t"
        "fnstsw %%ax\n\t"
        "sahf\n\t"                 /* redefines all but OF */
        "seto   %%al\n\t"          /* reads the PRE-RUN OF */
        "movzbl %%al, %0\n\t"
        : "=r"(out)
        : "r"(x), "r"(vals)
        : "ax", "cc", "memory");
    return out;
}

/* Compare consumed through fnstsw+sahf+setb, then a test redefines EFLAGS:
   OF is dead at the sahf, the elision may fire — result must be exact. */
static int sahf_below_of_dead(unsigned x) {
    int out, dead;
    __asm__ volatile(
        "fldl   (%2)\n\t"          /* 1.5 */
        "fcompl 8(%2)\n\t"         /* vs 2.5 → C0 (below) */
        "fnstsw %%ax\n\t"
        "sahf\n\t"                 /* C0→CF, C3→ZF */
        "setb   %%al\n\t"          /* below → CF → 1 */
        "movzbl %%al, %0\n\t"
        "testl  %3, %3\n\t"        /* full definer: kills ret's all-live seed */
        "setne  %%al\n\t"
        "movzbl %%al, %1\n\t"
        : "=r"(out), "=r"(dead)
        : "r"(vals), "r"(x)
        : "ax", "cc", "memory");
    return out + (dead << 1);
}

/* Compare consumed via fnstsw+test AFTER an inc whose flowed-through CF is
   dead (the test defines CF): elision may fire — result must be exact. */
static int inc_cf_dead(void) {
    int out;
    unsigned scratch = 0;
    __asm__ volatile(
        "fldl   (%2)\n\t"          /* 1.5 */
        "fcompl 8(%2)\n\t"         /* vs 2.5 → C0 (below) */
        "fnstsw %%ax\n\t"
        "incl   %1\n\t"            /* CF dead below (test defines it) */
        "testb  $0x45, %%ah\n\t"   /* C0|C2|C3 */
        "setne  %%al\n\t"          /* 1.5 < 2.5 → 1 */
        "movzbl %%al, %0\n\t"
        : "=r"(out), "+r"(scratch)
        : "r"(vals)
        : "ax", "cc", "memory");
    return out;
}

/* x87 instructions in the post-run tail are EFLAGS-neutral: the run breaks
   at the fstpt (m80 store — the IR declines it), the walk crosses it and
   reaches the test (full definer) — elision may fire; result must be exact. */
static int x87_tail_elision(void) {
    int out;
    unsigned char t80[10];
    __asm__ volatile(
        "fldl   (%2)\n\t"          /* 1.5 */
        "fldl   8(%2)\n\t"         /* 2.5 */
        "fcompp\n\t"               /* 2.5 vs 1.5 → above: C0=C2=C3=0 */
        "fnstsw %%ax\n\t"
        "fldl   (%2)\n\t"
        "fstpt  %1\n\t"            /* m80 store: run ends here */
        "testb  $0x45, %%ah\n\t"
        "sete   %%al\n\t"          /* above → all CC clear → 1 */
        "movzbl %%al, %0\n\t"
        : "=r"(out), "=m"(t80)
        : "r"(vals)
        : "ax", "cc", "memory");
    return out;
}

int main(void) {
    CHECK("x87_tail_elision", x87_tail_elision() == 1, x87_tail_elision());
    CHECK("pre_cf_survives_inc_b", pre_cf_survives_inc(0) == 1, pre_cf_survives_inc(0));
    CHECK("pre_cf_survives_inc_ae", pre_cf_survives_inc(5) == 0, pre_cf_survives_inc(5));
    CHECK("pre_of_survives_sahf_o", pre_of_survives_sahf((int)0x80000000) == 1,
          pre_of_survives_sahf((int)0x80000000));
    CHECK("pre_of_survives_sahf_no", pre_of_survives_sahf(0) == 0, pre_of_survives_sahf(0));
    CHECK("sahf_below_of_dead", sahf_below_of_dead(3) == 3, sahf_below_of_dead(3));
    CHECK("sahf_below_of_dead_z", sahf_below_of_dead(0) == 1, sahf_below_of_dead(0));
    CHECK("inc_cf_dead", inc_cf_dead() == 1, inc_cf_dead());

    if (failures == 0)
        printf("ALL PASS (test_nzcv_liveness)\n");
    return failures != 0;
}
