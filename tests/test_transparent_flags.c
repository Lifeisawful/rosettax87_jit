/*
 * test_transparent_flags.c — TRANSPARENT_FLAGS: xor r,r zero idiom inside
 * x87 runs.
 *
 * Under ROSETTA_X87_TRANSPARENT_FLAGS=1 a self-xor whose flag results are
 * provably dead (Rosetta's flag_liveness == 0) is consumed mid-run as
 * GuestMovRI 0 instead of ending IR consumption.  The consumed form emits no
 * flag writes, so correctness depends entirely on the liveness gate.  These
 * tests pin down both sides:
 *   - consumed: register is zeroed, surrounding x87 results unchanged
 *   - flags LIVE (a jcc/setcc/fcmov reads them before redefinition): the
 *     idiom must NOT be consumed — the xor's architectural flag effects
 *     (ZF=1, CF=0, PF=1, SF=0, OF=0) must be observable
 *
 * The mixed fp/int shapes mirror the hot decline cluster in the WoW binary
 * (matrix-scale: fld/fmul/fst interleaved with xor+mov zero-stores).
 *
 * Build: clang -arch x86_64 -O0 -o test_transparent_flags test_transparent_flags.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

static void check_u(const char *name, uint64_t got, uint64_t expected) {
    if (got != expected) {
        printf("FAIL  %-55s  got=0x%llx  expected=0x%llx\n", name,
               (unsigned long long)got, (unsigned long long)expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

static void check_f(const char *name, float got, float expected) {
    uint32_t a, b;
    memcpy(&a, &got, 4); memcpy(&b, &expected, 4);
    if (a != b) {
        printf("FAIL  %-55s  got=%.9g  expected=%.9g\n", name, got, expected);
        failures++;
    } else {
        printf("PASS  %s\n", name);
    }
}

/* WoW matrix-scale shape: fld/fmul/fst run with xor+mov zero-stores in the
 * middle.  Flags die at the trailing `test` — the xor is consumable. */
static void wow_scale_shape(float s, float *v /* [4]: in-out, [3] zeroed */,
                            uint32_t *zeroed) {
    uint32_t z;
    __asm__ volatile(
        "flds %2\n"
        "xorl %%eax, %%eax\n"        /* zero idiom, flags dead (test below) */
        "fmuls (%1)\n"
        "movl %%eax, 12(%1)\n"       /* zero-store through eax */
        "fsts (%1)\n"
        "flds %2\n"
        "fmuls 4(%1)\n"
        "fstps 4(%1)\n"
        "flds %2\n"
        "fmuls 8(%1)\n"
        "fstps 8(%1)\n"
        "fstp %%st(0)\n"
        "movl %%eax, %0\n"
        "testl %%eax, %%eax\n"       /* full EFLAGS redefinition */
        : "=r"(z) : "r"(v), "m"(s) : "eax", "memory", "cc");
    *zeroed = z;
}

/* 64-bit form: xor rax,rax mid-run (W-write zero-extend covers r64). */
static uint64_t zero64_mid_run(double *a /* [2] */) {
    uint64_t r = 0xDEADBEEFCAFEF00DULL;
    __asm__ volatile(
        "fldl (%1)\n"
        "xorq %%rax, %%rax\n"
        "faddl 8(%1)\n"
        "fstpl (%1)\n"
        "movq %%rax, %0\n"
        "testq %%rax, %%rax\n"
        : "=r"(r) : "r"(a) : "rax", "memory", "cc");
    return r;
}

/* Flags LIVE: a setz reads ZF right after the xor — must not be consumed;
 * the xor's ZF=1 must be observable. */
static uint32_t flags_live_setz(double *a) {
    uint32_t r;
    __asm__ volatile(
        "cmpl $1, %2\n"              /* ZF=0 beforehand (1 != 2) */
        "fldl (%1)\n"
        "xorl %%eax, %%eax\n"        /* ZF=1 — read below, NOT dead */
        "fchs\n"
        "fstpl (%1)\n"
        "setz %%al\n"                /* observes the xor's ZF */
        "movl %%eax, %0\n"
        : "=r"(r) : "r"(a), "r"(2) : "eax", "memory", "cc");
    return r;  /* al = 1 iff the xor's ZF survived */
}

/* Flags LIVE via CF: jnc after the xor (CF=0 from xor; CF=1 beforehand). */
static uint32_t flags_live_carry(double *a) {
    uint32_t r;
    __asm__ volatile(
        "movl $0, %0\n"
        "cmpl $5, %2\n"              /* 2 < 5 -> CF=1 beforehand */
        "fldl (%1)\n"
        "xorl %%ecx, %%ecx\n"        /* CF=0 — read below, NOT dead */
        "fabs\n"
        "fstpl (%1)\n"
        "jc 1f\n"                    /* taken only if xor's CF clear lost */
        "movl $1, %0\n"              /* correct path: CF==0 */
        "1:\n"
        : "+r"(r) : "r"(a), "r"(2) : "ecx", "memory", "cc");
    return r;  /* 1 iff the xor's CF=0 survived */
}

/* fcomi + xor + fcmovb: the fcmov reads CF/ZF/PF — the xor between them
 * redefines exactly those flags, so it must not be consumed AND its own
 * flag writes must be materialized (fcmovb sees the xor's CF=0). */
static double fcomi_xor_fcmov(double a, double b) {
    double out;
    __asm__ volatile(
        "fldl %2\n"                  /* st1 = b */
        "fldl %1\n"                  /* st0 = a */
        "fcomi %%st(1), %%st\n"      /* CF = (a < b) */
        "xorl %%edx, %%edx\n"        /* CF=0 — overrides the compare! */
        "fcmovb %%st(1), %%st\n"     /* never moves: CF is 0 */
        "fstpl %0\n"
        "fstp %%st(0)\n"
        : "=m"(out) : "m"(a), "m"(b) : "edx", "cc");
    return out;  /* always a: the xor killed the fcomi's CF */
}

/* ── Stage 2: reg-imm ALU + memory RMW forms ──────────────────────────────── */

/* WoW sign-bit-extraction shape (0x6aaf7x): fld/fadd/fstp with mov r,m +
 * shr r,imm + and r,imm + or [m],r interleaved.  All flag writes die at the
 * next definer (or the trailing test) — everything is consumable. */
static uint32_t sign_pack_shape(const float *v /* [3] */, float bias) {
    uint32_t out, tmp;
    __asm__ volatile(
        "movl $0, %0\n"
        "flds (%2)\n"
        "fadds %3\n"
        "fstps %1\n"
        "movl %1, %%esi\n"
        "shrl $31, %%esi\n"
        "movl %%esi, %0\n"
        "flds 4(%2)\n"
        "fadds %3\n"
        "fstps %1\n"
        "movl %1, %%esi\n"
        "shrl $30, %%esi\n"
        "andl $2, %%esi\n"
        "orl %%esi, %0\n"
        "flds 8(%2)\n"
        "fadds %3\n"
        "fstps %1\n"
        "movl %1, %%esi\n"
        "shrl $29, %%esi\n"
        "andl $4, %%esi\n"
        "orl %%esi, %0\n"
        "testl %%esi, %%esi\n"
        : "=m"(out), "=m"(tmp) : "r"(v), "m"(bias) : "esi", "cc");
    return out;
}

/* Reg-imm ALU chain mid-run: add (imm8 sign-extended), sub (imm needing the
 * temp-GPR path), shl, sar, shr with count masking (33 & 31 = 1), and a
 * bitmask-encodable and/xor.  Interleaved with x87 so consumption happens
 * inside one run; flags die at the trailing test. */
static uint32_t alu_imm_chain(uint32_t x, double *d) {
    uint32_t r = x;
    __asm__ volatile(
        "fldl (%2)\n"
        "addl $-7, %0\n"
        "fabs\n"
        "subl $0x12345, %0\n"
        "fchs\n"
        "shll $4, %0\n"
        "fldl 8(%2)\n"
        "sarl $2, %0\n"
        "faddp\n"
        "shrl $33, %0\n"
        "fstpl (%2)\n"
        "andl $0xFFFFFFF0, %0\n"
        "fldl 8(%2)\n"
        "xorl $0x0F0F0F0F, %0\n"
        "fstpl 8(%2)\n"
        "testl %0, %0\n"
        : "+r"(r) : "r"(d) : "memory", "cc");
    return r;
}

/* 64-bit forms: andq with sign-extended imm32, addq, orq [m64],r64. */
static uint64_t alu64_forms(uint64_t x, uint64_t *m, double *d) {
    uint64_t r = x;
    __asm__ volatile(
        "fldl (%3)\n"
        "andq $-16, %0\n"
        "fchs\n"
        "addq $5, %0\n"
        "orq %0, (%2)\n"
        "fstpl (%3)\n"
        "testq %0, %0\n"
        : "+r"(r) : "r"(m), "r"(d) : "memory", "cc");
    return r;
}

/* Memory-RMW eviction: the or [m],r between two flds of the same location
 * must invalidate the mem-CSE entry — the second fld reads the updated bits. */
static double rmw_evicts_cse(void) {
    uint32_t m = 0x3F800000;  /* 1.0f */
    double out;
    __asm__ volatile(
        "movl $0x00400000, %%ecx\n"
        "flds %1\n"            /* 1.0f — cached */
        "orl %%ecx, %1\n"      /* m becomes 0x3FC00000 = 1.5f */
        "flds %1\n"            /* must reload: 1.5f */
        "faddp\n"              /* 1.0 + 1.5 */
        "fstpl %0\n"
        "testl %%ecx, %%ecx\n"
        : "=m"(out), "+m"(m) :: "ecx", "cc");
    return out;
}

/* All five RMW ops on one word, mid-run. */
static uint32_t rmw_all_ops(double *d) {
    uint32_t m = 100;
    __asm__ volatile(
        "movl $7, %%ecx\n"
        "fldl (%1)\n"
        "addl %%ecx, %0\n"     /* 107 */
        "fabs\n"
        "subl %%ecx, %0\n"     /* 100 */
        "fchs\n"
        "orl %%ecx, %0\n"      /* 103 */
        "fabs\n"
        "andl %%ecx, %0\n"     /* 7 */
        "fchs\n"
        "xorl %%ecx, %0\n"     /* 0 */
        "fstpl (%1)\n"
        "testl %%ecx, %%ecx\n"
        : "+m"(m) : "r"(d) : "ecx", "cc", "memory");
    return m;
}

/* Flags LIVE: shr's CF (last bit shifted out) read by setc — must decline
 * and materialize CF=1. */
static uint32_t flags_live_shr_carry(double *a) {
    uint32_t r;
    __asm__ volatile(
        "movl $5, %%eax\n"
        "testl %%eax, %%eax\n"  /* CF=0 beforehand */
        "fldl (%1)\n"
        "shrl $1, %%eax\n"      /* eax=2, CF=1 (bit 0 out) — read below */
        "fchs\n"
        "fstpl (%1)\n"
        "setc %%al\n"
        "movzbl %%al, %%eax\n"
        "movl %%eax, %0\n"
        : "=r"(r) : "r"(a) : "eax", "memory", "cc");
    return r;  /* 1 iff the shr's CF survived */
}

/* Non-encodable logical immediate: declined (run splits), semantics hold. */
static uint32_t nonencodable_and(uint32_t x, double *a) {
    uint32_t r = x;
    __asm__ volatile(
        "fldl (%2)\n"
        "andl $0x12345678, %0\n"
        "fchs\n"
        "fstpl (%2)\n"
        "testl %0, %0\n"
        : "+r"(r) : "r"(a) : "memory", "cc");
    return r;
}

/* ── Stage 3: unary ALU forms (inc/dec/neg r; not r on the INT tier) ──────── */

/* inc/dec/neg/not chained mid-run; flags die at the trailing test.
 * Net effect: inc,dec,neg,not,inc == identity (~(-x) = x-1). */
static uint32_t unary_chain(uint32_t x, double *d) {
    uint32_t r = x;
    __asm__ volatile(
        "fldl (%2)\n"
        "incl %0\n"
        "fabs\n"
        "decl %0\n"
        "fchs\n"
        "negl %0\n"
        "fldl 8(%2)\n"
        "notl %0\n"
        "faddp\n"
        "incl %0\n"
        "fstpl (%2)\n"
        "testl %0, %0\n"
        : "+r"(r) : "r"(d) : "memory", "cc");
    return r;
}

/* inc consumed WITH CF live across it (the per-form gate: inc preserves CF,
 * so only OF/SF/ZF/AF/PF need be dead — they die at the trailing test).
 * The setc reads the PRE-inc CF from the cmp. */
static uint32_t inc_preserves_cf(uint32_t x, double *d) {
    uint32_t cnt = 7, out;
    __asm__ volatile(
        "cmpl $1, %2\n"        /* CF = (x < 1) */
        "fldl (%3)\n"
        "incl %1\n"            /* consumable: CF flows through */
        "fchs\n"
        "fstpl (%3)\n"
        "setc %%al\n"          /* reads the cmp's CF */
        "movzbl %%al, %0\n"
        "testl %1, %1\n"       /* full definer: kills ret's all-live seed */
        : "=r"(out), "+r"(cnt) : "r"(x), "r"(d) : "eax", "memory", "cc");
    return out | (cnt << 8);
}

/* Flags LIVE: setz reads neg's ZF — must decline and materialize ZF=1. */
static uint32_t flags_live_neg(double *a) {
    uint32_t r;
    __asm__ volatile(
        "movl $0, %%eax\n"
        "fldl (%1)\n"
        "negl %%eax\n"         /* ZF=1 (neg of 0) — read below, NOT dead */
        "fchs\n"
        "fstpl (%1)\n"
        "setz %%al\n"
        "movzbl %%al, %0\n"
        : "=r"(r) : "r"(a) : "eax", "memory", "cc");
    return r;  /* 1 iff the neg's ZF survived */
}

/* Memory-destination inc: declined (stays bridged/native), semantics hold. */
static uint32_t inc_mem_declines(double *a) {
    uint32_t m = 41;
    __asm__ volatile(
        "fldl (%1)\n"
        "incl %0\n"            /* mem-dest — not consumable */
        "fchs\n"
        "fstpl (%1)\n"
        "testl $1, %0\n"
        : "+m"(m) : "r"(a) : "memory", "cc");
    return m;
}

int main(void) {
    float v[4] = {2.0f, 3.0f, 4.0f, 55.5f};
    uint32_t z = 0x12345678;
    wow_scale_shape(1.5f, v, &z);
    check_f("wow-shape: v[0] = 2*1.5", v[0], 3.0f);
    check_f("wow-shape: v[1] = 3*1.5", v[1], 4.5f);
    check_f("wow-shape: v[2] = 4*1.5", v[2], 6.0f);
    check_f("wow-shape: v[3] zero-stored via eax", v[3], 0.0f);
    check_u("wow-shape: eax zeroed", z, 0);

    double d[2] = {1.25, 2.5};
    check_u("xor rax,rax mid-run", zero64_mid_run(d), 0);
    check_u("  (fp result intact)", d[0] == 3.75, 1);

    double s = 7.0;
    check_u("flags live: setz observes xor's ZF=1", flags_live_setz(&s), 1);
    check_u("  (fchs applied)", s == -7.0, 1);

    double c = -3.0;
    check_u("flags live: jc observes xor's CF=0", flags_live_carry(&c), 1);
    check_u("  (fabs applied)", c == 3.0, 1);

    check_u("fcomi/xor/fcmovb: xor's CF=0 wins", fcomi_xor_fcmov(1.0, 9.0) == 1.0, 1);

    /* ── Stage 2 ── */
    const float sv[3] = {-1.0f, 2.0f, -3.0f};
    /* signs of -0.5, 2.5, -2.5: bit0=1, bit1=0, bit2=1 → 5 */
    check_u("sign-pack shape (shr/and/or-RMW)", sign_pack_shape(sv, 0.5f), 5);

    {
        uint32_t e = 1000;
        e = e + (uint32_t)-7;       /* addl $-7 */
        e = e - 0x12345;            /* subl (temp-GPR path) */
        e = e << 4;                 /* shll $4 */
        e = (uint32_t)((int32_t)e >> 2);  /* sarl $2 */
        e = e >> (33 & 31);         /* shrl $33 — count masked to 1 */
        e = e & 0xFFFFFFF0u;        /* andl (bitmask imm) */
        e = e ^ 0x0F0F0F0Fu;        /* xorl (bitmask imm) */
        double dd[2] = {2.0, 3.0};
        check_u("reg-imm ALU chain mid-run", alu_imm_chain(1000, dd), e);
        /* |2.0| → fchs → -2.0; -2.0 + 3.0 = 1.0 */
        check_u("  (fp results intact)", dd[0] == 1.0 && dd[1] == 3.0, 1);
    }

    {
        uint64_t m = 0x100;
        double dv = 4.0;
        const uint64_t e = (0xDEADBEEF12345677ULL & ~15ULL) + 5;
        check_u("64-bit and/add + orq [m64],r64",
                alu64_forms(0xDEADBEEF12345677ULL, &m, &dv), e);
        check_u("  (m64 or'd)", m, 0x100 | e);
        check_u("  (fchs applied)", dv == -4.0, 1);
    }

    check_u("or [m],r evicts mem-CSE (1.0 -> 1.5 reload)",
            rmw_evicts_cse() == 2.5, 1);

    {
        double dv = -6.0;
        check_u("rmw add/sub/or/and/xor [m32],r", rmw_all_ops(&dv), 0);
        check_u("  (fabs/fchs net applied)", dv == -6.0, 1);
    }

    {
        double dv = 2.0;
        check_u("flags live: setc observes shr's CF=1", flags_live_shr_carry(&dv), 1);
        check_u("  (fchs applied)", dv == -2.0, 1);
    }

    {
        double dv = 8.0;
        check_u("non-encodable and imm declines, semantics hold",
                nonencodable_and(0xFFFFFFFFu, &dv), 0x12345678u);
        check_u("  (fchs applied)", dv == -8.0, 1);
    }

    /* ── Stage 3 ── */
    {
        double dd[2] = {2.0, 3.0};
        check_u("unary chain inc/dec/neg/not mid-run", unary_chain(12345, dd), 12345);
        /* |2.0| → fchs → -2.0; -2.0 + 3.0 = 1.0 */
        check_u("  (fp results intact)", dd[0] == 1.0 && dd[1] == 3.0, 1);
    }
    {
        double dv = 5.0;
        check_u("inc consumed with CF live (borrow)", inc_preserves_cf(0, &dv), 0x801);
        check_u("inc consumed with CF live (no borrow)", inc_preserves_cf(5, &dv), 0x800);
    }
    {
        double dv = 9.0;
        check_u("flags live: setz observes neg's ZF=1", flags_live_neg(&dv), 1);
        check_u("  (fchs applied)", dv == -9.0, 1);
    }
    {
        double dv = 1.0;
        check_u("inc [m] declines, semantics hold", inc_mem_declines(&dv), 42);
        check_u("  (fchs applied)", dv == -1.0, 1);
    }

    if (failures == 0)
        printf("ALL TESTS PASSED (33 tests)\n");
    else
        printf("%d TESTS FAILED\n", failures);
    return failures != 0;
}
