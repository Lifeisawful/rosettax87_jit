/*
 * test_fstp_fld.c — Tests for FSTP + FLD fusion (OPT-F11).
 *
 * Covers: FSTP mem + FLD mem, FSTP reg + FLD reg, FSTP reg + FLD mem,
 *         FSTP mem + FLD reg, FSTP mem + FLDZ/FLD1/FILD, consecutive
 *         FSTP+FLD pairs, stack depth preservation.
 *
 * Build: clang -arch x86_64 -O0 -g -o test_fstp_fld test_fstp_fld.c
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

/* ==== FSTP m64 + FLD m64 (different addresses) ==== */
static void fstp_fld_mem_mem(double *out_stored, double *out_top) {
    double src = 7.0;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 3.0 */
        "fstpl %0\n"           /* store 3.0 → out_stored, pop */
        "fldl %3\n"            /* push 7.0 → ST(0) */
        "fstpl %1\n"           /* store ST(0) to out_top */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){3.0}), "m"(src));
}

/* ==== FSTP m32 + FLD m64 (mixed sizes) ==== */
static void fstp_fld_m32_m64(float *out_f32, double *out_top) {
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 2.5 */
        "fstps %0\n"           /* store as f32 → out_f32, pop */
        "fldl %3\n"            /* push 9.0 → ST(0) */
        "fstpl %1\n"           /* store ST(0) */
        : "=m"(*out_f32), "=m"(*out_top)
        : "m"((double){2.5}), "m"((double){9.0}));
}

/* ==== FSTP m64 + FLD m32 (mixed sizes) ==== */
static void fstp_fld_m64_m32(double *out_stored, double *out_top) {
    float src_f32 = 4.5f;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 6.0 */
        "fstpl %0\n"           /* store 6.0 → out_stored, pop */
        "flds %3\n"            /* push 4.5 (from f32) → ST(0) */
        "fstpl %1\n"           /* store ST(0) as f64 */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){6.0}), "m"(src_f32));
}

/* ==== FSTP ST(1) + FLD m64 ==== */
static double fstp_fld_reg_mem(void) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = 10.0 */
        "fldl %2\n"            /* ST(0) = 20.0, ST(1) = 10.0 */
        "fstp %%st(1)\n"       /* ST(1) = 20.0, pop → ST(0) = 20.0 (was ST(1), now has 20.0) */
        "fldl %3\n"            /* push 30.0 → ST(0) = 30.0, ST(1) = 20.0 */
        "fstpl %0\n"           /* store 30.0 */
        "fstp %%st(0)\n"       /* discard */
        : "=m"(r)
        : "m"((double){10.0}), "m"((double){20.0}), "m"((double){30.0}));
    return r;
}

/* ==== FSTP m64 + FLD ST(0) (loads new top after pop) ==== */
static void fstp_fld_mem_reg(double *out_stored, double *out_top) {
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 100.0 */
        "fldl %3\n"            /* ST(0) = 200.0, ST(1) = 100.0 */
        "fstpl %0\n"           /* store 200.0, pop → ST(0) = 100.0 */
        "fld %%st(0)\n"        /* push copy of ST(0) → ST(0) = ST(1) = 100.0 */
        "fstpl %1\n"           /* store 100.0 */
        "fstp %%st(0)\n"       /* discard */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){100.0}), "m"((double){200.0}));
}

/* ==== FSTP ST(1) + FLD ST(1) (register-register) ==== */
static void fstp_fld_reg_reg(double *out0, double *out1) {
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 1.0 */
        "fldl %3\n"            /* ST(0) = 2.0, ST(1) = 1.0 */
        "fldl %4\n"            /* ST(0) = 3.0, ST(1) = 2.0, ST(2) = 1.0 */
        "fstp %%st(1)\n"       /* ST(1) = 3.0, pop → ST(0) = 3.0, ST(1) = 1.0 */
        "fld %%st(1)\n"        /* push ST(1) = 1.0 → ST(0) = 1.0, ST(1) = 3.0, ST(2) = 1.0 */
        "fstpl %0\n"           /* store 1.0 */
        "fstpl %1\n"           /* store 3.0 */
        "fstp %%st(0)\n"       /* discard 1.0 */
        : "=m"(*out0), "=m"(*out1)
        : "m"((double){1.0}), "m"((double){2.0}), "m"((double){3.0}));
}

/* ==== FSTP m64 + FLDZ ==== */
static void fstp_fldz(double *out_stored, double *out_top) {
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 42.0 */
        "fstpl %0\n"           /* store 42.0, pop */
        "fldz\n"               /* push 0.0 */
        "fstpl %1\n"           /* store 0.0 */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){42.0}));
}

/* ==== FSTP m64 + FLD1 ==== */
static void fstp_fld1(double *out_stored, double *out_top) {
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 42.0 */
        "fstpl %0\n"           /* store 42.0, pop */
        "fld1\n"               /* push 1.0 */
        "fstpl %1\n"           /* store 1.0 */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){42.0}));
}

/* ==== FSTP m64 + FILD m32 ==== */
static void fstp_fild(double *out_stored, double *out_top) {
    int32_t ival = 123;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 55.0 */
        "fstpl %0\n"           /* store 55.0, pop */
        "fildl %3\n"           /* push (double)123 = 123.0 */
        "fstpl %1\n"           /* store 123.0 */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){55.0}), "m"(ival));
}

/* ==== Consecutive FSTP+FLD pairs ==== */
static void fstp_fld_consecutive(double *out0, double *out1, double *out_final) {
    __asm__ volatile(
        "fldl %3\n"            /* ST(0) = 10.0 */
        "fstpl %0\n"           /* store 10.0, pop */
        "fldl %4\n"            /* push 20.0 */
        "fstpl %1\n"           /* store 20.0, pop */
        "fldl %5\n"            /* push 30.0 */
        "fstpl %2\n"           /* store 30.0 */
        : "=m"(*out0), "=m"(*out1), "=m"(*out_final)
        : "m"((double){10.0}), "m"((double){20.0}), "m"((double){30.0}));
}

/* ==== FSTP ST(0) + FLD m64 (FSTP ST(0) is discard, then reload) ==== */
static double fstp_st0_fld(void) {
    double r;
    __asm__ volatile(
        "fldl %1\n"            /* ST(0) = 5.0 */
        "fldl %2\n"            /* ST(0) = 8.0, ST(1) = 5.0 */
        "fstp %%st(0)\n"       /* discard 8.0 → ST(0) = 5.0 */
        "fldl %3\n"            /* push 99.0 → ST(0) = 99.0, ST(1) = 5.0 */
        "fstpl %0\n"           /* store 99.0 */
        "fstp %%st(0)\n"       /* discard 5.0 */
        : "=m"(r)
        : "m"((double){5.0}), "m"((double){8.0}), "m"((double){99.0}));
    return r;
}

/* ==== Stack depth preserved after FSTP+FLD fusion ==== */
static void fstp_fld_depth(double *out0, double *out1, double *out2) {
    __asm__ volatile(
        "fldl %3\n"            /* push 1.0: ST(0)=1 */
        "fldl %4\n"            /* push 2.0: ST(0)=2, ST(1)=1 */
        "fldl %5\n"            /* push 3.0: ST(0)=3, ST(1)=2, ST(2)=1 */
        "fstpl %0\n"           /* store 3.0, pop → ST(0)=2, ST(1)=1 */
        "fldl %6\n"            /* push 4.0 → ST(0)=4, ST(1)=2, ST(2)=1 */
        "fstpl %1\n"           /* store 4.0, pop → ST(0)=2, ST(1)=1 */
        "fstpl %2\n"           /* store 2.0, pop → ST(0)=1 */
        "fstp %%st(0)\n"       /* discard 1.0 */
        : "=m"(*out0), "=m"(*out1), "=m"(*out2)
        : "m"((double){1.0}), "m"((double){2.0}),
          "m"((double){3.0}), "m"((double){4.0}));
}

/* ==== FSTP m32 + FLD m32, same address (f32 truncation roundtrip) ==== */
static double fstp_fld_truncate_f32(void) {
    float tmp;
    double r;
    double val = 1.0 / 3.0;   /* not exactly representable in f32 */
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 1/3 (full double precision) */
        "fstps %1\n"           /* truncate to f32, store → tmp, pop */
        "flds %1\n"            /* reload truncated f32 → ST(0) */
        "fstpl %0\n"           /* store result as f64 */
        : "=m"(r), "=m"(tmp) : "m"(val));
    return r;
}

/* ==== FSTP m64 + FLD m64, same address (store-reload roundtrip) ==== */
static double fstp_fld_same_addr_f64(void) {
    double tmp;
    double r;
    double val = 42.5;
    __asm__ volatile(
        "fldl %2\n"            /* ST(0) = 42.5 */
        "fstpl %1\n"           /* store to tmp, pop */
        "fldl %1\n"            /* reload from same address */
        "fstpl %0\n"           /* store result */
        : "=m"(r), "=m"(tmp) : "m"(val));
    return r;
}

/* ==== FSTP m64 + FLD ST(1) (deeper reg source after pop) ==== */
static void fstp_fld_mem_deepreg(double *out_stored, double *out_top) {
    __asm__ volatile(
        "fldl %2\n"            /* push 10.0: ST(0)=10 */
        "fldl %3\n"            /* push 20.0: ST(0)=20, ST(1)=10 */
        "fldl %4\n"            /* push 30.0: ST(0)=30, ST(1)=20, ST(2)=10 */
        "fstpl %0\n"           /* store 30.0, pop → ST(0)=20, ST(1)=10 */
        "fld %%st(1)\n"        /* push ST(1)=10 → ST(0)=10, ST(1)=20, ST(2)=10 */
        "fstpl %1\n"           /* store 10.0 */
        "fstp %%st(0)\n"       /* discard 20 */
        "fstp %%st(0)\n"       /* discard 10 */
        : "=m"(*out_stored), "=m"(*out_top)
        : "m"((double){10.0}), "m"((double){20.0}), "m"((double){30.0}));
}

int main(void) {
    /* FSTP m64 + FLD m64 */
    {
        double stored, top;
        fstp_fld_mem_mem(&stored, &top);
        check("fstp_m64+fld_m64: stored value", stored, 3.0);
        check("fstp_m64+fld_m64: new ST(0)", top, 7.0);
    }

    /* FSTP m32 + FLD m64 */
    {
        float stored_f32;
        double top;
        fstp_fld_m32_m64(&stored_f32, &top);
        check("fstp_m32+fld_m64: stored value", (double)stored_f32, 2.5);
        check("fstp_m32+fld_m64: new ST(0)", top, 9.0);
    }

    /* FSTP m64 + FLD m32 */
    {
        double stored, top;
        fstp_fld_m64_m32(&stored, &top);
        check("fstp_m64+fld_m32: stored value", stored, 6.0);
        check("fstp_m64+fld_m32: new ST(0)", top, 4.5);
    }

    /* FSTP ST(1) + FLD m64 */
    check("fstp_reg+fld_mem: new ST(0)", fstp_fld_reg_mem(), 30.0);

    /* FSTP m64 + FLD ST(0) (register source) */
    {
        double stored, top;
        fstp_fld_mem_reg(&stored, &top);
        check("fstp_m64+fld_st0: stored value", stored, 200.0);
        check("fstp_m64+fld_st0: new ST(0)", top, 100.0);
    }

    /* FSTP ST(1) + FLD ST(1) (register-register) */
    {
        double a, b;
        fstp_fld_reg_reg(&a, &b);
        check("fstp_reg+fld_reg: popped value", a, 1.0);
        check("fstp_reg+fld_reg: remaining", b, 3.0);
    }

    /* FSTP m64 + FLDZ */
    {
        double stored, top;
        fstp_fldz(&stored, &top);
        check("fstp_m64+fldz: stored value", stored, 42.0);
        check("fstp_m64+fldz: new ST(0)", top, 0.0);
    }

    /* FSTP m64 + FLD1 */
    {
        double stored, top;
        fstp_fld1(&stored, &top);
        check("fstp_m64+fld1: stored value", stored, 42.0);
        check("fstp_m64+fld1: new ST(0)", top, 1.0);
    }

    /* FSTP m64 + FILD m32 */
    {
        double stored, top;
        fstp_fild(&stored, &top);
        check("fstp_m64+fild_m32: stored value", stored, 55.0);
        check("fstp_m64+fild_m32: new ST(0)", top, 123.0);
    }

    /* Consecutive FSTP+FLD pairs */
    {
        double a, b, c;
        fstp_fld_consecutive(&a, &b, &c);
        check("consecutive: first stored", a, 10.0);
        check("consecutive: second stored", b, 20.0);
        check("consecutive: final stored", c, 30.0);
    }

    /* FSTP ST(0) + FLD m64 */
    check("fstp_st0+fld_m64: new ST(0)", fstp_st0_fld(), 99.0);

    /* Stack depth preservation */
    {
        double a, b, c;
        fstp_fld_depth(&a, &b, &c);
        check("depth: first stored (3.0)", a, 3.0);
        check("depth: second stored (4.0)", b, 4.0);
        check("depth: remaining ST(0) (2.0)", c, 2.0);
    }

    /* FSTP m64 + FLD ST(1) (deeper register source) */
    {
        double stored, top;
        fstp_fld_mem_deepreg(&stored, &top);
        check("fstp_m64+fld_st1: stored value", stored, 30.0);
        check("fstp_m64+fld_st1: new ST(0)", top, 10.0);
    }

    /* FSTP m32 + FLD m32, same address (f32 truncation roundtrip) */
    check("truncate_f32: precision loss", fstp_fld_truncate_f32(), (double)(float)(1.0/3.0));

    /* FSTP m64 + FLD m64, same address (store-reload roundtrip) */
    check("same_addr_f64: roundtrip", fstp_fld_same_addr_f64(), 42.5);

    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
