/*
 * bench_fusion_arithp_fstp.c -- Benchmark for arithp_fstp fusion.
 * Pattern: ARITHp ST(1) + FSTP mem.
 *
 * The fusion fires when the arithp is NOT preceded by an FLD (otherwise
 * fld_arithp catches it first).  Real-world scenarios: values already on
 * the x87 stack from prior non-popping arithmetic, then the final
 * arithp+fstp stores the result.
 *
 * Modelled after patterns like:
 *   fld [a]  →  fmul [b]  →  faddp  →  fstp [out]    (multiply-accumulate)
 *   fld [x]  →  fmul [y]  →  fld [z]  →  fmul [w]  →  faddp  →  fstp [out]  (dot2)
 *   four-component dot product (dot4)
 *   distance²  =  dx*dx + dy*dy + dz*dz
 *
 * NOTE: GAS AT&T: fsubp=Intel FSUBRP, fdivp=Intel FDIVRP
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIMES 1000000
#define RUNS  5

/*
 * Multiply-accumulate:  result = ST(0) * [b] + [c]
 *
 * x87 sequence: fld [a] | fmul [b] | fld [c] | faddp | fstp [out]
 *
 * fld+fmul is caught by fld_arithp.
 * fld [c] is standalone (no fusion partner).
 * faddp+fstp is our target fusion.
 */
static clock_t bench_madd(void) {
    clock_t start = clock();
    volatile double a = 3.0, b = 4.0, c = 5.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl  %1\n\t"       /* ST(0)=a */
            "fmull %2\n\t"       /* ST(0)=a*b       (non-popping mem arith) */
            "fldl  %3\n\t"       /* ST(0)=c, ST(1)=a*b */
            "faddp\n\t"          /* ST(0)=c+(a*b)=17  ← arithp */
            "fstpl %0\n"         /*                    ← fstp   */
            : "=m"(r) : "m"(a), "m"(b), "m"(c));
    return clock() - start;
}

/*
 * 2D dot product:  out = x0*y0 + x1*y1
 *
 * x87 sequence: fld [x0] | fmul [y0] | fld [x1] | fmul [y1] | faddp | fstp [out]
 *
 * Both fld+fmul pairs are caught by fld_arithp.
 * faddp+fstp is our target.
 */
static clock_t bench_dot2(void) {
    clock_t start = clock();
    volatile double x0 = 1.0, y0 = 2.0, x1 = 3.0, y1 = 4.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl  %1\n\t"       /* ST(0) = x0 */
            "fmull %2\n\t"       /* ST(0) = x0*y0 */
            "fldl  %3\n\t"       /* ST(0) = x1, ST(1) = x0*y0 */
            "fmull %4\n\t"       /* ST(0) = x1*y1, ST(1) = x0*y0 */
            "faddp\n\t"          /* ST(0) = x0*y0 + x1*y1 */
            "fstpl %0\n"
            : "=m"(r) : "m"(x0), "m"(y0), "m"(x1), "m"(y1));
    return clock() - start;
}

/*
 * 3D dot product:  out = x0*y0 + x1*y1 + x2*y2
 *
 * Common pattern in game engines for lighting/collision.
 * The final faddp+fstp stores the scalar result.
 */
static clock_t bench_dot3(void) {
    clock_t start = clock();
    volatile double x0 = 1.0, y0 = 2.0;
    volatile double x1 = 3.0, y1 = 4.0;
    volatile double x2 = 5.0, y2 = 6.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl  %1\n\t"       /* x0 */
            "fmull %2\n\t"       /* x0*y0 */
            "fldl  %3\n\t"       /* x1 */
            "fmull %4\n\t"       /* x1*y1 */
            "faddp\n\t"          /* x0*y0 + x1*y1 */
            "fldl  %5\n\t"       /* x2 */
            "fmull %6\n\t"       /* x2*y2 */
            "faddp\n\t"          /* x0*y0 + x1*y1 + x2*y2 */
            "fstpl %0\n"
            : "=m"(r) : "m"(x0), "m"(y0), "m"(x1), "m"(y1), "m"(x2), "m"(y2));
    return clock() - start;
}

/*
 * Distance² = dx*dx + dy*dy + dz*dz  (using fld+fmul ST(0),ST(0) pattern)
 *
 * Typical in game AI / collision detection.
 */
static clock_t bench_distsq(void) {
    clock_t start = clock();
    volatile double dx = 3.0, dy = 4.0, dz = 5.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl  %1\n\t"       /* ST(0) = dx */
            "fmul  %%st(0)\n\t"  /* ST(0) = dx*dx */
            "fldl  %2\n\t"       /* ST(0) = dy */
            "fmul  %%st(0)\n\t"  /* ST(0) = dy*dy */
            "faddp\n\t"          /* ST(0) = dx²+dy² */
            "fldl  %3\n\t"       /* ST(0) = dz */
            "fmul  %%st(0)\n\t"  /* ST(0) = dz*dz */
            "faddp\n\t"          /* ST(0) = dx²+dy²+dz² */
            "fstpl %0\n"
            : "=m"(r) : "m"(dx), "m"(dy), "m"(dz));
    return clock() - start;
}

/*
 * 4D dot product:  out = x0*y0 + x1*y1 + x2*y2 + x3*y3
 *
 * Two intermediate faddp (not followed by fstp) plus final faddp+fstp.
 * Tests repeated arithp_fstp at the tail of a long accumulation chain.
 */
static clock_t bench_dot4(void) {
    clock_t start = clock();
    volatile double x0 = 1.0, y0 = 2.0;
    volatile double x1 = 3.0, y1 = 4.0;
    volatile double x2 = 5.0, y2 = 6.0;
    volatile double x3 = 7.0, y3 = 8.0;
    volatile double r;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            "fldl  %1\n\t"
            "fmull %2\n\t"
            "fldl  %3\n\t"
            "fmull %4\n\t"
            "faddp\n\t"
            "fldl  %5\n\t"
            "fmull %6\n\t"
            "faddp\n\t"
            "fldl  %7\n\t"
            "fmull %8\n\t"
            "faddp\n\t"
            "fstpl %0\n"
            : "=m"(r)
            : "m"(x0), "m"(y0), "m"(x1), "m"(y1),
              "m"(x2), "m"(y2), "m"(x3), "m"(y3));
    return clock() - start;
}

/*
 * Multiple dot3 outputs (batch of 3 dot products).
 * Exercises arithp_fstp across a long x87 run boundary.
 */
static clock_t bench_dot3_x3(void) {
    clock_t start = clock();
    volatile double a = 1.0, b = 2.0, c = 3.0;
    volatile double d = 4.0, e = 5.0, f = 6.0;
    volatile double r0, r1, r2;
    for (int i = 0; i < TIMES; i++)
        __asm__ volatile (
            /* dot3 #1 */
            "fldl %3\n\t"  "fmull %4\n\t"
            "fldl %5\n\t"  "fmull %6\n\t"  "faddp\n\t"
            "fldl %7\n\t"  "fmull %8\n\t"  "faddp\n\t"
            "fstpl %0\n\t"
            /* dot3 #2 */
            "fldl %4\n\t"  "fmull %3\n\t"
            "fldl %6\n\t"  "fmull %5\n\t"  "faddp\n\t"
            "fldl %8\n\t"  "fmull %7\n\t"  "faddp\n\t"
            "fstpl %1\n\t"
            /* dot3 #3 */
            "fldl %3\n\t"  "fmull %5\n\t"
            "fldl %4\n\t"  "fmull %6\n\t"  "faddp\n\t"
            "fldl %7\n\t"  "fmull %8\n\t"  "faddp\n\t"
            "fstpl %2\n"
            : "=m"(r0), "=m"(r1), "=m"(r2)
            : "m"(a), "m"(b), "m"(c), "m"(d), "m"(e), "m"(f));
    return clock() - start;
}

int main(void) {
    struct { const char *name; clock_t (*fn)(void); } benches[] = {
        {"madd",     bench_madd},
        {"dot2",     bench_dot2},
        {"dot3",     bench_dot3},
        {"distsq",   bench_distsq},
        {"dot4",     bench_dot4},
        {"dot3_x3",  bench_dot3_x3},
    };
    int n = (int)(sizeof(benches) / sizeof(benches[0]));
    for (int i = 0; i < n; i++) {
        clock_t sum = 0;
        for (int r = 0; r < RUNS; r++) sum += benches[i].fn();
        printf("BENCH %s %lu\n", benches[i].name, (unsigned long)(sum / RUNS));
    }
    return 0;
}
