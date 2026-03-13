#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TIMES 1000000
#define RUNS 10

typedef void (*BenchFunc)(clock_t *out_ticks, float *out_result);

typedef struct {
	const char *name;
	BenchFunc func;
	const char *expected;
	unsigned int weight; /* count from MMO x87 x87 profile (of ~75717 total) */
} Benchmark;

/* Format a float using pure integer arithmetic on IEEE 754 bits.
   Avoids all FP operations — necessary because -mno-sse -O2 breaks
   float arithmetic outside inline asm, and printf %f uses xmm regs. */
static void fmt_float(char *buf, int buflen, const float *valp) {
	uint32_t bits;
	__builtin_memcpy(&bits, valp, 4);

	int sign = (bits >> 31) & 1;
	int exp = (int)((bits >> 23) & 0xFF);
	uint32_t mant = bits & 0x7FFFFF;

	if (exp == 0 && mant == 0) {
		snprintf(buf, buflen, sign ? "-0.0000" : "0.0000");
		return;
	}

	if (exp > 0)
		mant |= 0x800000; /* implicit leading 1 */
	else
		exp = 1; /* denormalized */

	/* val = mant * 2^(exp - 150), we want val * 10000 as integer */
	uint64_t product = (uint64_t)mant * 10000;
	int shift = 150 - exp;
	unsigned long scaled;

	if (shift > 0 && shift <= 63)
		scaled = (unsigned long)((product + (1ULL << (shift - 1))) >> shift);
	else if (shift <= 0)
		scaled = (unsigned long)(product << (-shift));
	else
		scaled = 0;

	unsigned long ipart = scaled / 10000;
	unsigned long fpart = scaled % 10000;

	if (sign)
		snprintf(buf, buflen, "-%lu.%04lu", ipart, fpart);
	else
		snprintf(buf, buflen, "%lu.%04lu", ipart, fpart);
}

/* Format ticks as human-readable: "12.8k", "179.4k", "1.2M" etc. */
static void fmt_ticks(char *buf, int buflen, unsigned long ticks) {
	if (ticks >= 1000000)
		snprintf(buf, buflen, "%lu.%luM", ticks / 1000000, (ticks % 1000000) / 100000);
	else if (ticks >= 1000)
		snprintf(buf, buflen, "%lu.%luk", ticks / 1000, (ticks % 1000) / 100);
	else
		snprintf(buf, buflen, "%lu", ticks);
}

/*
 * Benchmarks weighted by MMO x87 x87 instruction frequency.
 * Weight = raw instruction count from disassembly (~75,717 total x87 ops).
 * wt% = weight / 75717 * 100, displayed in table.
 *
 * All benchmarks use inline asm to directly emit x87 instructions.
 * Variables are volatile so -O2 can't elide the memory operands.
 */

/* ================================================================
 *  f32 memory arithmetic: flds/fstps/fadds/fsubs/fmuls/fdivs/etc
 * ================================================================ */

void run_fld_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fst_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsts %0\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fmul_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fmuls %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fadd_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fadds %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsub_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 5.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsubs %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdiv_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fdivs %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdivr_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 2.0f, b = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fdivrs %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsubr_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 2.0f, b = 5.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsubrs %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcom_f32(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, b = 2.0f, r;
	unsigned short sw;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"fcomps %3\n\t"
			"fnstsw %%ax\n\t"
			"flds %2\n\t"
			"fstps %0"
			: "=m"(r), "=a"(sw) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  f64 memory arithmetic: fldl/fstpl/faddl/fsubl/fmull/fdivl/etc
 * ================================================================ */

void run_fld_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 1.5;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fmul_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 3.0, b = 2.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fmull %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fadd_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 1.0, b = 2.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"faddl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsub_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 5.0, b = 2.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fsubl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdiv_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 1.0, b = 2.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fdivl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdivr_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 2.0, b = 1.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fdivrl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsubr_f64(clock_t *out_ticks, float *out_result) {
	volatile double a = 2.0, b = 5.0;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldl %1\n\t"
			"fsubrl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcom_f64(clock_t *out_ticks, float *out_result) {
	volatile double b = 2.0;
	volatile float a = 3.0f, r;
	unsigned short sw;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"fcompl %3\n\t"
			"fnstsw %%ax\n\t"
			"flds %2\n\t"
			"fstps %0"
			: "=m"(r), "=a"(sw) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  f80 memory ops: fldt/fstpt
 * ================================================================ */

void run_fld_f80(clock_t *out_ticks, float *out_result) {
	/* 10-byte extended precision for 1.5: sign=0, exp=0x3FFF, mant=0xC000000000000000 */
	volatile uint8_t f80[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xFF, 0x3F};
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldt %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(f80)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fst_f80(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.5f, r;
	volatile uint8_t f80[10];
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fstpt %0"
			: "=m"(f80) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	/* re-load f80 to get float result */
	__asm__ volatile ("fldt %1\n\t" "fstps %0" : "=m"(r) : "m"(f80));
	*out_result = r;
}

/* ================================================================
 *  Register-register ops: faddp/fmulp/fsubp/fdivp/fxch/etc
 * ================================================================ */

/* Register-popping arithmetic in the MMO binary is 63% preceded by fmul mem,
   forming the multiply-accumulate chain: fld → fmul mem → f*p → fstp.
   Benchmarks use that pattern instead of fld → fld → f*p → fstp. */

void run_fadd_st(clock_t *out_ticks, float *out_result) {
	volatile float seed = 1.0f, a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"faddp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fmul_st(clock_t *out_ticks, float *out_result) {
	volatile float seed = 3.0f, a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"fmulp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsub_st(clock_t *out_ticks, float *out_result) {
	/* AT&T fsubp: ST(0)-ST(1) → ST(1), pop. So a*b - seed. */
	volatile float seed = -1.0f, a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"fsubp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsubr_st(clock_t *out_ticks, float *out_result) {
	/* AT&T fsubrp: ST(1)-ST(0) → ST(1), pop. So seed - a*b. */
	volatile float seed = 8.0f, a = 1.0f, b = 5.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"fsubrp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdiv_st(clock_t *out_ticks, float *out_result) {
	/* AT&T fdivp: ST(0)/ST(1) → ST(1), pop. So a*b / seed. */
	volatile float seed = 4.0f, a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"fdivp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fdivr_st(clock_t *out_ticks, float *out_result) {
	/* AT&T fdivrp: ST(1)/ST(0) → ST(1), pop. So seed / (a*b). */
	volatile float seed = 1.0f, a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fmuls %3\n\t"
			"fdivrp\n\t"
			"fstps %0"
			: "=m"(r) : "m"(seed), "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcom_st(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, b = 2.0f, r;
	unsigned short sw;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"flds %3\n\t"
			"fcomp %%st(1)\n\t"
			"fnstsw %%ax\n\t"
			"fstps %0"
			: "=m"(r), "=a"(sw) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcompp(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, b = 2.0f, r;
	unsigned short sw;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"flds %2\n\t"
			"flds %3\n\t"
			"fcompp\n\t"
			"fnstsw %%ax\n\t"
			"fstps %0"
			: "=m"(r), "=a"(sw) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fucom(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, b = 2.0f, r;
	unsigned short sw;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"flds %3\n\t"
			"fucompp\n\t"
			"fnstsw %%ax\n\t"
			"flds %2\n\t"
			"fstps %0"
			: "=m"(r), "=a"(sw) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fld_sti(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fld %%st(0)\n\t"
			"fstp %%st(1)\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fst_sti(clock_t *out_ticks, float *out_result) {
	volatile float a = 2.5f, b = 0.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"flds %1\n\t"
			"fstp %%st(1)\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fxch(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fxch\n\t"
			"fstps %0\n\t"
			"fstp %%st(0)"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_ffree(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %1\n\t"
			"ffree %%st(1)\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcmov(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, b = 2.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"clc\n\t"
			"fcmovnb %%st(1), %%st(0)\n\t"
			"fstps %0\n\t"
			"fstp %%st(0)"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  Integer memory ops: fild/fist/fisttp
 * ================================================================ */

void run_fild(clock_t *out_ticks, float *out_result) {
	volatile int32_t a = 42;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fildl %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fist(clock_t *out_ticks, float *out_result) {
	/* In the MMO binary, 79% of fistp is preceded by fsub (floor/truncate idiom) */
	volatile float a = 45.0f, b = 3.0f;
	volatile int32_t r32;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsubs %2\n\t"
			"fistpl %0"
			: "=m"(r32) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	__asm__ volatile ("fildl %1\n\t" "fstps %0" : "=m"(r) : "m"(r32));
	*out_result = r;
}

void run_fisttp(clock_t *out_ticks, float *out_result) {
	volatile float a = 42.7f;
	volatile int32_t r32;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fisttpl %0"
			: "=m"(r32) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	__asm__ volatile ("fildl %1\n\t" "fstps %0" : "=m"(r) : "m"(r32));
	*out_result = r;
}

void run_fiadd(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f;
	volatile int32_t b = 2;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fiaddl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fimul(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f;
	volatile int32_t b = 2;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fimull %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fidiv(clock_t *out_ticks, float *out_result) {
	volatile float a = 6.0f;
	volatile int32_t b = 2;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fidivl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fisub(clock_t *out_ticks, float *out_result) {
	volatile float a = 5.0f;
	volatile int32_t b = 2;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fisubl %2\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_ficom(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f;
	volatile int32_t b = 2;
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"ficompl %2\n\t"
			"flds %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  Unary / constant loads
 * ================================================================ */

void run_fsqrt(clock_t *out_ticks, float *out_result) {
	volatile float a = 4.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsqrt\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fchs(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fchs\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fabs(clock_t *out_ticks, float *out_result) {
	volatile float a = -3.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fabs\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fld_const(clock_t *out_ticks, float *out_result) {
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fldz\n\t"
			"fstps %0"
			: "=m"(r)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_ftst(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"ftst\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fxam(clock_t *out_ticks, float *out_result) {
	volatile float a = 3.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fxam\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  Transcendental (rare in the MMO binary but present)
 * ================================================================ */

void run_fsincos(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsincos\n\t"
			"fstps %0\n\t"
			"fstp %%st(0)"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fsin(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fsin\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fcos(clock_t *out_ticks, float *out_result) {
	volatile float a = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fcos\n\t"
			"fstps %0"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fpatan(clock_t *out_ticks, float *out_result) {
	volatile float y = 1.0f, x = 1.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fpatan\n\t"
			"fstps %0"
			: "=m"(r) : "m"(y), "m"(x)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fptan(clock_t *out_ticks, float *out_result) {
	volatile float a = 0.5f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"fptan\n\t"
			"fstps %0\n\t"
			"fstp %%st(0)"
			: "=m"(r) : "m"(a)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fyl2x(clock_t *out_ticks, float *out_result) {
	volatile float y = 1.0f, x = 8.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %1\n\t"
			"flds %2\n\t"
			"fyl2x\n\t"
			"fstps %0"
			: "=m"(r) : "m"(y), "m"(x)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

void run_fprem(clock_t *out_ticks, float *out_result) {
	volatile float a = 7.0f, b = 3.0f, r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"flds %2\n\t"
			"flds %1\n\t"
			"fprem\n\t"
			"fstps %0\n\t"
			"fstp %%st(0)"
			: "=m"(r) : "m"(a), "m"(b)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  BCD (fbld/fbstp)
 * ================================================================ */

void run_fbld(clock_t *out_ticks, float *out_result) {
	/* BCD encoding of 42: packed BCD in 10 bytes */
	volatile uint8_t bcd[10] = {0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	volatile float r;
	clock_t start = clock();
	for (int i = 0; i < TIMES; i++) {
		__asm__ volatile (
			"fbld %1\n\t"
			"fstps %0"
			: "=m"(r) : "m"(bcd)
		);
	}
	*out_ticks = clock() - start;
	*out_result = r;
}

/* ================================================================
 *  Bench harness
 * ================================================================ */

void bench(BenchFunc func, clock_t *out_avg, float *out_result) {
	clock_t warmup_t;
	float warmup_r;
	func(&warmup_t, &warmup_r);

	clock_t sum = 0;
	float result = 0.0f;
	for (int i = 0; i < RUNS; i++) {
		clock_t t;
		float r;
		func(&t, &r);
		sum += t;
		result = r;
	}
	*out_avg = sum / RUNS;
	*out_result = result;
}

int main() {
	/*
	 * Weight = raw instruction count from MMO x87 disassembly.
	 * Total x87 ops: 76,844 (excluding fnstsw/fldcw/fnstcw/frstor/fnsave/etc).
	 * Sorted by weight descending.
	 */
	Benchmark benchmarks[] = {
		{"flds",       run_fld_f32,    "1.5000", 35027},  /* fld f32(19155) + fstp f32(15872) — same fld→fstp chain */
		{"fmuls",      run_fmul_f32,   "6.0000", 10121},  /* fmul f32 */
		{"faddp",      run_fadd_st,    "3.0000",  3250},  /* faddp(2343) + fadd reg(907) */
		{"fsubs",      run_fsub_f32,   "3.0000",  2695},  /* fsub f32 */
		{"fadds",      run_fadd_f32,   "3.0000",  2350},  /* fadd f32 */
		{"fcomps",     run_fcom_f32,   "3.0000",  2303},  /* fcomps(1975) + fcoms(328) */
		{"fstp STi",   run_fst_sti,    "2.5000",  2281},  /* fstp to register */
		{"fmulp",      run_fmul_st,    "6.0000",  2006},  /* fmul reg(1847) + fmulp(159) */
		{"fld STi",    run_fld_sti,    "1.5000",  1911},  /* fld from register */
		{"fldl",       run_fld_f64,    "1.5000",  1843},  /* fld f64(471) + fstp f64(1372) — same fld→fstp chain */
		{"fild",       run_fild,      "42.0000",  1298},  /* fildl(745) + fildll(545) + filds(8) */
		{"fdivs",      run_fdiv_f32,   "0.5000",  1089},  /* fdiv f32 */
		{"fchs",       run_fchs,      "-3.5000",   774},  /* fchs */
		{"fxch",       run_fxch,       "1.0000",   734},  /* fxch */
		{"fsts",       run_fst_f32,    "1.5000",   698},  /* fst f32 non-popping */
		{"fld const",  run_fld_const,  "0.0000",   646},  /* fldz(486)+fld1(147)+fldlg2+fldl2e+fldln2+fldpi */
		{"fsubrp",     run_fsubr_st,   "3.0000",   474},  /* fsubrp(419) + fsubr reg(55) */
		{"fabs",       run_fabs,       "3.5000",   463},  /* fabs */
		{"fsubp",      run_fsub_st,    "3.0000",   405},  /* fsub reg(384) + fsubp(21) */
		{"fdivrs",     run_fdivr_f32,  "0.5000",   303},  /* fdivr f32 */
		{"fsubrs",     run_fsubr_f32,  "3.0000",   258},  /* fsubr f32 */
		{"fsqrt",      run_fsqrt,      "2.0000",   272},  /* fsqrt */
		{"fmull",      run_fmul_f64,   "6.0000",   219},  /* fmul f64 */
		{"fcompp",     run_fcompp,     "3.0000",   188},  /* fcompp double-pop */
		{"fist",       run_fist,      "42.0000",   167},  /* fistpl(157) + fistpll(8) + fistl(2) */
		{"fcomp STi",  run_fcom_st,    "3.0000",   138},  /* fcomp reg(128) + fcom reg(10) */
		{"fstpt",      run_fst_f80,    "1.5000",   134},  /* fst f80 */
		{"fdivrp",     run_fdivr_st,   "0.5000",   101},  /* fdivrp(81) + fdivr reg(20) */
		{"fdivp",      run_fdiv_st,    "0.5000",    97},  /* fdiv reg(78) + fdivp(19) */
		{"fsubrl",     run_fsubr_f64,  "3.0000",    93},  /* fsubr f64 */
		{"fldt",       run_fld_f80,    "1.5000",    93},  /* fld f80 */
		{"fcompl",     run_fcom_f64,   "3.0000",    75},  /* fcompl(68) + fcoml(7) */
		{"fidiv",      run_fidiv,      "3.0000",    72},  /* fidivl(60) + fidivrs(7) + fidivrl(5) */
		{"fsincos",    run_fsincos,    "0.5403",    68},  /* fsincos */
		{"fsin",       run_fsin,       "0.8415",    52},  /* fsin */
		{"fpatan",     run_fpatan,     "0.7854",    41},  /* fpatan */
		{"fcos",       run_fcos,       "0.5403",    37},  /* fcos */
		{"faddl",      run_fadd_f64,   "3.0000",    37},  /* fadd f64 */
		{"fimul",      run_fimul,      "6.0000",    33},  /* fimull(32) + fimuls(1) */
		{"fsubl",      run_fsub_f64,   "3.0000",    27},  /* fsub f64 */
		{"fiadd",      run_fiadd,      "3.0000",    20},  /* fiaddl(17) + fiadds(3) */
		{"ffree",      run_ffree,      "1.0000",    13},  /* ffree */
		{"fdivrl",     run_fdivr_f64,  "0.5000",    12},  /* fdivr f64 */
		{"ficom",      run_ficom,      "3.0000",    10},  /* ficompl(6) + ficomps(3) + ficoml(1) */
		{"fisub",      run_fisub,      "3.0000",     9},  /* fisubl(5) + fisubrs(4) */
		{"fdivl",      run_fdiv_f64,   "0.5000",     9},  /* fdiv f64 */
		{"fisttp",     run_fisttp,    "42.0000",     9},  /* fisttpl(7) + fisttpll(2) */
		{"fprem",      run_fprem,      "1.0000",     9},  /* fprem(7) + fprem1(2) */
		{"fyl2x",      run_fyl2x,      "3.0000",     8},  /* fyl2x */
		{"fucom",      run_fucom,      "3.0000",     7},  /* fucompp(5) + fucomp(1) + fucompi(1) */
		{"ftst",       run_ftst,       "3.0000",     4},  /* ftst */
		{"fxam",       run_fxam,       "3.0000",     3},  /* fxam */
		{"fptan",      run_fptan,      "1.0000",     3},  /* fptan */
		{"fbld",       run_fbld,      "42.0000",     3},  /* fbld(2) + fbstp(1) */
		{"fcmov",      run_fcmov,      NULL,         2},  /* fcmovne(1) + fcmovnb(1); skip verify (clc emulation) */
	};

	int n = sizeof(benchmarks) / sizeof(benchmarks[0]);

	/* compute total weight for percentage display */
	unsigned long total_weight = 0;
	for (int i = 0; i < n; i++)
		total_weight += benchmarks[i].weight;

	printf("+------------+-------+--------+------------+------------+-----+\n");
	printf("| %-10s | %5s | %6s | %10s | %10s | %-3s |\n",
		"op", "wt(%)", "ticks", "expected", "actual", "ok?");
	printf("+------------+-------+--------+------------+------------+-----+\n");

	unsigned long total_ticks = 0;
	unsigned long long weighted_sum = 0;
	int pass = 0;

	for (int i = 0; i < n; i++) {
		clock_t avg;
		float result;
		bench(benchmarks[i].func, &avg, &result);

		char tick_str[16], res_str[32];
		fmt_ticks(tick_str, sizeof(tick_str), avg);
		fmt_float(res_str, sizeof(res_str), &result);

		const char *exp = benchmarks[i].expected;
		int ok = exp ? (strcmp(exp, res_str) == 0) : 1; /* NULL = skip verify */

		/* weight as percentage of total x87 ops: weight * 1000 / total_weight gives permille */
		unsigned long pct10 = (unsigned long)benchmarks[i].weight * 1000 / total_weight;
		printf("| %-10s | %2lu.%lu  | %6s | %10s | %10s | %-3s |\n",
			benchmarks[i].name,
			pct10 / 10, pct10 % 10,
			tick_str, exp ? exp : "---", res_str,
			ok ? "YES" : "NO");

		total_ticks += avg;
		weighted_sum += (unsigned long long)avg * benchmarks[i].weight;
		if (ok) pass++;
	}

	char total_str[16], weighted_str[16];
	unsigned long coverage = total_weight * 100 / 76844;
	fmt_ticks(total_str, sizeof(total_str), total_ticks);
	fmt_ticks(weighted_str, sizeof(weighted_str), (unsigned long)(weighted_sum / total_weight));

	printf("+------------+-------+--------+-------------------------------+-----+\n");
	printf("| RAW TOTAL  |       | %6s |            %2d/%d passed | %-3s |\n",
		total_str, pass, n, pass == n ? "YES" : "NO");
	printf("| WEIGHTED   | %3lu%%  | %6s |  MMO-avg per 1M x87 ops |     |\n",
		coverage, weighted_str);
	printf("+------------+-------+--------+-------------------------------+-----+\n");
	return 0;
}
