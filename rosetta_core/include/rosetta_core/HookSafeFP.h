#pragma once

#include <cstdint>
#include <cstring>

// FP arithmetic that is safe to run inside the lazy-translation hook.
//
// The hook runs on the guest thread with live guest vector state in the host
// registers (guest XMM0-7 in q0-q7, cached XMM scalars in temporary FPRs
// v16+), so hook code must not let the compiler touch ANY v-register — the
// same invariant that forbids __builtin_popcount here, and the root cause of
// the const-promote FCVT corruption (research/const_promote_isinf_bug/).
// This helper takes and returns raw bit patterns in GPRs and does its float
// work inside a single asm block that saves/restores the exact v-registers
// it names, so surrounding code stays integer-only.
//
// Exact conversions (f32→f64 widening) don't belong here — implement those
// in pure integer arithmetic instead (see widen_f32_to_f64_bits in
// X87IRBuild.cpp). This is only for genuinely inexact FP work like the
// FAST_RECIP_DIV reciprocal, where integer soft-float would have to
// re-implement correctly rounded division.

// 1.0 / bits(d), result as raw f64 bits. Rounds with the FPCR in effect at
// translation time — acceptable for the opt-in fast-division fidelity trade
// (documented 1-ulp divergence from a true runtime FDIV).
inline uint64_t hook_safe_recip_bits(uint64_t bits) {
#if defined(__aarch64__)
    // Save/restore via a local buffer, not sp pushes — inline-asm sp
    // adjustment would overlap the Darwin arm64 red zone in leaf functions.
    alignas(16) uint8_t save[32];
    uint64_t out;
    asm volatile(
        "stp  q0, q1, [%2]\n\t"
        "fmov d0, %1\n\t"
        "fmov d1, #1.00000000\n\t"
        "fdiv d0, d1, d0\n\t"
        "fmov %0, d0\n\t"
        "ldp  q0, q1, [%2]\n\t"
        : "=r"(out)
        : "r"(bits), "r"(save)
        : "memory");
    return out;
#else
    double d, r;
    memcpy(&d, &bits, 8);
    r = 1.0 / d;
    uint64_t rb;
    memcpy(&rb, &r, 8);
    return rb;
#endif
}
