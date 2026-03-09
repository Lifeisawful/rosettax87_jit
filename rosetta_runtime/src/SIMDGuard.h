#pragma once

// most x87 instruction handlers only use d0-d3 registers, so backing all up is
// too much of a penalty. Only sin/cos/log2/exp require a full backup of the
// simd registers. Anything above d7 handled by the compiler. This assumption
// was made by staring at disassembled code.

#include <cstdint>

#define ENABLE_SIMD_GUARD

struct SIMDGuard {
    using SIMDRegister_t = uint8_t[8];

    SIMDGuard() {
#if defined(ENABLE_SIMD_GUARD)
        // Save q0–q3 in pairs into buf
        asm volatile(
            "stp  q0,  q1, [%0, # 0]\n\t"
            "stp  q2,  q3, [%0, #32]\n\t"
            :  // no outputs
            : "r"(buf)
            : "memory");
#endif
    }

    ~SIMDGuard() {
#if defined(ENABLE_SIMD_GUARD)
        // Restore q0–q3 in reverse order
        asm volatile(
            "ldp  q2,  q3, [%0, #32]\n\t"
            "ldp  q0,  q1, [%0, # 0]\n\t"
            :
            : "r"(buf)
            : "v0", "v1", "v2", "v3", "memory");
#endif
    }

    alignas(16) uint8_t buf[16][4];
};

struct SIMDGuardAndX0X7 {
    using SIMDRegister_t = uint8_t[8];

    SIMDGuardAndX0X7() {
#if defined(ENABLE_SIMD_GUARD)
        // Save q0–q3 in pairs into buf
        // Save x0–x7 in pairs into buf
        asm volatile(
            "stp  q0,  q1, [%0, #  0]\n\t"
            "stp  q2,  q3, [%0, # 32]\n\t"
            "stp  x0,  x1, [%0, # 64]\n\t"
            "stp  x2,  x3, [%0, # 80]\n\t"
            "stp  x4,  x5, [%0, # 96]\n\t"
            "stp  x6,  x7, [%0, #112]\n\t"
            :  // no outputs
            : "r"(buf)
            : "memory");
#endif
    }

    ~SIMDGuardAndX0X7() {
#if defined(ENABLE_SIMD_GUARD)
        // Restore x0–x7 in reverse order
        // Restore q0–q3 in reverse order
        asm volatile(
            "ldp  x6,  x7, [%0, #112]\n\t"
            "ldp  x4,  x5, [%0, # 96]\n\t"
            "ldp  x2,  x3, [%0, # 80]\n\t"
            "ldp  x0,  x1, [%0, # 64]\n\t"
            "ldp  q2,  q3, [%0, # 32]\n\t"
            "ldp  q0,  q1, [%0, #  0]\n\t"
            :
            : "r"(buf)
            : "v0", "v1", "v2", "v3", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory");
#endif
    }

    alignas(16) uint8_t buf[16][8];
};

struct SIMDGuardFull {
    using SIMDRegister_t = uint8_t[8];

    SIMDGuardFull() {
#if defined(ENABLE_SIMD_GUARD)
        // Save q0–q7 in pairs into buf
        asm volatile(
            "stp  q0,  q1, [%0, # 0]\n\t"
            "stp  q2,  q3, [%0, #32]\n\t"
            "stp  q4,  q5, [%0, #64]\n\t"
            "stp  q6,  q7, [%0, #96]\n\t"
            :  // no outputs
            : "r"(buf)
            : "memory");
#endif
    }

    ~SIMDGuardFull() {
#if defined(ENABLE_SIMD_GUARD)
        // Restore q0–q7 in reverse order
        asm volatile(
            "ldp  q6,  q7, [%0, #96]\n\t"
            "ldp  q4,  q5, [%0, #64]\n\t"
            "ldp  q2,  q3, [%0, #32]\n\t"
            "ldp  q0,  q1, [%0, # 0]\n\t"
            :
            : "r"(buf)
            : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory");
#endif
    }

    alignas(16) uint8_t buf[16][8];
};

struct SIMDGuardFullAndX0X7 {
    using SIMDRegister_t = uint8_t[8];

    SIMDGuardFullAndX0X7() {
#if defined(ENABLE_SIMD_GUARD)
        // Save q0–q7 in pairs into buf
        // Save x0–x7 in pairs into buf
        asm volatile(
            "stp  q0,  q1, [%0, #  0]\n\t"
            "stp  q2,  q3, [%0, # 32]\n\t"
            "stp  q4,  q5, [%0, # 64]\n\t"
            "stp  q6,  q7, [%0, # 96]\n\t"
            "stp  x0,  x1, [%0, #128]\n\t"
            "stp  x2,  x3, [%0, #144]\n\t"
            "stp  x4,  x5, [%0, #160]\n\t"
            "stp  x6,  x7, [%0, #176]\n\t"
            :  // no outputs
            : "r"(buf)
            : "memory");
#endif
    }

    ~SIMDGuardFullAndX0X7() {
#if defined(ENABLE_SIMD_GUARD)
        // Restore x0–x7 in reverse order
        // Restore q0–q7 in reverse order
        asm volatile(
            "ldp  x6,  x7, [%0, #176]\n\t"
            "ldp  x4,  x5, [%0, #160]\n\t"
            "ldp  x2,  x3, [%0, #144]\n\t"
            "ldp  x0,  x1, [%0, #128]\n\t"
            "ldp  q6,  q7, [%0, # 96]\n\t"
            "ldp  q4,  q5, [%0, # 64]\n\t"
            "ldp  q2,  q3, [%0, # 32]\n\t"
            "ldp  q0,  q1, [%0, #  0]\n\t"
            :
            : "r"(buf)
            : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "x0", "x1", "x2", "x3", "x4", "x5",
              "x6", "x7", "memory");
#endif
    }

    alignas(16) uint8_t buf[16][12];
};
