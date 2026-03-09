#pragma once
#include <cstdint>

// ── Register.h ───────────────────────────────────────────────────────────────
// AArch64 register number constants, mirroring Rosetta's Register.h.
//
// In AArch64 integer instructions register 31 is context-dependent:
//   - Data-processing: XZR / WZR  (zero register, reads 0, writes discarded)
//   - Load/store base, ADD/SUB:   SP   (stack pointer)
//
// Rosetta uses the convention that 31 = XZR in GPR data-processing context,
// and 63 = SP in the gpr_to_num_sp (stack-pointer) context.
// ─────────────────────────────────────────────────────────────────────────────

enum GPR : uint8_t {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,  // thread-local base (Rosetta thread context)
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,  // scratch GPR pool start
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,  // scratch GPR pool end / frame pointer
    X30 = 30,  // link register
    XZR = 31,  // zero register (data-processing context) — sentinel for "allocate me one"
    SP = 63,   // SP sentinel (gpr_to_num_sp context)
};

enum FPR : uint8_t {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8 = 8,
    V9 = 9,
    V10 = 10,
    V11 = 11,
    V12 = 12,
    V13 = 13,
    V14 = 14,
    V15 = 15,
    V16 = 16,
    V17 = 17,
    V18 = 18,
    V19 = 19,
    V20 = 20,
    V21 = 21,
    V22 = 22,
    V23 = 23,
    // ── allocatable scratch pool (free_fpr_mask bits 24–31) ──
    V24 = 24,
    V25 = 25,
    V26 = 26,
    V27 = 27,
    V28 = 28,
    V29 = 29,
    V30 = 30,
    V31 = 31,
};

// Scratch pool lookup tables — mirrors of Rosetta's byte_43BC8 / byte_43BD0
static constexpr uint8_t kGprScratchPool[8] = {22, 23, 24, 25, 26, 27, 28, 29};
static constexpr uint8_t kFprScratchPool[8] = {24, 25, 26, 27, 28, 29, 30, 31};

// Bitmasks of scratch registers in the free_gpr_mask / free_fpr_mask fields
static constexpr uint32_t kGprScratchMask = 0x3FC00000u;  // bits 22–29
static constexpr uint32_t kFprScratchMask = 0xFF000000u;  // bits 24–31

// ── x86 Register encoding ────────────────────────────────────────────────────
// The encoded byte used in IROperand::reg / IRSourceOperand.
// High nibble = register class, low nibble = index.
//
// High nibble encoding:
//   0x00–0x40  GPR          index 0–15
//   0x50       XMM          index 0–15
//   0x60+bit3=0  MM (MMX)   index 0–7
//   0x70       x87 ST(i)    index 0–7
//   0x90       YMM (AVX)    index 0–15
//   0xA0       ZMM (AVX-512) index 0–15
// ─────────────────────────────────────────────────────────────────────────────

struct Register {
    uint8_t value;

    uint8_t index() const {
        if (is_mm())
            return value & 0x07;
        return value & 0x0F;
    }

    bool is_gpr() const { return value < 0x50; }
    bool is_xmm() const { return (value & 0xF0) == 0x50; }
    bool is_mm() const { return (value & 0xF0) == 0x60 && (value & 0x08) == 0; }
    bool is_stack() const { return (value & 0xF0) == 0x70; }  // x87 ST(i)
    bool is_avx() const {
        auto h = value & 0xF0;
        return h == 0x90 || h == 0xA0;
    }
    bool is_vector() const { return is_xmm() || is_avx(); }
    bool is_vector_or_mm() const { return is_vector() || is_mm(); }
};