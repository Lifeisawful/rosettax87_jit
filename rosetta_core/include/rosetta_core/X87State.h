#pragma once

#include <cstddef>
#include <cstdint>

enum X87StatusWordFlag : uint16_t {
    kInvalidOperation = 0x0001,
    kDenormalizedOperand = 0x0002,
    kZeroDivide = 0x0004,
    kOverflow = 0x0008,
    kUnderflow = 0x0010,
    kPrecision = 0x0020,
    kStackFault = 0x0040,
    kErrorSummary = 0x0080,
    kConditionCode0 = 0x0100,
    kConditionCode1 = 0x0200,
    kConditionCode2 = 0x0400,
    kConditionCode3 = 0x4000,
    kTopOfStack = 0x3800,
    kBusy = 0x8000,
};

enum class X87TagState { kValid = 0, kZero = 1, kSpecial = 2, kEmpty = 3 };

enum X87ControlWord : uint16_t {
    kInvalidOpMask = 0x0001,
    kDenormalMask = 0x0002,
    kZeroDivideMask = 0x0004,
    kOverflowMask = 0x0008,
    kUnderflowMask = 0x0010,
    kPrecisionMask = 0x0020,
    kPrecisionControl = 0x0300,
    kPrecision24Bit = 0x0000,
    kPrecision53Bit = 0x0200,
    kPrecision64Bit = 0x0300,
    kRoundingControlMask = 0x0C00,
    kRoundToNearest = 0x0000,
    kRoundDown = 0x0400,
    kRoundUp = 0x0800,
    kRoundToZero = 0x0C00,
    kInfinityControl = 0x1000
};

// Legacy 80-bit type — used only by fld_fp80 / fst_fp80 runtime helpers.
#pragma pack(push, 1)
struct X87Float80 {
    uint64_t mantissa;
    uint16_t exponent;
};
#pragma pack(pop)
static_assert(sizeof(X87Float80) == 0x0A, "Invalid size for X87Float80");

// ── x87 state — stride-8 layout ─────────────────────────────────────────────
//
// All x87 values are stored as IEEE 754 double (64-bit).  The 80-bit extended
// precision is deliberately dropped.  This puts the st[] register file at
// 8-byte stride, enabling AArch64 scaled register-offset addressing:
//   LDR Dd, [Xbase_st, Windex, SXTW #3]   ; one instruction, zero offset math
//
// 2-byte padding at +0x06 aligns st[0] to offset 0x08.
#pragma pack(push, 1)

struct X87State {
    uint16_t control_word;  // +0x00
    uint16_t status_word;   // +0x02
    int16_t tag_word;       // +0x04
    int16_t _pad06;         // +0x06  alignment padding

    double st[8];  // +0x08, stride 8
};

#pragma pack(pop)

static_assert(sizeof(X87State) == 0x48, "Invalid size for X87State");
static_assert(offsetof(X87State, control_word) == 0, "");
static_assert(offsetof(X87State, status_word) == 2, "");
static_assert(offsetof(X87State, tag_word) == 4, "");
static_assert(offsetof(X87State, st) == 0x08, "");
