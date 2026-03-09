#pragma once

#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "Log.h"
#include "X87Float80.h"
#include "X87StackRegister.h"

// Option to convert 64 bit float to 80 bit x87 format to be compatible with
// original rosetta x87 implementation This must be used if you want to
// selectively enable x87 instructions.
// #define X87_CONVERT_TO_FP80

enum X87StatusWordFlag : uint16_t {
    // Exception flags
    kInvalidOperation = 0x0001,     // Invalid Operation Exception
    kDenormalizedOperand = 0x0002,  // Denormalized Operand Exception
    kZeroDivide = 0x0004,           // Zero Divide Exception
    kOverflow = 0x0008,             // Overflow Exception–
    kUnderflow = 0x0010,            // Underflow Exception
    kPrecision = 0x0020,            // Precision Exception

    // Status flags
    kStackFault = 0x0040,    // Stack Fault
    kErrorSummary = 0x0080,  // Error Summary Status

    // Condition codes
    kConditionCode0 = 0x0100,  // Condition Code 0
    kConditionCode1 = 0x0200,  // Condition Code 1
    kConditionCode2 = 0x0400,  // Condition Code 2
    kConditionCode3 = 0x4000,  // Condition Code 3

    // Special flags
    kTopOfStack = 0x3800,  // Top of Stack Pointer (bits 11-13)
    kBusy = 0x8000,        // FPU Busy
};

enum class X87TagState {
    kValid = 0,    // 00: Valid non-zero value
    kZero = 1,     // 01: Valid zero value
    kSpecial = 2,  // 10: Special value (NaN, Infinity, Denormal)
    kEmpty = 3     // 11: Empty register
};

enum X87ControlWord : uint16_t {
    // Exception Masks (1=masked)
    kInvalidOpMask = 0x0001,
    kDenormalMask = 0x0002,
    kZeroDivideMask = 0x0004,
    kOverflowMask = 0x0008,
    kUnderflowMask = 0x0010,
    kPrecisionMask = 0x0020,

    // Precision Control
    kPrecisionControl = 0x0300,
    kPrecision24Bit = 0x0000,  // Single precision
    kPrecision53Bit = 0x0200,  // Double precision
    kPrecision64Bit = 0x0300,  // Extended precision

    // Rounding Control
    kRoundingControlMask = 0x0C00,
    kRoundToNearest = 0x0000,
    kRoundDown = 0x0400,
    kRoundUp = 0x0800,
    kRoundToZero = 0x0C00,

    // Infinity Control (only on 287)
    kInfinityControl = 0x1000
};

double inline ConvertX87RegisterToFloat64(X87Float80 x87, uint16_t* statusFlags) {
    uint64_t mantissa = x87.mantissa;
    uint16_t biasedExp = x87.exponent & 0x7FFF;
    uint64_t sign = (x87.exponent & 0x8000) ? 0x8000000000000000ULL : 0;
    union {
        uint64_t bits;
        double value;
    } result;

    // Zero
    if (mantissa == 0) {
        return (sign ? -0.0 : 0.0);
    }

    // NaN or Infinity
    if (biasedExp == 0x7FFF) {
        if (mantissa != 0x8000000000000000ULL) {
            if (statusFlags)
                *statusFlags |= X87StatusWordFlag::kInvalidOperation;
            result.bits = sign | 0x7FF8000000000000ULL;
            return result.value;
        }
        result.bits = sign | 0x7FF0000000000000ULL;
        return result.value;
    }

    int32_t exp = static_cast<int32_t>(biasedExp) - 16383 + 1023;

    // Denormalized / Underflow
    if (exp <= 0) {
        if (statusFlags)
            *statusFlags |= X87StatusWordFlag::kUnderflow;
        if (exp < -52) {
            return (sign ? -0.0 : 0.0);
        }
        // Denormalize
        mantissa >>= (1 - exp);
        exp = 0;
    }

    // Overflow
    if (exp >= 2047) {
        if (statusFlags)
            *statusFlags |= X87StatusWordFlag::kOverflow;
        result.bits = sign | 0x7FF0000000000000ULL;
        return result.value;
    }

    // Round to 52 bits
    uint64_t significant = (mantissa >> 11) & 0xFFFFFFFFFFFFFULL;
    uint64_t roundBit = (mantissa >> 10) & 1;
    uint64_t stickyBits = (mantissa & ((1ULL << 10) - 1)) != 0;

    // Precision exception
    if ((roundBit || stickyBits) && statusFlags) {
        *statusFlags |= X87StatusWordFlag::kPrecision;
    }

    // Round to nearest even
    if (roundBit && (stickyBits || (significant & 1))) {
        significant++;
        if (significant == 0x10000000000000ULL) {
            significant = 0;
            exp++;
            if (exp >= 2047) {
                if (statusFlags)
                    *statusFlags |= X87StatusWordFlag::kOverflow;
                result.bits = sign | 0x7FF0000000000000ULL;
                return result.value;
            }
        }
    }

    result.bits = sign | (static_cast<uint64_t>(exp) << 52) | significant;
    return result.value;
}

#pragma pack(push, 1)
struct X87State {
    uint16_t controlWord;
    uint16_t statusWord;
    int16_t tagWord;
    int16_t pad;
    X87StackRegister st[8];

    X87State()
        : controlWord(0x037F),
          statusWord(0x0000),
          tagWord(0xFFFF) {  // All registers marked empty (11)
        // Initialize all registers to zero
        for (int i = 0; i < 8; i++) {
            st[i].ieee754 = 0.0;
        }
    }

    // Get index of top register
    auto topIndex() const -> uint32_t {
        return (statusWord >> 11) & 7;
    }  // Get reference to top register

    // Get index of ST(i) register
    auto getStIndex(uint32_t stOffset) const -> uint32_t { return (stOffset + topIndex()) & 7; }

    // Get value from register at ST(i). Checks tag bits for validity, returns 0.0
    // if empty. Updates status word.
    __attribute__((always_inline)) auto getSt(uint32_t stOffset) -> double {
        const uint32_t regIdx = getStIndex(stOffset);
        const auto tag = static_cast<X87TagState>((tagWord >> (regIdx * 2)) & 3);
        if (tag == X87TagState::kEmpty) {
            // FP_X_STK | FP_X_INV
            statusWord |= X87StatusWordFlag::kStackFault | X87StatusWordFlag::kInvalidOperation;
            return std::numeric_limits<double>::quiet_NaN();
        }

        return st[regIdx].ieee754;
    }

    auto getStConst(uint32_t stOffset) const -> std::pair<double, uint16_t> {
        const uint32_t regIdx = getStIndex(stOffset);
        const X87TagState tag = static_cast<X87TagState>((tagWord >> (regIdx * 2)) & 3);

        uint16_t newStatusWord = statusWord & ~(X87StatusWordFlag::kConditionCode1);
        if (tag == X87TagState::kEmpty) {
            // FP_X_STK | FP_X_INV
            //  return nan
            return {std::numeric_limits<double>::quiet_NaN(),
                    newStatusWord | X87StatusWordFlag::kStackFault |
                        X87StatusWordFlag::kInvalidOperation};
        }
        return {st[regIdx].ieee754, newStatusWord};
    }

    auto getStConst32(uint32_t stOffset) const -> std::pair<float, uint16_t> {
        const uint32_t regIdx = getStIndex(stOffset);
        const X87TagState tag = static_cast<X87TagState>((tagWord >> (regIdx * 2)) & 3);

        uint16_t newStatusWord = statusWord & ~(X87StatusWordFlag::kConditionCode1);
        if (tag == X87TagState::kEmpty) {
            // FP_X_STK | FP_X_INV
            //  return nan
            return {std::numeric_limits<float>::quiet_NaN(),
                    newStatusWord | X87StatusWordFlag::kStackFault |
                        X87StatusWordFlag::kInvalidOperation};
        }

        return {st[regIdx].ieee754, newStatusWord};
    }

    __attribute__((always_inline)) auto getStTag(uint32_t stOffset) const -> X87TagState {
        const uint32_t regIdx = getStIndex(stOffset);
        return static_cast<X87TagState>((tagWord >> (regIdx * 2)) & 3);
    }

    // Push value to FPU stack
    auto push() -> void {
        const int currentTop = topIndex();
        const int newTop = (currentTop - 1) & 7;
        statusWord = (statusWord & ~X87StatusWordFlag::kTopOfStack) | (newTop << 11);
        // Clear tag bits (set to valid 00) for new register
        tagWord &= ~(3 << (newTop * 2));
    }

    auto pop() -> void {
        const int currentTop = topIndex();
        // Set tag bits to empty (11) for popped register
        tagWord |= (3 << (currentTop * 2));
        st[currentTop].ieee754 = 0.0;
        statusWord =
            (statusWord & ~X87StatusWordFlag::kTopOfStack) | (((currentTop + 1) & 7) << 11);
    }

    __attribute__((always_inline)) auto setSt(uint32_t stOffset, double value) -> void {
        auto stIdx = getStIndex(stOffset);

        st[stIdx].ieee754 = value;
        X87TagState tag;
        if (value == 0.0) {
            tag = X87TagState::kZero;
        } else if (std::isnan(value) || std::isinf(value) ||
                   std::fpclassify(value) == FP_SUBNORMAL) {
            tag = X87TagState::kSpecial;
        } else {
            tag = X87TagState::kValid;
        }

        // Clear existing tag bits and set new state
        tagWord &= ~(3 << (stIdx * 2));
        tagWord |= (static_cast<int>(tag) << (stIdx * 2));
    }

    __attribute__((always_inline)) auto setStFast(uint32_t stOffset, double value) -> void {
        const uint32_t idx = getStIndex(stOffset);

        // Direct IEEE-754 store
        st[idx].ieee754 = value;

        // Clear both tag bits → 00 (kValid)
        tagWord &= ~(0x3u << (idx * 2));
    }

    // Fast path: bypass tag-checks, assume value valid
    __attribute__((always_inline)) auto getStFast(uint32_t stOffset) const -> double {
        // Compute absolute slot index
        const uint32_t idx = getStIndex(stOffset);

        // Direct IEEE-754 load
        return st[idx].ieee754;
    }

    auto swap_registers(uint32_t regOffset1, uint32_t regOffset2) -> void {
        // Swap register contents
        auto regIdx1 = getStIndex(regOffset1);
        auto regIdx2 = getStIndex(regOffset2);

        auto temp = st[regIdx1].ieee754;
        st[regIdx1].ieee754 = st[regIdx2].ieee754;
        st[regIdx2].ieee754 = temp;

        // Get current tags
        const int tag1 = (tagWord >> (regIdx1 * 2)) & 3;
        const int tag2 = (tagWord >> (regIdx2 * 2)) & 3;

        // Clear both tags
        tagWord &= ~((3 << (regIdx1 * 2)) | (3 << (regIdx2 * 2)));

        // Set swapped tags
        tagWord |= (tag2 << (regIdx1 * 2)) | (tag1 << (regIdx2 * 2));
    }

    auto print() const -> void {
        // printf("FPU state:\n");
        // printf("Control word: %d\n", controlWord);
        // printf("Status word: %d\n", statusWord);
        // printf("Tag word: %d\n", tagWord);
        // printf("Top index: %d\n", topIndex());
        // printf("\n");
    }
};
#pragma pack(pop)
static_assert(sizeof(X87State) == 0x48, "Invalid size for X87State");
static_assert(offsetof(X87State, controlWord) == 0, "Invalid offset for X87State::controlWord");
static_assert(offsetof(X87State, statusWord) == 2, "Invalid offset for X87State::statusWord");
static_assert(offsetof(X87State, tagWord) == 4, "Invalid offset for X87State::tagWord");

static_assert(offsetof(X87State, st) == 0x08, "Invalid offset for X87State::st0");
