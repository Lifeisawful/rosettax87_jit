// clang-format off
#include "X87.h"

#include <cstring>

#include "Export.h"
#include "Offsets.h"
#include "Log.h"
#include "SIMDGuard.h"
#include "X87State.h"
#include "openlibm/s_tan.h"
#include "openlibm/s_remquo.h"
#include "openlibm/s_exp2.h"
#include "openlibm/e_log2.h"
#include "openlibm/e_pow.h"
#include "openlibm/s_cos.h"
#include "openlibm/s_sin.h"
#include "openlibm/s_atan.h"
#include "openlibm/e_atan2.h"
#include "openlibm/e_fmod.h"
#include "openlibm/s_ilogb.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/RuntimeLibC.h"
#include "RuntimeConfig.h"
// clang-format on

#define X87_TRAMPOLINE(NAME, REGISTER)                                 \
    void __attribute__((naked, used)) NAME() {                         \
        asm volatile("adrp " #REGISTER ", _orig_" #NAME                \
                     "@PAGE\n"                                         \
                     "ldr " #REGISTER ", [" #REGISTER ", _orig_" #NAME \
                     "@PAGEOFF]\n"                                     \
                     "br " #REGISTER);                                 \
    }

#define X87_TRAMPOLINE_ARGS(RETURN, NAME, ARGS, REGISTER)              \
    RETURN __attribute__((naked, used)) NAME ARGS {                    \
        asm volatile("adrp " #REGISTER ", _orig_" #NAME                \
                     "@PAGE\n"                                         \
                     "ldr " #REGISTER ", [" #REGISTER ", _orig_" #NAME \
                     "@PAGEOFF]\n"                                     \
                     "br " #REGISTER);                                 \
    }

#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/RuntimeLibC.h"

void* init_library(SymbolList const* a1, uint64_t a2, ThreadContextOffsets const* a3) {
    SIMDGuardFull simdGuard;
    exportsInit();
    rosetta_set_config(&kConfig);

    printf("RosettaRuntimex87 built %s\n", __DATE__ " " __TIME__);

    uintptr_t runtime_library_base =
        reinterpret_cast<uintptr_t>(orig_init_library) - kOffsets.init_library_rva;
    uintptr_t translation_ptr = runtime_library_base + kOffsets.translate_insn_addr;
    uintptr_t transaction_result_size_addr =
        runtime_library_base + kOffsets.transaction_result_size_addr;

    printf("Installing JIT Translation Hook at 0x%lx\n", (unsigned long)translation_ptr);
    init_custom_translation_hook(translation_ptr, transaction_result_size_addr);
    printf("JIT Translation Hook installed\n");

    return orig_init_library(a1, a2, a3);
}

X87_TRAMPOLINE(register_runtime_routine_offsets, x9)
X87_TRAMPOLINE(translator_use_t8027_codegen, x9)
X87_TRAMPOLINE(translator_reset, x9)
X87_TRAMPOLINE(ir_create_bad_access, x9)
X87_TRAMPOLINE(ir_create, x9)
X87_TRAMPOLINE(module_free, x9)
X87_TRAMPOLINE(module_get_size, x9)
X87_TRAMPOLINE(module_is_bad_access, x9)
X87_TRAMPOLINE(module_print, x9)
X87_TRAMPOLINE(translator_translate, x9)
X87_TRAMPOLINE(translator_free, x9)
X87_TRAMPOLINE(translator_get_data, x9)
X87_TRAMPOLINE(translator_get_size, x9)
X87_TRAMPOLINE(translator_get_branch_slots_offset, x9)
X87_TRAMPOLINE(translator_get_branch_slots_count, x9)
X87_TRAMPOLINE(translator_get_branch_entries, x9)
X87_TRAMPOLINE(translator_get_instruction_offsets, x9)
X87_TRAMPOLINE(translator_apply_fixups, x9)

void x87_init(X87State* state) {
    SIMDGuard simdGuard;
    LOG(1, "x87_init\n", 9);
    *state = X87State();
}

X87_TRAMPOLINE(x87_state_from_x86_float_state, x9);
X87_TRAMPOLINE(x87_state_to_x86_float_state, x9);

void x87_pop_register_stack(X87State* state) {
    LOG(1, "x87_pop_register_stack\n", 9);
    state->pop();
}

void x87_f2xm1(X87State* state) {
    SIMDGuardFull simdGuard;

    LOG(1, "x87_f2xm1\n", 10);
    // Get value from ST(0)
    auto x = state->getStFast(0);

    // // Check range [-1.0, +1.0]
    if (x < -1.0f || x > 1.0f) {
        // Set to NaN for undefined result
        state->setStFast(0, 0);
        return;
    }

    // Calculate 2^x - 1 using mmath::exp2
    auto result = openlibm_exp2(x) - 1.0f;

    // Store result back in ST(0)
    state->setStFast(0, result);
}

// Clears the sign bit of ST(0) to create the absolute value of the operand. The
// following table shows the results obtained when creating the absolute value
// of various classes of numbers. C1 Set to 0.
void x87_fabs(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fabs\n", 10);

    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get value in ST(0)
    auto value = state->getStFast(0);

    // Set value in ST(0) to its absolute value
    state->setStFast(0, std::abs(value));
}

void x87_fadd_ST(X87State* state, uint32_t st_offset_1, uint32_t st_offset_2, bool pop_stack) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fadd_ST\n", 13);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset_1);
    const auto val2 = state->getStFast(st_offset_2);

    // Perform addition and store result in ST(idx1)
    state->setStFast(st_offset_1, val1 + val2);

    if (pop_stack) {
        state->pop();
    }
}

void x87_fadd_f32(X87State* state, uint32_t fp32) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fadd_f32\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(fp32);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 + value);
}

void x87_fadd_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fadd_f64\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 + value);
}

double BCD2Double(uint8_t bcd[10]) {
    uint64_t tmp = 0;
    uint64_t mult = 1;
    uint8_t piece;

    for (int i = 0; i < 9; ++i) {
        piece = bcd[i];
        tmp += mult * (piece & 0x0F);
        mult *= 10;
        tmp += mult * ((piece >> 4) & 0x0F);
        mult *= 10;
    }

    piece = bcd[9];
    tmp += mult * (piece & 0x0F);

    double value = static_cast<double>(tmp);

    if (piece & 0x80) {
        value = -value;
    }

    return value;
}

void x87_fbld(X87State* state, uint64_t val1, uint64_t val2) {
    SIMDGuard simdGuard;
    LOG(1, "x87_fbld\n", 10);

    // set C1 to 0
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    uint8_t bcd[10];
    memcpy(bcd, &val1, 8);      // Copy 8 bytes from val1
    memcpy(bcd + 8, &val2, 2);  // Copy 2 bytes from val2

    auto value = BCD2Double(bcd);

    // Add space on the stack and push the converted BCD
    state->push();
    state->setSt(0, value);
}

uint128_t x87_fbstp(X87State* state) {
    SIMDGuardAndX0X7 simdGuard;
    LOG(1, "x87_fbstp\n", 11);

    auto st0 = state->getSt(0);
    state->pop();

    // convert double to BCD
    uint8_t bcd[10] = {0};  // Initialize all bytes to 0

    // Handle sign
    bool is_negative = signbit(st0);

    // Handle special cases
    if (x87_is_nan_or_inf(st0)) {
        // Set to indefinite BCD value
        memset(bcd, 0, 10);
        if (is_negative) {
            bcd[9] = 0x80;  // Set sign bit if negative
        }
    } else {
        // Get absolute value
        double abs_value = fabs(st0);

        // Truncate to integer
        abs_value = trunc(abs_value);

        // Check if value is too large for BCD format (more than 18 decimal digits)
        if (abs_value > 999999999999999999.0) {
            // Handle overflow - set to maximum BCD value
            memset(bcd, 0x99, 9);  // Set first 9 bytes to 0x99 (all digits = 9)
            bcd[9] = 0x09;         // Set last digit to 9
            if (is_negative) {
                bcd[9] |= 0x80;  // Set sign bit if negative
            }
        } else {
            // Convert to BCD representation
            uint64_t integer_part = static_cast<uint64_t>(abs_value);

            // Process each byte (2 decimal digits per byte)
            for (int i = 0; i < 9; i++) {
                uint8_t digit1 = integer_part % 10;
                integer_part /= 10;
                uint8_t digit2 = integer_part % 10;
                integer_part /= 10;

                bcd[i] = digit1 | (digit2 << 4);
            }

            // Handle the 10th byte (contains 1 digit and sign)
            bcd[9] = integer_part % 10;
            if (is_negative) {
                bcd[9] |= 0x80;  // Set sign bit if negative
            }
        }
    }

    return {
        .low = reinterpret_cast<uint64_t*>(bcd)[0],
        .high = reinterpret_cast<uint64_t*>(bcd)[1],
    };
}

void x87_fchs(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fchs\n", 10);
    // set C1 to 0
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Negate value in ST(0)
    state->setStFast(0, -state->getStFast(0));
}

void x87_fcmov(X87State* state, uint32_t condition, uint32_t st_offset) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fcmov\n", 11);

    // clear precision flag
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    double value;

    auto stTagWord = state->getStTag(st_offset);
    if (stTagWord != X87TagState::kEmpty) {
        if (condition == 0) {
            return;
        }

        value = state->getSt(st_offset);
    } else {
        state->statusWord |= 0x41;  // Set invalid operation
        value = 0.0f;
    }

    state->setSt(0, value);  // Perform the actual register move
}

void x87_fcom_ST(X87State* state, uint32_t st_offset, uint32_t number_of_pops) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fcom_ST\n", 13);

    // Get values to compare
    auto st0 = state->getSt(0);
    auto src = state->getSt(st_offset);

    // Clear condition code bits C0, C2, C3 (bits 8, 9, 14)
    state->statusWord &= ~(kConditionCode0 | kConditionCode2 | kConditionCode3);

    // Set condition codes based on comparison
    if (st0 > src) {
        // Leave C0=C2=C3=0
    } else if (st0 < src) {
        state->statusWord |= kConditionCode0;  // Set C0=1
    } else {                                   // st0 == sti
        state->statusWord |= kConditionCode3;  // Set C3=1
    }

    if ((state->controlWord & kInvalidOpMask) == kInvalidOpMask) {
        if (x87_is_nan(st0) || x87_is_nan(src)) {
            state->statusWord |=
                kConditionCode0 | kConditionCode2 | kConditionCode3;  // Set C0=C2=C3=1
        }
    }

    // Handle pops if requested
    for (unsigned int i = 0; i < number_of_pops; i++) {
        state->pop();
    }
}

void x87_fcom_f32(X87State* state, uint32_t fp32, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fcom_f32\n", 14);
    auto st0 = state->getSt(0);
    auto src = std::bit_cast<float>(fp32);

    state->statusWord &= ~(kConditionCode0 | kConditionCode1 | kConditionCode2 | kConditionCode3);

    if (st0 > src) {
        // Leave C0=C2=C3=0
    } else if (st0 < src) {
        state->statusWord |= kConditionCode0;  // Set C0=1
    } else {                                   // st0 == value
        state->statusWord |= kConditionCode3;  // Set C3=1
    }

    if ((state->controlWord & kInvalidOpMask) == kInvalidOpMask) {
        if (x87_is_nan(st0) || x87_is_nan(src)) {
            state->statusWord |=
                kConditionCode0 | kConditionCode2 | kConditionCode3;  // Set C0=C2=C3=1
        }
    }

    if (pop) {
        state->pop();
    }
}

void x87_fcom_f64(X87State* state, uint64_t fp64, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fcom_f64\n", 14);
    auto st0 = state->getSt(0);
    auto src = std::bit_cast<double>(fp64);

    state->statusWord &= ~(kConditionCode0 | kConditionCode2 | kConditionCode3);

    if (st0 > src) {
        // Leave C0=C2=C3=0
    } else if (st0 < src) {
        state->statusWord |= kConditionCode0;  // Set C0=1
    } else {                                   // st0 == value
        state->statusWord |= kConditionCode3;  // Set C3=1
    }

    if ((state->controlWord & kInvalidOpMask) == kInvalidOpMask) {
        if (x87_is_nan(st0) || x87_is_nan(src)) {
            state->statusWord |=
                kConditionCode0 | kConditionCode2 | kConditionCode3;  // Set C0=C2=C3=1
        }
    }

    if (pop) {
        state->pop();
    }
}

uint32_t x87_fcomi(X87State* state, uint32_t st_offset, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fcomi\n", 11);
    state->statusWord &= ~(kConditionCode0);

    auto st0_val = state->getSt(0);
    auto sti_val = state->getSt(st_offset);

    uint32_t flags = 0;
    /*
    Filters: fcomi
    Randomness seeded to: 3528984885
    x87_fcomi_less
    x87_fcomi result: 0x000000000000000
    x87_fcomi_greater
    x87_fcomi result: 0x000000020000000
    x87_fcomi_equal
    x87_fcomi result: 0x000000060000000
    */

    if (x87_is_nan(st0_val) || x87_is_nan(sti_val)) {
        flags = 0x54000000;  // unordered: bit26=PF for x87_fcmov path, V=1 for translated fcsel VS/VC path
    } else if (st0_val < sti_val) {
        flags = 0x000000000000000;
    } else if (st0_val > sti_val) {
        flags = 0x000000020000000;
    } else {
        flags = 0x000000060000000;
    }

    if (pop) {
        state->pop();
    }

    return flags;
}

void x87_fcos(X87State* state) {
    SIMDGuardFullAndX0X7 simdGuard;

    LOG(1, "x87_fcos\n", 10);
    state->statusWord &= ~(kConditionCode1 | kConditionCode2);
    // Get ST(0)
    auto value = state->getStFast(0);

    // Calculate cosine
    auto result = openlibm_cos(value);

    // Store result back in ST(0)
    state->setStFast(0, result);
}

void x87_fdecstp(X87State* state) {
    LOG(1, "x87_fdecstp\n", 13);

    uint16_t current_top = (state->statusWord & X87StatusWordFlag::kTopOfStack) >> 11;

    // Decrement the top of stack pointer (wrapping from 0 to 7)
    uint16_t new_top = (current_top - 1) & 7;

    // Clear C1
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;
    // Clear the top of stack bits and set the new value
    state->statusWord = (state->statusWord & ~X87StatusWordFlag::kTopOfStack) | (new_top << 11);
}

void x87_fdiv_ST(X87State* state, uint32_t st_offset_1, uint32_t st_offset_2, bool pop_stack) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdiv_ST\n", 13);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset_1);
    const auto val2 = state->getStFast(st_offset_2);

    // Perform division and store result
    state->setStFast(st_offset_1, val1 / val2);

    if (pop_stack) {
        state->pop();
    }
}

void x87_fdiv_f32(X87State* state, uint32_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdiv_f32\n", 14);
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 / value);
}

void x87_fdiv_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdiv_f64\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 / value);
}

void x87_fdivr_ST(X87State* state, uint32_t st_offset_1, uint32_t st_offset_2, bool pop_stack) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdivr_ST\n", 14);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset_1);
    const auto val2 = state->getStFast(st_offset_2);

    // Perform reversed division and store result
    state->setStFast(st_offset_1, val2 / val1);

    if (pop_stack) {
        state->pop();
    }
}

void x87_fdivr_f32(X87State* state, uint32_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdivr_f32\n", 15);
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, value / st0);
}

void x87_fdivr_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fdivr_f64\n", 15);
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, value / st0);
}

void x87_ffree(X87State* state, uint32_t val) {
    LOG(1, "x87_ffree\n", 11);
    orig_x87_ffree(state, val);
}

void x87_fiadd(X87State* state, int32_t m32int) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fiadd\n", 11);
    // simplePrintf("m32int: %d\n", m32int);
    // printf("m32int: %d\n", m32int);

    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get value in ST(0)
    auto st0 = state->getSt(0);

    // printf("ST(0) before addition: %08x\n", st0);
    // printf("Tag for ST(0): %d\n", state->getStTag(0));

    // Add integer value
    st0 += m32int;

    // Store result back in ST(0)
    state->setSt(0, st0);
}

void x87_ficom(X87State* state, int32_t src, bool pop) {
    SIMDGuard simdGuard;
    LOG(1, "x87_ficom\n", 11);
    auto st0 = state->getSt(0);

    // Clear condition code bits C0, C2, C3 (bits 8, 9, 14)
    state->statusWord &= ~(kConditionCode0 | kConditionCode2 | kConditionCode3);

    // Set condition codes based on comparison
    if (x87_is_nan(st0)) {
        state->statusWord |= kConditionCode0 | kConditionCode2 | kConditionCode3;  // Set C0=C2=C3=1
    } else if (st0 > src) {
        // Leave C0=C2=C3=0
    } else if (st0 < src) {
        state->statusWord |= kConditionCode0;  // Set C0=1
    } else {                                   // st0 == src
        state->statusWord |= kConditionCode3;  // Set C3=1
    }

    // Handle pops if requested
    if (pop) {
        state->pop();
    }
}

void x87_fidiv(X87State* state, int val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fidiv\n", 11);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get value in ST(0)
    auto value = state->getSt(0);

    // Divide by integer value
    value /= val;

    // Store result back in ST(0)
    state->setSt(0, value);
}

void x87_fidivr(X87State* state, int val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fidivr\n", 12);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get value in ST(0)
    auto value = state->getSt(0);

    // Divide integer value by value in ST(0)
    value = val / value;

    // Store result back in ST(0)
    state->setSt(0, value);
}
void x87_fild(X87State* state, int64_t value) {
    SIMDGuard simdGuard;
    LOG(1, "x87_fild\n", 10);

    state->push();
    state->setSt(0, static_cast<double>(value));
}

void x87_fimul(X87State* state, int val) {
    SIMDGuard simdGuard;
    LOG(1, "x87_fimul\n", 11);
    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get value in ST(0)
    auto value = state->getSt(0);

    // Multiply by integer value
    value *= val;

    // Store result back in ST(0)
    state->setSt(0, value);
}

void x87_fincstp(X87State* state) {
    LOG(1, "x87_fincstp\n", 13);

    // Clear condition code 1 (C1)
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Extract the TOP field (bits 11-13)
    uint16_t top = (state->statusWord & X87StatusWordFlag::kTopOfStack) >> 11;

    // Increment TOP with wrap-around (values 0-7)
    top = (top + 1) & 0x7;

    // Clear old TOP value and set the new one
    state->statusWord &= ~X87StatusWordFlag::kTopOfStack;  // Clear TOP field
    state->statusWord |= (top << 11);                      // Set new TOP value
}

X87ResultStatusWord x87_fist_i16(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fist_i16\n", 14);
    auto [value, statusWord] = state->getStConst(0);
    X87ResultStatusWord result{0, statusWord};

    // Special case: value > INT16_MAX or infinity (changed from >=)
    if (value > static_cast<double>(INT16_MAX)) {
        result.signedResult = INT16_MIN;  // 0x8000
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    // Special case: value <= INT16_MIN
    if (value <= static_cast<double>(INT16_MIN)) {
        result.signedResult = INT16_MIN;
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    // Normal case
    auto round_bits = state->controlWord & X87ControlWord::kRoundingControlMask;

    switch (round_bits) {
        case X87ControlWord::kRoundToNearest: {
            result.signedResult = static_cast<int16_t>(std::nearbyint(value));
        } break;

        case X87ControlWord::kRoundDown: {
            result.signedResult = static_cast<int16_t>(std::floor(value));
            return result;
        } break;

        case X87ControlWord::kRoundUp: {
            result.signedResult = static_cast<int16_t>(std::ceil(value));
            return result;
        } break;

        case X87ControlWord::kRoundToZero: {
            result.signedResult = static_cast<int16_t>(value);
            return result;
        } break;
    }

    return result;
}

X87ResultStatusWord x87_fist_i32(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fist_i32\n", 14);
    auto [value, statusWord] = state->getStConst(0);
    X87ResultStatusWord result{0, statusWord};

    // Special case: value >= INT32_MAX or infinity
    if (value >= static_cast<double>(INT32_MAX)) {
        result.signedResult = INT32_MIN;  // 0x80000000
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    // Special case: value <= INT32_MIN
    if (value <= static_cast<double>(INT32_MIN)) {
        result.signedResult = INT32_MIN;
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    auto round_bits = state->controlWord & X87ControlWord::kRoundingControlMask;

    switch (round_bits) {
        case X87ControlWord::kRoundToNearest: {
            result.signedResult = static_cast<int32_t>(std::nearbyint(value));
        } break;

        case X87ControlWord::kRoundDown: {
            result.signedResult = static_cast<int32_t>(std::floor(value));
            return result;
        } break;

        case X87ControlWord::kRoundUp: {
            result.signedResult = static_cast<int32_t>(std::ceil(value));
            return result;
        } break;

        case X87ControlWord::kRoundToZero: {
            result.signedResult = static_cast<int32_t>(value);
            return result;
        } break;
    }

    return result;
}

X87ResultStatusWord x87_fist_i64(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fist_i64\n", 14);
    // Get value in ST(0)
    auto [value, statusWord] = state->getStConst(0);

    X87ResultStatusWord result{0, statusWord};

    // Special case: value >= INT64_MAX or infinity
    if (value >= static_cast<double>(INT64_MAX)) {
        result.signedResult = INT64_MIN;  // 0x8000000000000000
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    // Special case: value <= INT64_MIN
    if (value <= static_cast<double>(INT64_MIN)) {
        result.signedResult = INT64_MIN;
        result.statusWord |= X87StatusWordFlag::kConditionCode1;
        return result;
    }

    // Normal case

    auto round_bits = state->controlWord & X87ControlWord::kRoundingControlMask;

    switch (round_bits) {
        case X87ControlWord::kRoundToNearest: {
            result.signedResult = static_cast<int64_t>(std::nearbyint(value));
        } break;

        case X87ControlWord::kRoundDown: {
            result.signedResult = static_cast<int64_t>(std::floor(value));
            return result;
        } break;

        case X87ControlWord::kRoundUp: {
            result.signedResult = static_cast<int64_t>(std::ceil(value));
            return result;
        } break;

        case X87ControlWord::kRoundToZero: {
            result.signedResult = static_cast<int64_t>(value);
            return result;
        } break;
    }

    return result;
}

X87ResultStatusWord x87_fistt_i16(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fistt_i16\n", 15);
    // Get value in ST(0)
    auto [value, statusWord] = state->getStConst(0);

    return {.signedResult = static_cast<int16_t>(value), statusWord};
}

X87ResultStatusWord x87_fistt_i32(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fistt_i32\n", 15);
    // Get value in ST(0)
    auto [value, statusWord] = state->getStConst(0);

    return {.signedResult = static_cast<int32_t>(value), statusWord};
}

X87ResultStatusWord x87_fistt_i64(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fistt_i64\n", 15);
    // Get value in ST(0)
    auto [value, statusWord] = state->getStConst(0);

    return {.signedResult = static_cast<int64_t>(value), statusWord};
}

void x87_fisub(X87State* state, int val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fisub\n", 11);
    // Clear condition code 1
    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get value in ST(0)
    auto value = state->getSt(0);

    // Subtract integer value
    value -= val;

    // Store result back in ST(0)
    state->setSt(0, value);
}

void x87_fisubr(X87State* state, int val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fisubr\n", 12);

    // Clear condition code 1
    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get value in ST(0)
    auto value = state->getSt(0);

    // Subtract integer value
    value = val - value;

    // Store result back in ST(0)
    state->setSt(0, value);
}

void x87_fld_STi(X87State* state, uint32_t st_offset) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fld_STi\n", 13);
    state->statusWord &= ~0x200u;

    // Get index of ST(i) register
    const auto value = state->getSt(st_offset);

    // make room for new value
    state->push();

    // Copy value from ST(i) to ST(0)
    state->setSt(0, value);
}

void x87_fld_constant(X87State* state, X87Constant val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fld_constant\n", 18);
    // simplePrintf("x87_fld_constant %d\n", (int)val);
    switch (val) {
        case X87Constant::kOne: {  // fld1
            state->push();
            state->setSt(0, 1.0);
        } break;

        case X87Constant::kZero: {  // fldz
            state->push();
            state->setSt(0, 0.0);
        } break;

        case X87Constant::kPi: {  // fldpi
            state->push();
            state->setSt(0, std::bit_cast<double>(0x400921FB54442D18ULL));
        } break;

        case X87Constant::kLog2e: {  // fldl2e
            state->push();
            state->setSt(0, std::bit_cast<double>(0x3FF71547652B82FEULL));
        } break;

        case X87Constant::kLoge2: {  // fldln2
            state->push();
            state->setSt(0, std::bit_cast<double>(0x3FE62E42FEFA39EFULL));
        } break;

        case X87Constant::kLog2t: {  // fldl2t
            state->push();
            state->setSt(0, std::bit_cast<double>(0x400A934F0979A371ULL));
        } break;

        case X87Constant::kLog102: {  // fldlg2
            state->push();
            state->setSt(0, std::bit_cast<double>(0x3FD34413509F79FFULL));
        } break;

        default: {
            // simplePrintf("x87_fld_constant ERROR %d\n", (int)val);
        } break;
    }
}

void x87_fld_fp32(X87State* state, uint32_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fld_fp32\n", 14);

    // Push new value onto stack, get reference to new top
    state->push();

    state->setSt(0, std::bit_cast<float>(val));
}

void x87_fld_fp64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fld_fp64\n", 14);

    // Push new value onto stack, get reference to new top
    state->push();

    state->setSt(0, std::bit_cast<double>(val));
}

void x87_fld_fp80(X87State* state, X87Float80 val) {
    SIMDGuard simdGuard;
    LOG(1, "x87_fld_fp80\n", 14);

    auto ieee754 = ConvertX87RegisterToFloat64(val, &state->statusWord);

    state->push();
    state->setSt(0, ieee754);
}

void x87_fmul_ST(X87State* state, uint32_t st_offset_1, uint32_t st_offset_2, bool pop_stack) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fmul_ST\n", 13);

    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset_1);
    const auto val2 = state->getStFast(st_offset_2);

    // Perform multiplication and store result
    state->setStFast(st_offset_1, val1 * val2);

    if (pop_stack) {
        state->pop();
    }
}

void x87_fmul_f32(X87State* state, uint32_t fp32) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fmul_f32\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(fp32);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 * value);
}

void x87_fmul_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fmul_f64\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 * value);
}

void x87_fpatan(X87State* state) {
    SIMDGuardFull simdGuard;

    LOG(1, "x87_fpatan\n", 12);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get values from ST(0) and ST(1)
    auto st0 = state->getSt(0);
    auto st1 = state->getSt(1);

    // Calculate arctan(ST(1)/ST(0))
    auto result = openlibm_atan2(st1, st0);

    // Store result in ST(1) and pop the register stack
    state->setSt(1, result);

    state->pop();
}

void x87_fprem(X87State* state) {
    SIMDGuardAndX0X7 simdGuard;
    LOG(1, "x87_fprem\n", 11);

    // 1) Clear CC0–CC3
    state->statusWord &= ~(kConditionCode0 | kConditionCode1 | kConditionCode2 | kConditionCode3);

    double st0 = state->getSt(0);
    double st1 = state->getSt(1);

    // 2) Special cases: NaN/div0/∞ → #IA, ∞ divisor → pass through
    if (x87_is_nan(st0) || x87_is_nan(st1) || x87_is_inf(st0) || st1 == 0.0) {
        state->setSt(0, std::numeric_limits<double>::quiet_NaN());
        state->statusWord |= kInvalidOperation;
        return;
    }
    if (isinf(st1)) {
        // remainder = dividend; no exception
        return;
    }

    // 3) Compute truncated quotient and remainder
    double rawDiv = st0 / st1;
    double truncDiv = std::trunc(rawDiv);  // Q = trunc(ST0/ST1)
    int q = static_cast<int>(truncDiv);
    double rem = openlibm_fmod(st0, st1);  // rem = ST0 - Q*ST1
    state->setSt(0, rem);

    // 4) CC0, CC1, CC3 ← low bits of Q (Q2→CC0, Q0→CC1, Q1→CC3)
    if (q & 0x4)
        state->statusWord |= kConditionCode0;
    if (q & 0x1)
        state->statusWord |= kConditionCode1;
    if (q & 0x2)
        state->statusWord |= kConditionCode3;

    // 5) CC2 “incomplete” if exponent gap > 0
    //    D = E0 – E1; E = std::ilogb(x)
    int e0 = openlibm_ilogb(st0);
    int e1 = openlibm_ilogb(st1);
    int D = e0 - e1;
    if (D > 0) {
        state->statusWord |= kConditionCode2;
        // (optional) you could iterate: rem -= std::ldexp(trunc(rem/st1), D);
    }
}

void x87_fprem1(X87State* state) {
    SIMDGuardAndX0X7 simdGuard;
    LOG(1, "x87_fprem1\n", 12);

    // 1) clear condition-code bits CC0–CC3
    state->statusWord &= ~(kConditionCode0 | kConditionCode1 | kConditionCode2 | kConditionCode3);

    double st0 = state->getSt(0);
    double st1 = state->getSt(1);

    // 2) special cases: NaN/div0/∞ → #IA or pass through
    if (x87_is_nan(st0) || x87_is_nan(st1) || x87_is_inf(st0) || st1 == 0.0) {
        state->setSt(0, std::numeric_limits<double>::quiet_NaN());
        state->statusWord |= kInvalidOperation;
        return;
    }
    if (isinf(st1)) {
        // remainder = dividend; no exception
        return;
    }

    // 3) IEEE-754 remainder with nearest-integer quotient
    int q;
    double rem = openlibm_remquo(st0, st1, &q);
    // rem = ST0 – q*ST1, where q = round-to-nearest(ST0/ST1), ties-to-even
    state->setSt(0, rem);

    // 4) CC0, CC1, CC3 from the three low bits of q:
    //    Q2→CC0, Q0→CC1, Q1→CC3
    if (q & 0x4)
        state->statusWord |= kConditionCode0;
    if (q & 0x1)
        state->statusWord |= kConditionCode1;
    if (q & 0x2)
        state->statusWord |= kConditionCode3;

    // 5) CC2 = “incomplete” flag based on exponent diff D = E0 – E1
    int e0 = openlibm_ilogb(st0);  // unbiased exponent of st0
    int e1 = openlibm_ilogb(st1);  // unbiased exponent of st1
    int D = e0 - e1;
    if (D >= 64) {
        state->statusWord |= kConditionCode2;
        // (optional) do the “partial” reduction loop per spec if you want
        // hardware-accurate step-wise remainder
    }
    // else D<64 ⇒ CC2 stays clear (complete reduction)
}

void x87_fptan(X87State* state) {
    SIMDGuardFullAndX0X7 simdGuard;

    LOG(1, "x87_fptan\n", 11);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1 | X87StatusWordFlag::kConditionCode2);

    // Get value from ST(0)
    const auto value = state->getSt(0);

    // Calculate tangent
    auto tan_value = openlibm_tan(value);

    // Store result in ST(0)
    state->setSt(0, tan_value);

    // Push 1.0 onto the FPU register stack
    state->push();
    state->setSt(0, 1.0);
}

void x87_frndint(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_frndint\n", 13);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get current value and round it
    double value = state->getStFast(0);
    double rounded;
    auto round_bits = state->controlWord & X87ControlWord::kRoundingControlMask;

    switch (round_bits) {
        case X87ControlWord::kRoundToNearest: {
            rounded = std::nearbyint(value);
        } break;

        case X87ControlWord::kRoundDown: {
            rounded = std::floor(value);
        } break;

        case X87ControlWord::kRoundUp: {
            rounded = std::ceil(value);
        } break;

        case X87ControlWord::kRoundToZero: {
            rounded = std::trunc(value);
        } break;
    }

    // Store rounded value and update tag
    state->setStFast(0, rounded);
}

void x87_fscale(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fscale\n", 12);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get values from ST(0) and ST(1)
    double st0 = state->getSt(0);
    double st1 = state->getSt(1);

    // Round ST(1) to nearest integer
    int scale = static_cast<int>(st1);

    // Scale ST(0) by 2^scale using bit manipulation for integer powers
    int32_t exponent = scale + 1023;  // IEEE-754 bias
    uint64_t scaleFactor = static_cast<uint64_t>(exponent) << 52;
    double factor = std::bit_cast<double>(scaleFactor);

    // Multiply ST(0) by scale factor
    double result = st0 * factor;

    // Store result back in ST(0)
    state->setSt(0, result);
}

void x87_fsin(X87State* state) {
    SIMDGuardFullAndX0X7 simdGuard;

    LOG(1, "x87_fsin\n", 10);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1 | X87StatusWordFlag::kConditionCode2);

    // Get current value from top register
    const double value = state->getStFast(0);

    // Store result and update tag
    state->setStFast(0, openlibm_sin(value));
}

void x87_fsincos(X87State* state) {
    SIMDGuardFullAndX0X7 simdGuard;

    LOG(1, "x87_fsincos\n", 13);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1 | X87StatusWordFlag::kConditionCode2);

    // Get value from ST(0)
    const auto value = state->getStFast(0);

    // Calculate sine and cosine
    auto sin_value = openlibm_sin(value);
    auto cos_value = openlibm_cos(value);

    // Store sine in ST(0)
    state->setStFast(0, sin_value);

    // Push cosine onto the FPU register stack
    state->push();
    state->setStFast(0, cos_value);

    // Clear C2 condition code bit
    state->statusWord &= ~X87StatusWordFlag::kConditionCode2;
}

void x87_fsqrt(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsqrt\n", 11);

    state->statusWord &= ~(X87StatusWordFlag::kConditionCode1);

    // Get current value and calculate sqrt
    const double value = state->getStFast(0);

    state->statusWord |= X87StatusWordFlag::kPrecision;

    // Store result and update tag
    state->setStFast(0, sqrt(value));
}

void x87_fst_STi(X87State* state, uint32_t st_offset, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fst_STi\n", 13);

    // Clear C1 condition code (bit 9)
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Copy ST(0) to ST(i)
    state->setSt(st_offset, state->getSt(0));

    // Pop if requested
    if (pop) {
        state->pop();
    }
}

X87ResultStatusWord x87_fst_fp32(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fst_fp32\n", 14);

    auto [value, statusWord] = state->getStConst32(0);
    float tmp = value;
    return {std::bit_cast<uint32_t>(tmp), statusWord};
}

X87ResultStatusWord x87_fst_fp64(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fst_fp64\n", 14);

    // Create temporary double to ensure proper value representation
    auto [value, statusWord] = state->getStConst(0);
    double tmp = value;
    return {std::bit_cast<uint64_t>(tmp), statusWord};
}

X87Float80StatusWordResult x87_fst_fp80(X87State const* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fst_fp80\n", 14);

    // Get value from ST(0)
    auto [value, statusWord] = state->getStConst(0);

    uint64_t bits = std::bit_cast<uint64_t>(value);

    // Extract components from double (64-bit IEEE 754)
    uint64_t mantissa = bits & 0xFFFFFFFFFFFFFULL;  // 52 bits
    uint32_t exp = (bits >> 52) & 0x7FF;             // 11 bits
    uint16_t sign = (uint16_t)((bits >> 63) << 15);  // Move sign to bit 15

    X87Float80StatusWordResult result;
    result.statusWord = statusWord;

    // Handle zero / denormal (treated as ±0.0)
    if (exp == 0) {
        result.mantissa = 0;
        result.exponent = sign;
        return result;
    }

    // Handle infinity or NaN
    if (exp == 0x7FF) {
        result.mantissa = (mantissa << 11) | 0x8000000000000000ULL;
        result.exponent = sign | 0x7FFF;
        return result;
    }

    // Normal numbers: Convert to x87 format
    // Shift 52-bit mantissa to 63-bit position and set explicit integer bit
    result.mantissa = (mantissa << 11) | 0x8000000000000000ULL;

    // Bias adjustment: IEEE 754 double bias(1023) to x87 bias(16383)
    result.exponent = sign | (uint16_t)(exp + 16383 - 1023);

    return result;
}

void x87_fsub_ST(X87State* state, uint32_t st_offset1, uint32_t st_offset2, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsub_ST\n", 13);

    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset1);
    const auto val2 = state->getStFast(st_offset2);

    // Perform subtraction and store result in ST(st_offset1)
    state->setStFast(st_offset1, val1 - val2);

    if (pop) {
        state->pop();
    }
}

void x87_fsub_f32(X87State* state, uint32_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsub_f32\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 - value);
}

void x87_fsub_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsub_f64\n", 14);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, st0 - value);
}

void x87_fsubr_ST(X87State* state, uint32_t st_offset1, uint32_t st_offset2, bool pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsubr_ST\n", 14);

    // Clear condition code 1 and exception flags
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get register indices and values
    const auto val1 = state->getStFast(st_offset1);
    const auto val2 = state->getStFast(st_offset2);

    // Perform reversed subtraction and store result in ST(st_offset1)
    state->setStFast(st_offset1, val2 - val1);

    if (pop) {
        state->pop();
    }
}

void x87_fsubr_f32(X87State* state, unsigned int val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsubr_f32\n", 15);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<float>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, value - st0);
}

void x87_fsubr_f64(X87State* state, uint64_t val) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fsubr_f64\n", 15);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto value = std::bit_cast<double>(val);
    auto st0 = state->getStFast(0);

    state->setStFast(0, value - st0);
}

void x87_fucom(X87State* state, uint32_t st_offset, uint32_t pop) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fucom\n", 11);
    auto st0 = state->getSt(0);
    auto src = state->getSt(st_offset);

    // Clear condition code bits C0, C2, C3 (bits 8, 9, 14)
    state->statusWord &= ~(kConditionCode0 | kConditionCode2 | kConditionCode3);

    // Set condition codes based on comparison
    if (x87_is_nan(st0) || x87_is_nan(src)) {
        state->statusWord |= kConditionCode0 | kConditionCode2 | kConditionCode3;  // Set C0=C2=C3=1
    } else if (st0 > src) {
        // Leave C0=C2=C3=0
    } else if (st0 < src) {
        state->statusWord |= kConditionCode0;  // Set C0=1
    } else {                                   // st0 == src
        state->statusWord |= kConditionCode3;  // Set C3=1
    }

    // Handle pops if requested
    for (auto i = 0; i < pop; ++i) {
        state->pop();
    }
}



uint32_t x87_fucomi(X87State* state, uint32_t st_offset, bool pop_stack) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fucomi\n", 12);

    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto st0_val = state->getSt(0);
    auto sti_val = state->getSt(st_offset);

    uint32_t flags = 0;
    /*
    Filters: fcomi
    Randomness seeded to: 3528984885
    x87_fcomi_less
    x87_fcomi result: 0x000000000000000
    x87_fcomi_greater
    x87_fcomi result: 0x000000020000000
    x87_fcomi_equal
    x87_fcomi result: 0x000000060000000
    */

    if (x87_is_nan(st0_val) || x87_is_nan(sti_val)) {
        flags = 0x54000000;  // unordered: bit26=PF for x87_fcmov path, V=1 for translated fcsel VS/VC path
    } else if (st0_val < sti_val) {
        flags = 0x000000000000000;
    } else if (st0_val > sti_val) {
        flags = 0x000000020000000;
    } else {
        flags = 0x000000060000000;
    }

    if (pop_stack) {
        state->pop();
    }

    return flags;
}

void x87_fxam(X87State* state) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fxam\n", 10);

    // Get tag state for ST(0)
    X87TagState tag = state->getStTag(0);

    // simplePrintf("tag: %d\n", tag);

    static_assert((X87StatusWordFlag::kConditionCode0 | X87StatusWordFlag::kConditionCode1 |
                   X87StatusWordFlag::kConditionCode2 | X87StatusWordFlag::kConditionCode3) ==
                  0x4700);

    // Clear C3,C2,C1,C0 bits
    state->statusWord &= ~(X87StatusWordFlag::kConditionCode0 | X87StatusWordFlag::kConditionCode1 |
                           X87StatusWordFlag::kConditionCode2 | X87StatusWordFlag::kConditionCode3);

    // Handle empty and zero based on tag word
    if (tag == X87TagState::kEmpty) {
        state->statusWord |= X87StatusWordFlag::kConditionCode3 |
                             X87StatusWordFlag::kConditionCode0;  // C3=1, C0=1 (101)
        return;
    }
    if (tag == X87TagState::kZero) {
        state->statusWord |= X87StatusWordFlag::kConditionCode3;  // C3=1 (100)
        return;
    }

    // Get actual value for other cases
    auto value = state->getSt(0);

    // Set C1 based on sign
    if (signbit(value)) {
        state->statusWord |= X87StatusWordFlag::kConditionCode1;
    }

    // Set C3,C2,C0 based on value type
    // NOTE: also check value == 0.0 here because the inline JIT fld path sets
    // kValid tags for all pushed values (including zero), so kZero may never
    // be set even for a genuine zero.
    if (value == 0.0) {
        state->statusWord |= X87StatusWordFlag::kConditionCode3;  // 100 (zero)
    } else if (x87_is_nan(value)) {
        state->statusWord |= X87StatusWordFlag::kConditionCode0;  // 001
    } else if (x87_is_inf(value)) {
        state->statusWord |=
            X87StatusWordFlag::kConditionCode2 | X87StatusWordFlag::kConditionCode0;  // 011
    } else if (x87_is_subnormal(value)) {
        state->statusWord |=
            X87StatusWordFlag::kConditionCode3 | X87StatusWordFlag::kConditionCode2;  // 110
    } else {
        state->statusWord |= X87StatusWordFlag::kConditionCode2;  // 010 (normal)
    }
}

void x87_fxch(X87State* state, uint32_t st_offset) {
    SIMDGuard simdGuard;

    LOG(1, "x87_fxch\n", 10);

    // Clear condition code 1
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    auto st0 = state->getSt(0);
    auto sti = state->getSt(st_offset);

    state->setSt(0, sti);
    state->setSt(st_offset, st0);
}

void x87_fxtract(X87State* state) {
    SIMDGuardFull simdGuard;

    LOG(1, "x87_fxtract\n", 13);

    auto st0 = state->getSt(0);

    // If the floating-point zero-divide exception (#Z) is masked and the source
    // operand is zero, an exponent value of –∞ is stored in register ST(1) and 0
    // with the sign of the source operand is stored in register ST(0).
    if ((state->controlWord & X87ControlWord::kZeroDivideMask) != 0 && st0 == 0.0) {
        state->setSt(1, -std::numeric_limits<double>::infinity());
        state->setSt(0, copysign(0.0, st0));
        return;
    }

    if (isinf(st0)) {
        state->setSt(0, st0);
        state->push();
        state->setSt(0, std::numeric_limits<double>::infinity());
        return;
    }

    auto e = std::floor(openlibm_log2(abs(st0)));
    auto m = st0 / openlibm_pow(2.0, e);

    state->setSt(0, e);

    state->push();
    state->setSt(0, m);
}

static inline __attribute__((always_inline)) void fyl2x_common(X87State* state, double constant) {
    // Clear condition code 1
    state->statusWord &= ~X87StatusWordFlag::kConditionCode1;

    // Get x from ST(0) and y from ST(1)
    auto st0 = state->getSt(0);
    auto st1 = state->getSt(1);

    // Calculate y * log2(x)
    auto result = st1 * (openlibm_log2(st0 + constant));

    // Pop ST(0)
    state->pop();

    // Store result in new ST(0)
    state->setSt(0, result);
}

// Replace ST(1) with (ST(1) ∗ log2ST(0)) and pop the register stack.
void x87_fyl2x(X87State* state) {
    SIMDGuardFull simdGuard;
    LOG(1, "x87_fyl2x\n", 12);

    fyl2x_common(state, 0.0);
}

// Replace ST(1) with (ST(1) ∗ log2ST(0 + 1.0)) and pop the register stack.
void x87_fyl2xp1(X87State* state) {
    SIMDGuardFull simdGuard;
    LOG(1, "x87_fyl2xp1\n", 14);

    fyl2x_common(state, 1.0);
}

X87_TRAMPOLINE(sse_pcmpestri, x9)
X87_TRAMPOLINE(sse_pcmpestrm, x9)
X87_TRAMPOLINE(sse_pcmpistri, x9)
X87_TRAMPOLINE(sse_pcmpistrm, x9)
X87_TRAMPOLINE(is_ldt_initialized, x9)
X87_TRAMPOLINE(get_ldt, x9)
X87_TRAMPOLINE(set_ldt, x9)
X87_TRAMPOLINE(execution_mode_for_code_segment_selector, x9)
X87_TRAMPOLINE(mov_segment, x9)
X87_TRAMPOLINE(abi_for_address, x9)

X87_TRAMPOLINE(determine_state_recovery_action, x9)
X87_TRAMPOLINE(get_segment_limit, x9)
X87_TRAMPOLINE(translator_set_variant, x9)

void x87_set_init_state(X87State* state) {
    SIMDGuard simdGuard;
    LOG(1, "x87_set_init_state\n", 9);

    state->controlWord = 0x037F;
    state->statusWord = 0x0000;
    state->tagWord = 0xFFFF;
    for (int i = 0; i < 8; i++) {
        state->st[i].ieee754 = 0.0;
    }
}

X87_TRAMPOLINE(runtime_cpuid, x22)
X87_TRAMPOLINE(runtime_wide_udiv_64, x9)
X87_TRAMPOLINE(runtime_wide_sdiv_64, x9)
