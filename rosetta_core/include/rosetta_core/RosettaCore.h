#pragma once

#include <cstdint>

struct CustomTranslationHook;

struct RosettaCoreConfig {
    uint64_t  runtime_version;
    uintptr_t translate_insn_addr;
    uintptr_t transaction_result_size_addr;
    uintptr_t decode_opcode_addr;
    uintptr_t default_free_gpr_mask_addr;
    uintptr_t free_temporary_gpr_addr;
    // Optional observer fired around original_translate_insn. Null = no hook.
    // The pointee must outlive translation.
    const CustomTranslationHook* translation_hook = nullptr;
};

void rosetta_core_init(const RosettaCoreConfig& config);

uint64_t rosetta_core_runtime_version();
