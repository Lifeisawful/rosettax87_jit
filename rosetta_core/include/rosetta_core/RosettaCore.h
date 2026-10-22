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

// Seeds the runtime version on its own, ahead of rosetta_core_init.
//
// rosetta_core_init can only run from init_library, because the addresses it also
// installs (translate_insn and friends) are not knowable until libRosettaRuntime
// is bound. But the runtime's main() creates the first ExecutableHeap chunk
// BEFORE it calls init_library, so anything choosing a version-dependent ABI at
// _start time — ExecutableHeap's allocate_chunk hook — would otherwise see 0 here.
// The loader seeds kImports.version before it runs our _start, so the value is
// already available; this publishes it early. rosetta_core_init overwrites it with
// the same value later, so calling both is harmless.
void rosetta_core_set_runtime_version(uint64_t runtime_version);

uint64_t rosetta_core_runtime_version();
