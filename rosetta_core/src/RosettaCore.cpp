#include "rosetta_core/RosettaCore.h"

#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/DecodeOpcodeHook.h"

static uint64_t g_runtime_version = 0;

void rosetta_core_init(const RosettaCoreConfig& config) {
    g_runtime_version = config.runtime_version;
    init_custom_translation_hook(config.translate_insn_addr, config.transaction_result_size_addr,
                                 config.default_free_gpr_mask_addr, config.free_temporary_gpr_addr,
                                 config.translation_hook);
    init_decode_opcode_hook(config.decode_opcode_addr);
}

uint64_t rosetta_core_runtime_version() {
    return g_runtime_version;
}
