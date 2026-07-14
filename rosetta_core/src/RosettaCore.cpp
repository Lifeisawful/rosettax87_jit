#include "rosetta_core/RosettaCore.h"

#include "rosetta_config/Config.h"
#include "rosetta_core/ClassifyArmPCHook.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CustomTranslationHook.h"
#include "rosetta_core/DecodeOpcodeHook.h"

static uint64_t g_runtime_version = 0;

void rosetta_core_init(const RosettaCoreConfig& config) {
    g_runtime_version = config.runtime_version;
    const auto* cfg = g_rosetta_config;
    if (!(cfg && cfg->disable_translate_hook)) {
        init_custom_translation_hook(config.translate_insn_addr,
                                     config.transaction_result_size_addr);
    }
    if (!(cfg && cfg->disable_classify_hook)) {
        init_classify_arm_pc_hook(config.classify_arm_pc_addr, config.rosettax87_base,
                                  config.rosettax87_size);
    }
    if (!(cfg && cfg->disable_decode_hook)) {
        init_decode_opcode_hook(config.decode_opcode_addr);
    }
}

uint64_t rosetta_core_runtime_version() {
    return g_runtime_version;
}
