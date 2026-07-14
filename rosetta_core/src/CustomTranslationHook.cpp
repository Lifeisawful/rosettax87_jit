#include "rosetta_core/CustomTranslationHook.h"

#include "rosetta_config/Config.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/Translator.h"
#include "rosetta_core/hook.h"

// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on

using translate_insn_t = int64_t (*)(TranslationResult* a1, IRBlock* a2, IRInstr* a3,
                                     int64_t num_instrs, int64_t insn_idx);

int64_t hook_translate_insn(TranslationResult* a1, IRBlock* a2, IRInstr* instr_array,
                            int64_t num_instrs, int64_t insn_idx);

translate_insn_t original_translate_insn = nullptr;

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr) {
    original_translate_insn = reinterpret_cast<translate_insn_t>(translate_insn_addr);
    hook_install(reinterpret_cast<void*>(original_translate_insn),
                 reinterpret_cast<void*>(hook_translate_insn),
                 reinterpret_cast<void**>(&original_translate_insn));

    if (!(g_rosetta_config && g_rosetta_config->disable_size_patch)) {
        patch_movz_imm((void*)transaction_result_size_addr, 0x400);
    }
}

int64_t hook_translate_insn(TranslationResult* result, IRBlock* block, IRInstr* instr_array,
                            int64_t num_instrs, int64_t insn_idx) {
    auto new_insn_idx =
        Translator::translate_instruction(result, block, instr_array, num_instrs, insn_idx);

    if (new_insn_idx.has_value()) {
        return *new_insn_idx;
    }

    return original_translate_insn(result, block, instr_array, num_instrs, insn_idx);
}