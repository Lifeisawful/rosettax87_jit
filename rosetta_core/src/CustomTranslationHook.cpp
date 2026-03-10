#include "rosetta_core/CustomTranslationHook.h"

#include "rosetta_core/CoreLog.h"
#include "rosetta_core/Translator.h"
#include "rosetta_core/hook.h"

// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on

translate_insn_t original_translate_insn = nullptr;

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr) {
    original_translate_insn = reinterpret_cast<translate_insn_t>(translate_insn_addr);
    hook_install(reinterpret_cast<void*>(original_translate_insn),
                 reinterpret_cast<void*>(hook_translate_insn),
                 reinterpret_cast<void**>(&original_translate_insn));

    patch_movz_imm((void*)transaction_result_size_addr, 0x400);
}

int64_t hook_translate_insn(TranslationResult* result, IRBlock* block, IRInstr* instr_array,
                            int64_t num_instrs, int64_t insn_idx) {
    auto new_insn_idx =
        Translator::translate_instruction(result, block, instr_array, num_instrs, insn_idx);

    if (new_insn_idx.has_value()) {
        return new_insn_idx.value();
    }
#if defined(ROSETTA_RUNTIME)
    static bool reset_executable_flag = false;
    // for some reason original_translate_insn page is flipped back to non-executable ...
    if (reset_executable_flag != true) {
        // CORE_LOG("Making original_translate_insn executable at address %p",
        // (void*)original_translate_insn);
        make_page_executable((void*)original_translate_insn);
        reset_executable_flag = true;
    }
#endif

    return original_translate_insn(result, block, instr_array, num_instrs, insn_idx);
}