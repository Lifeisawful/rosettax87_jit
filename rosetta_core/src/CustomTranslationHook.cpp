#include "rosetta_core/CustomTranslationHook.h"

#include "rosetta_core/CoreLog.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/X87BackEdge.h"
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

static const CustomTranslationHook* g_translation_hook = nullptr;

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr,
                                  uintptr_t default_free_gpr_mask_addr,
                                  uintptr_t free_temporary_gpr_addr,
                                  const CustomTranslationHook* hook) {
    g_translation_hook = hook;
    original_translate_insn = reinterpret_cast<translate_insn_t>(translate_insn_addr);
    hook_install(reinterpret_cast<void*>(original_translate_insn),
                 reinterpret_cast<void*>(hook_translate_insn),
                 reinterpret_cast<void**>(&original_translate_insn));

    patch_movz_imm((void*)transaction_result_size_addr, 0x400);

    // NOP out the STR that overwrites the free-GPR mask so we can track and
    // reset it ourselves (bridge feature). Only aotinvoke supplies this; the
    // runtime hook path passes 0.
    if (default_free_gpr_mask_addr != 0) {
        patch_nop((void*)default_free_gpr_mask_addr, 1);
    }

    // Neuter free_temporary_gpr by turning its entry into an immediate RET so
    // scratch GPRs are never returned to the pool during translation. Only
    // aotinvoke supplies this; the runtime hook path passes 0.
    if (free_temporary_gpr_addr != 0) {
        patch_ret((void*)free_temporary_gpr_addr);
    }
}

int64_t hook_translate_insn(TranslationResult* result, IRBlock* block, IRInstr* instr_array,
                            int64_t num_instrs, int64_t insn_idx) {
    if (g_translation_hook && g_translation_hook->before)
        g_translation_hook->before(result, block, instr_array, num_instrs, insn_idx);

    auto new_insn_idx =
        Translator::translate_instruction(result, block, instr_array, num_instrs, insn_idx);

    int64_t result_idx;
    if (new_insn_idx.has_value()) {
        result_idx = new_insn_idx.value();
    } else {
        // OPT-BE: withhold a qualifying self-loop block's pinned registers
        // from Rosetta's allocator for this stock-translated instruction.
        // The GPR exclusion is undone by the mask reset below; the FPR mask
        // has no per-instruction reset, so save and restore it explicitly.
        uint32_t gpr_pins = 0, fpr_pins = 0;
        x87_backedge_gap_pins(result, block, &gpr_pins, &fpr_pins);
        const uint32_t saved_fpr_mask = result->free_fpr_mask;
        result->free_gpr_mask &= ~gpr_pins;
        result->free_fpr_mask &= ~fpr_pins;
        result_idx = original_translate_insn(result, block, instr_array, num_instrs, insn_idx);
        result->free_fpr_mask = saved_fpr_mask;
    }

    if (g_translation_hook && g_translation_hook->after)
        g_translation_hook->after(result, block, instr_array, num_instrs, insn_idx, result_idx);

    // custom translation pipeline skipped it, stock implementation translated this
    if (!new_insn_idx.has_value()) {
        // do what has been patch out - reset gpr scratch mask
        result->free_gpr_mask = kGprScratchMask;
    }

    return result_idx;
}