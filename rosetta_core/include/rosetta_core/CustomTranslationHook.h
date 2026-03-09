#pragma once

#include <cstdint>

#include "rosetta_core/IRBlock.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/TranslationResult.h"

using translate_insn_t = int64_t (*)(TranslationResult* a1, IRBlock* a2, IRInstr* a3,
                                     int64_t num_instrs, int64_t insn_idx);

extern translate_insn_t g_translate_insn;

void init_custom_translation_hook(uintptr_t translate_insn_addr,
                                  uintptr_t transaction_result_size_addr);

int64_t hook_translate_insn(TranslationResult* a1, IRBlock* a2, IRInstr* instr_array,
                            int64_t num_instrs, int64_t insn_idx);
