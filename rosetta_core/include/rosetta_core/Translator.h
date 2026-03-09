#pragma once

#include <cstdint>
#include <optional>

struct TranslationResult;
struct IRBlock;
struct IRInstr;

namespace Translator {
auto translate_instruction(TranslationResult* translation_result, IRBlock* block,
                           IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx)
    -> std::optional<int64_t>;
};