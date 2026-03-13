#pragma once

#include <cstdint>
#include <optional>

struct TranslationResult;
struct IRInstr;

namespace TranslatorX87 {

// Single entry point for all peephole fusion patterns.
// Returns total instructions consumed (≥2 for any fusion),
// or std::nullopt if no fusion matched (caller translates the current instruction alone).
// disabled_mask: bitmask of FusionId bits to skip (0 = all enabled).
auto try_peephole(TranslationResult* tr, IRInstr* instrs, int64_t num, int64_t idx,
                  uint64_t disabled_mask = 0) -> std::optional<int>;

}  // namespace TranslatorX87
