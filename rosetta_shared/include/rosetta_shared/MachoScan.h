#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <ranges>
#include <string_view>
#include <vector>

// Signature scanning + AArch64 instruction decoding shared by rosetta_loader and
// available to aotinvoke. `findPattern` takes a space-separated hex-byte string
// where `?` is a wildcard, e.g. "FD 43 07 91 ? ?".
namespace rosetta_shared {

// `optional` suppresses the "not found" diagnostic, for patterns whose absence is
// a legitimate outcome rather than a failure — e.g. a sequence that only exists on
// some Rosetta versions, where the caller decides whether missing is fatal.
inline auto findPattern(const std::vector<uint8_t>& haystack, std::string_view pattern,
                        const char* name, bool optional = false) -> std::optional<uint64_t> {
    struct PatternByte {
        uint8_t value;
        bool wildcard;
    };

    std::vector<PatternByte> parsed;

    for (auto token : std::views::split(pattern, ' ')) {
        std::string_view sv{token.begin(), token.end()};
        if (sv.empty())
            continue;
        if (sv[0] == '?') {
            parsed.push_back({0, true});
        } else {
            uint8_t val = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), val, 16);
            parsed.push_back({val, false});
        }
    }

    if (parsed.empty())
        return std::nullopt;

    auto it = std::search(
        haystack.begin(), haystack.end(), parsed.begin(), parsed.end(),
        [](uint8_t byte, const PatternByte& pat) { return pat.wildcard || byte == pat.value; });

    if (it != haystack.end())
        return static_cast<uint64_t>(std::distance(haystack.begin(), it));

    if (!optional)
        fprintf(stderr, "%s pattern not found.\n", name);
    return std::nullopt;
}

namespace aarch64 {

inline auto decodeAdrp(uint32_t insn, uint64_t pc) -> uint64_t {
    uint64_t immlo = (insn >> 29) & 0x3;
    uint64_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm = static_cast<int64_t>((immhi << 2) | immlo) << 12;
    if (imm & (1ULL << 32))
        imm |= ~((1ULL << 33) - 1);
    return (pc & ~0xFFFULL) + imm;
}

inline auto decodeLdrbImm(uint32_t insn) -> uint64_t {
    return (insn >> 10) & 0xFFF;
}

// ADD Xd, Xn, #imm{, LSL #12} — the immediate only. Pairs with decodeAdrp to
// recover the full address an ADRP/ADD (clang's ADRL macro) materialises.
inline auto decodeAddImm(uint32_t insn) -> uint64_t {
    uint64_t imm12 = (insn >> 10) & 0xFFF;
    if ((insn >> 22) & 1)
        imm12 <<= 12;
    return imm12;
}

inline auto decodeBl(uint32_t insn, uint64_t pc) -> uint64_t {
    int32_t imm26 = insn & 0x03FFFFFF;
    if (imm26 & (1 << 25))
        imm26 |= ~0x03FFFFFF;
    return pc + (static_cast<int64_t>(imm26) << 2);
}

}  // namespace aarch64

}  // namespace rosetta_shared
