#pragma once

#include <cstddef>
#include <cstdint>

enum FixupKind : uint8_t {
    Abs64 = 0,              // absolute 64-bit address patch
    Branch26 = 1,           // B/BL — 26-bit PC-relative ±128 MB
    Branch19 = 2,           // B.cond/CBZ/CBNZ — 19-bit PC-relative ±1 MB
    Branch14 = 3,           // TBZ/TBNZ — 14-bit PC-relative ±32 KB
    Arm64Adr21 = 4,         // ADR — 21-bit PC-relative (immediate)
    Arm64Page21 = 5,        // ADRP — page-granular ±4 GB (paired with PageOffset12)
    Arm64PageOffset12 = 6,  // ADD/LDR/STR imm12 page offset (paired with Page21)
};

// ── FixupRecord ───────────────────────────────────────────────────────────────
// 12-byte record. The first 8 bytes are written atomically as a uint64_t in
// push_back (the packed insn_offset_and_kind argument).
struct Fixup {
    FixupKind kind;        // +0x00
    uint32_t insn_offset;  // +0x04  byte offset into insn_buf
    uint32_t target;       // +0x08  x86 addr, runtime id, or branch target
};

static_assert(sizeof(Fixup) == 12, "Fixup must be 12 bytes");
static_assert(offsetof(Fixup, insn_offset) == 4, "insn_offset at +4");
static_assert(offsetof(Fixup, target) == 8, "target at +8");
