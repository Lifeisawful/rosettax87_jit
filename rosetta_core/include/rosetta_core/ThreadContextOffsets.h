#pragma once

#include <cstddef>
#include <cstdint>

struct ThreadContextOffsets {
    uint32_t debug_regs_offset;
    uint32_t translator_variant_offset;
    uint32_t fs_base_offset;
    uint32_t vtable_offset;
    uint32_t segment_selectors_offset;
    uint32_t x87_state_offset;
    uint32_t field_18;
};

static_assert(sizeof(ThreadContextOffsets) == 0x1c);
static_assert(offsetof(ThreadContextOffsets, debug_regs_offset) == 0x00);
static_assert(offsetof(ThreadContextOffsets, translator_variant_offset) == 0x04);
static_assert(offsetof(ThreadContextOffsets, fs_base_offset) == 0x08);
static_assert(offsetof(ThreadContextOffsets, vtable_offset) == 0x0C);
static_assert(offsetof(ThreadContextOffsets, segment_selectors_offset) == 0x10);
static_assert(offsetof(ThreadContextOffsets, x87_state_offset) == 0x14);
static_assert(offsetof(ThreadContextOffsets, field_18) == 0x18);
