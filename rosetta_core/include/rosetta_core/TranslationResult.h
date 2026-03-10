#pragma once

#include <cstdint>

#include "rosetta_core/AssemblerBuffer.h"
#include "rosetta_core/Fixup.h"
#include "rosetta_core/IRModuleData.h"
#include "rosetta_core/ThreadContextOffsets.h"
#include "rosetta_core/TransactionalList.h"

struct IRBlock;

struct TranslationResult {
    IRModuleData* ir_module_data;
    char _mode;
    char field_9;
    char field_A;
    char field_B;
    char field_C;
    char field_D;
    char field_E;
    char field_F;
    AssemblerBuffer insn_buf;
    uint32_t text_base_align_offset;
    uint32_t field_34;
    uint64_t arm_to_x86_map_begin;
    uint64_t arm_to_x86_map_end;
    uint64_t field_48;
    TransactionalList<Fixup> external_fixups;  ///< ADR+ADD for x86 abs addr reloc
    TransactionalList<Fixup> internal_fixups;  ///< Internal branch patch-ups
    TransactionalList<Fixup> _fixups;          ///< BL into runtime helper stubs
    TransactionalList<Fixup> field_B0;
    TransactionalList<Fixup> dyld_stub_fixups;  ///< dyld stub GOT-style relocations
    uint64_t field_F0;
    uint64_t field_F8;
    uint64_t field_100;
    uint64_t field_108;
    uint64_t field_110;
    uint64_t field_118;
    uint64_t field_120;
    uint64_t field_128;
    uint64_t field_130;
    uint64_t field_138;
    uint64_t field_140;
    uint64_t field_148;
    uint64_t field_150;
    uint64_t field_158;
    uint64_t field_160;
    uint64_t field_168;
    uint64_t field_170;
    uint64_t field_178;
    uint64_t field_180;
    uint64_t field_188;
    uint32_t field_190;
    uint32_t field_194;
    uint32_t field_198;
    uint32_t field_19C;
    uint32_t field_1A0;
    uint32_t max_translated_x86_pc;
    TransactionalList<Fixup> field_1A8;  ///< Cross-block/sequential fixups
    uint64_t field_1C8;
    uint64_t field_1D0;
    uint64_t field_1D8;
    uint64_t field_1E0;
    uint64_t field_1E8;
    uint64_t field_1F0;
    uint64_t field_1F8;
    uint64_t field_200;
    uint64_t field_208;
    uint32_t free_gpr_mask;
    uint32_t free_fpr_mask;
    uint32_t _unoccupied_temporary_fprs_for_xmm_scalars;
    uint32_t _pinned_temporary_scalars;
    uint64_t field_220;
    uint64_t field_228;
    ThreadContextOffsets* thread_context_offsets;
    char translator_variant;
    char field_239;
    uint16_t ymm_upper_half_alloc_mask;
    uint8_t ymm_upper_half_fpr[16];
    uint64_t data_;
    uint64_t data_size;
    uint64_t qword260;
    uint32_t dword268;
    uint32_t field_26C;
    uint64_t segments_begin;
    uint64_t segments_end;
    uint64_t field_280;

    // ── OPT-1: Per-instance x87 base/TOP register cache ────────────────────────
    // NOTE: All fields zero-initialise correctly (struct is memset to 0).
    //       x87_cache_gprs_valid == 0 means base/top/st_base GPR numbers are
    //       meaningless; the cache is inactive.  Set to 1 when GPRs are assigned.
    int8_t x87_cache_base_gpr;
    int8_t x87_cache_top_gpr;
    int16_t x87_cache_run_remaining;
    int8_t x87_cache_st_base_gpr;  // GPR holding &st[0] = Xbase + 8 for scaled addressing
    int8_t x87_cache_top_dirty;    // OPT-C: 1 = push skipped store_top, TOP in memory stale
    int8_t x87_cache_gprs_valid;   // 1 = base/top/st_base GPR numbers are meaningful
    int8_t _x87_pad[1];            // padding
    IRBlock* x87_cache_prev_block;
};

// sizeof changed from 0x288 due to OPT-1 cache fields appended at end.
static_assert(offsetof(TranslationResult, ir_module_data) == 0x00,
              "TranslationResult::ir_module_data offset mismatch");
static_assert(offsetof(TranslationResult, insn_buf) == 0x10,
              "TranslationResult::insn_buf offset mismatch");
static_assert(offsetof(TranslationResult, external_fixups) == 0x50,
              "TranslationResult::external_fixups offset mismatch");
static_assert(offsetof(TranslationResult, internal_fixups) == 0x70,
              "TranslationResult::internal_fixups offset mismatch");
static_assert(offsetof(TranslationResult, _fixups) == 0x90,
              "TranslationResult::_fixups offset mismatch");
static_assert(offsetof(TranslationResult, dyld_stub_fixups) == 0xD0,
              "TranslationResult::dyld_stub_fixups offset mismatch");
static_assert(offsetof(TranslationResult, free_gpr_mask) == 0x210,
              "TranslationResult::free_gpr_mask offset mismatch");
static_assert(offsetof(TranslationResult, free_fpr_mask) == 0x214,
              "TranslationResult::free_fpr_mask offset mismatch");
static_assert(offsetof(TranslationResult, thread_context_offsets) == 0x230,
              "TranslationResult::thread_context_offsets offset mismatch");