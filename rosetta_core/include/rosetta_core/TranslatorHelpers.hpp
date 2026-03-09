#pragma once
#include <cassert>
#include <cstdint>

#include "rosetta_core/IROperand.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"

// =============================================================================
// Layer 3 — Register Allocator Interface
//
// Thin wrappers around the existing Rosetta allocator machinery in
// TranslatorHelpers.cpp. All three underlying functions exist in the binary:
//
//   allocate_temporary_gpr_num  @ 0x1f4c0
//   alloc_specific_fpr          @ 0x1f650
//   free_gpr          @ 0x1f8d0
//
// No free_temporary_fpr exists in the binary. x87 FPR usage is transient
// (load → compute → store within a single translate_f* call), so FPRs are
// simply released by restoring free_fpr_mask directly after use.
// =============================================================================

// =============================================================================
// GPR allocation
//
// Allocates the next available scratch GPR from the pool at pool_index.
// Marks the register as occupied in translation.free_gpr_mask.
// Asserts if the pool slot is already occupied — callers must not double-allocate.
//
// pool_index: position in kGprScratchPool (0-based). Use sequentially:
//   0 for first scratch GPR, 1 for second, etc.
//
// Returns: AArch64 register number (0..30)
// =============================================================================

auto alloc_gpr(TranslationResult& translation, int pool_index) -> int;

// ---------------------------------------------------------------------------
// alloc_free_gpr — allocate lowest free scratch GPR directly from mask
// (used in paths that can't go through the pool-indexed allocator)
// ---------------------------------------------------------------------------
auto alloc_free_gpr(TranslationResult& translation) -> int;

auto resolve_hint_gpr(TranslationResult& result, int hint_reg) -> int;

// =============================================================================
// GPR release
//
// Returns a scratch GPR to the pool, clearing its bit in translation.free_gpr_mask.
// No-op if the register is not in kGprScratchMask (i.e. not a scratch reg).
// Asserts if reg == SP.
// =============================================================================

auto free_gpr(TranslationResult& translation, int reg) -> void;

// =============================================================================
// FPR allocation
//
// Allocates the next available scratch FPR from the pool at pool_index.
// Marks the register as occupied in translation.free_fpr_mask.
//
// pool_index: position in kFprScratchPool (0-based).
//
// Returns: AArch64 FPR number (0..31), used as D register index
// =============================================================================

auto alloc_fpr(TranslationResult& translation, int pool_index) -> int;

auto alloc_free_fpr(TranslationResult& translation) -> int;

// =============================================================================
// FPR release
//
// Returns a scratch FPR to the pool, restoring its bit in translation.free_fpr_mask.
// No equivalent exists in the binary — implemented directly against the mask.
// =============================================================================

auto free_fpr(TranslationResult& translation, int reg) -> void;

// ---------------------------------------------------------------------------
// emit_load_immediate — mirrors binary at 0xdd8c
// Loads a 64-bit constant into a register using MOVZ/MOVN/MOVK sequences.
// Returns the register used (may be dst_reg or a newly allocated one).
// Returns XZR if value == 0 (caller must not write to XZR).
// ---------------------------------------------------------------------------
auto emit_load_immediate(TranslationResult& result, int is_64bit, uint64_t value, int dst_reg)
    -> int;

// ---------------------------------------------------------------------------
// emit_load_immediate_no_xzr — mirrors binary at 0xdcfc
// Same as emit_load_immediate, but if value==0 emits MOVZ #0 into dst_reg
// rather than returning XZR (since caller needs a writable register).
// ---------------------------------------------------------------------------
auto emit_load_immediate_no_xzr(TranslationResult& result, int is_64bit, uint64_t value,
                                int dst_reg) -> void;

// ---------------------------------------------------------------------------
// compute_mem_operand_address — mirrors binary at 0x20390
//
// Handles IROperand::MemRef — the common case of [base + index*scale + disp].
// Returns the register holding the computed address.
// ---------------------------------------------------------------------------
auto compute_mem_operand_address(TranslationResult& result, bool is_64bit, const IROperand* op,
                                 int dst_reg) -> int;

// ---------------------------------------------------------------------------
// compute_operand_address — public entry point
// Mirrors binary at 0x1fffc.
// ---------------------------------------------------------------------------
auto compute_operand_address(TranslationResult& result, int is_64bit, IROperand* op, int dst_reg)
    -> int;

auto translate_gpr(TranslationResult* result, int is_64bit, uint8_t reg, unsigned int extend_mode,
                   int hint_reg) -> int;

auto read_operand_to_gpr(TranslationResult& result, bool is_64bit, IROperand* operand,
                         int extend_mode, int hint_reg) -> int;