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

// =============================================================================
// Addressing-mode folding (ROSETTA_X87_DISABLE_ADDR_FOLD=1 to disable)
//
// For simple [base + disp] operands (64-bit address size, no index, no segment
// override), the displacement can be folded straight into the AArch64 load/
// store addressing mode instead of materializing the full effective address
// with an ADD/SUB into a scratch register.
// =============================================================================

struct OperandAccess {
    // Address register for the access. Callers ALWAYS free_gpr() it after the
    // last use — free_gpr is a no-op for guest (non-scratch) registers, which
    // the folded encodings return directly. NOTE: when enc != FullEA (and even
    // for FullEA with zero disp) `base` may be a live guest register — never
    // write to it.
    int base;
    int32_t offset;  // folded byte offset; always 0 when enc == FullEA
    enum class Enc : uint8_t {
        ScaledImm12,  // LDR/STR [base, #offset]   (offset / access_size as imm12)
        Unscaled9,    // LDUR/STUR [base, #offset] (offset as signed imm9)
        FullEA,       // offset already folded into base; access [base, #0]
    } enc;
};

// Compute an access plan for `op`. Folds op->mem.disp into the addressing mode
// when the operand is a plain MemRef [base + disp] with 64-bit address size and
// the disp encodes for an access of size (1 << size_log2); otherwise falls back
// to compute_operand_address (bit-identical to the pre-fold behavior).
//
// extra_off/extra_size_log2: a second access made through the same base at
// byte offset (disp + extra_off) with size (1 << extra_size_log2) — e.g. the
// trailing 2-byte exponent load of an m80 at +8. Folding requires both
// accesses to encode in the SAME class (both imm12-scaled or both imm9).
auto compute_operand_access(TranslationResult& result, int is_64bit, IROperand* op, int size_log2,
                            int32_t extra_off = 0, int extra_size_log2 = 0) -> OperandAccess;

// One-call replacement for the dominant pattern
//   addr = compute_operand_address(...); emit_fldr/fstr_imm(size, Vt, addr, 0);
//   free_gpr(addr);
// size: 2=S (f32), 3=D (f64).  is_load: 1=LDR, 0=STR.
auto emit_fp_mem_access(TranslationResult& result, int is_64bit, IROperand* op, int size,
                        int is_load, int Vt) -> void;

// GPR counterpart of emit_fp_mem_access. size_log2: 0=B 1=H 2=W 3=X.
// Rt must not be a live guest register when is_load (it is written).
auto emit_gpr_mem_access(TranslationResult& result, int is_64bit, IROperand* op, int size_log2,
                         int is_load, int Rt) -> void;

// Load a signed integer memory operand (m16 → LDRH+SXTH, else LDR W) into a
// GPR and return that register; the caller frees it. Folds the displacement
// into the load's addressing mode when possible (compute_operand_access).
//
// The value register is the address register only when the latter is a scratch
// we own. Folded encodings — and zero-disp [reg] operands — hand back a LIVE
// guest base register, which must never be used as a load destination.
auto emit_load_int_operand(TranslationResult& result, IROperand* op, bool is_m16) -> int;

// dst = src + disp (dst == src allowed): ADD/SUB imm12 or imm12<<12 when the
// displacement fits, else one transient scratch GPR for the immediate.
auto emit_add_disp(TranslationResult& result, int is_64bit, int dst, int src,
                   int64_t disp) -> void;

auto translate_gpr(TranslationResult* result, int is_64bit, uint8_t reg, unsigned int extend_mode,
                   int hint_reg) -> int;

// ---------------------------------------------------------------------------
// emit_bl_runtime_routine — emit a placeholder BL (0x94000000) and record the
// Branch26 fixup that patches it to `routine` (a kRuntimeRoutine_* id).
//
// Replaces the repeated pattern:
//   Fixup fixup;
//   fixup.kind = FixupKind::Branch26;
//   fixup.insn_offset = static_cast<uint32_t>(result.insn_buf.end);
//   fixup.target = routine;
//   result._fixups.push_back(fixup);
//   result.insn_buf.emit(0x94000000u);
// ---------------------------------------------------------------------------
auto emit_bl_runtime_routine(TranslationResult& result, int routine) -> void;

auto read_operand_to_gpr(TranslationResult& result, bool is_64bit, IROperand* operand,
                         int extend_mode, int hint_reg) -> int;