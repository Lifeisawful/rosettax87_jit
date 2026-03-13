#include "rosetta_core/TranslatorX87.h"

#include <utility>

#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/RuntimeRoutine.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/TranslatorX87Helpers.hpp"

namespace TranslatorX87 {

// =============================================================================
// OPT-1: Cross-instruction x87 base/TOP register cache
//
// When consecutive x87 instructions appear in a block, the base address
// (X18 + x87_state_offset) and the TOP field never change between instructions
// except through our own push/pop (which update the register in-place).
// Caching these two values across instructions saves 3-4 emitted AArch64
// instructions per x87 opcode after the first in a run:
//   - 1-2 insns for emit_x87_base (ADD Xbase, X18, #offset)
//   - 2 insns for emit_load_top (LDRH + UBFX)
//
// The cache is managed by Translator::translate_instruction, which:
//   1. Invalidates on block change or non-x87 opcodes
//   2. Scans ahead to find consecutive x87 run length
//   3. Pins pool slots 0 (Xbase) and 1 (Wd_top) across the run
//   4. Excludes them from the free_gpr_mask reset between instructions
// =============================================================================

// ── Cache query/control (called from Translator.cpp) ─────────────────────────

bool x87_cache_active(TranslationResult* tr) {
    return tr->x87_cache_run_remaining > 0;
}

uint32_t x87_cache_pinned_mask(TranslationResult* tr) {
    uint32_t mask = 0;
    if (tr->x87_cache_gprs_valid) {
        mask |= (1u << tr->x87_cache_base_gpr);
        mask |= (1u << tr->x87_cache_top_gpr);
        mask |= (1u << tr->x87_cache_st_base_gpr);
    }
    return mask;
}

void x87_cache_invalidate(TranslationResult* tr) {
    tr->x87_cache_gprs_valid = 0;
    tr->x87_cache_top_dirty = 0;
    tr->x87_cache_run_remaining = 0;
}

void x87_cache_set_run(TranslationResult* tr, int run_length) {
    if (run_length >= 2)
        tr->x87_cache_run_remaining = static_cast<int16_t>(run_length);
}

void x87_cache_tick(TranslationResult* tr) {
    if (tr->x87_cache_run_remaining > 0) {
        tr->x87_cache_run_remaining--;
        if (tr->x87_cache_run_remaining == 0) {
            tr->x87_cache_gprs_valid = 0;
            tr->x87_cache_top_dirty = 0;
        }
    }
}

// ── Preamble / epilogue used by every translate_* function ───────────────────

// Acquires Xbase and Wd_top.  On a cache hit, returns the cached register
// numbers without emitting any instructions.  On a miss (first instruction
// in a run, or singleton), allocates pool slots 0+1 and emits the full
// ADD + LDRH + UBFX sequence.
static auto x87_begin(TranslationResult& a1, AssemblerBuffer& buf) -> std::pair<int, int> {
    if (a1.x87_cache_run_remaining > 0 && a1.x87_cache_gprs_valid) {
        // Cache HIT — registers already hold Xbase and TOP.
        return {a1.x87_cache_base_gpr, a1.x87_cache_top_gpr};
    }

    // Cache MISS — allocate and emit the preamble.
    const int Xbase = alloc_gpr(a1, 0);
    const int Wd_top = alloc_gpr(a1, 1);
    emit_x87_base(buf, a1, Xbase);
    emit_load_top(buf, a1, Xbase, Wd_top);

    if (a1.x87_cache_run_remaining > 0) {
        // First instruction in a new run — store registers in cache.
        a1.x87_cache_base_gpr = static_cast<int8_t>(Xbase);
        a1.x87_cache_top_gpr = static_cast<int8_t>(Wd_top);

        // Stride-8: Allocate and compute pointer to &st[0] = Xbase + 8.
        // Pool slot 6 = X28, never used by any translate_* via alloc_gpr().
        // Enables LDR Dd, [Xst_base, Widx, SXTW #3] — scaled indexed addressing.
        const int Xst_base = alloc_gpr(a1, 6);
        // ADD Xst_base, Xbase, #8  (64-bit ADD — Xst_base is a pointer)
        emit_add_imm(buf, /*is_64bit=*/1, /*is_sub=*/0, /*is_set_flags=*/0,
                     /*shift=*/0, kX87RegFileOff, Xbase, Xst_base);
        a1.x87_cache_st_base_gpr = static_cast<int8_t>(Xst_base);
        a1.x87_cache_gprs_valid = 1;
    }

    return {Xbase, Wd_top};
}

// Returns the cached &st[0] pointer register, or -1 if not preloaded.
static int x87_get_st_base(TranslationResult& a1) {
    return a1.x87_cache_gprs_valid ? a1.x87_cache_st_base_gpr : -1;
}

static void x87_end(TranslationResult& a1, AssemblerBuffer& buf, int Xbase, int Wd_top,
                    int Wd_tmp) {
    // OPT-C: If this is the last instruction in the run (run_remaining == 1,
    // will become 0 after tick), flush any deferred status_word writeback.
    if (a1.x87_cache_top_dirty && a1.x87_cache_run_remaining <= 1) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
        a1.x87_cache_top_dirty = 0;
    }

    if (a1.x87_cache_run_remaining > 0) {
        return;
    }
    free_gpr(a1, Wd_top);
    free_gpr(a1, Xbase);
}

static void x87_cache_force_release(TranslationResult& a1, AssemblerBuffer& buf) {
    // OPT-C: flush deferred writeback using the cached registers
    if (a1.x87_cache_top_dirty && a1.x87_cache_gprs_valid) {
        const int tmp = alloc_gpr(a1, 2);  // pool slot 2 is free here
        emit_store_top(buf, a1.x87_cache_base_gpr, a1.x87_cache_top_gpr, tmp);
        free_gpr(a1, tmp);
        a1.x87_cache_top_dirty = 0;
    }
    if (a1.x87_cache_gprs_valid) {
        a1.free_gpr_mask |= (1u << a1.x87_cache_base_gpr);
        a1.free_gpr_mask |= (1u << a1.x87_cache_top_gpr);
        a1.free_gpr_mask |= (1u << a1.x87_cache_st_base_gpr);
    }
    x87_cache_invalidate(&a1);
}

// ── OPT-C: Push/pop wrappers that manage the deferred writeback flag ─────────

// Push: when cache is active, skip the 3-insn store_top (deferred to next pop
// or end-of-run flush in x87_end).  When not cached, use full push.
static void x87_push(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top, int Wd_tmp,
                     int Wd_tmp2) {
    if (a1.x87_cache_run_remaining > 0) {
        emit_x87_push_deferred(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        a1.x87_cache_top_dirty = 1;
    } else {
        emit_x87_push(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
    }
}

// Pop: emit_store_top inside emit_x87_pop writes the correct current TOP
// via BFI regardless of what was in memory, so dirty is cleared.
// Wd_tmp2 is allocated from the free GPR pool for the tag word RMW.
static void x87_pop(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                    int Wd_tmp) {
    const int Wd_tmp2 = alloc_free_gpr(a1);
    emit_x87_pop(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
    free_gpr(a1, Wd_tmp2);
    a1.x87_cache_top_dirty = 0;
}

static void x87_pop_n(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                      int Wd_tmp, int n) {
    const int Wd_tmp2 = alloc_free_gpr(a1);
    emit_x87_pop_n(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2, n);
    free_gpr(a1, Wd_tmp2);
    a1.x87_cache_top_dirty = 0;
}

// Flush: emit deferred writeback if dirty.  Must be called before any
// instruction that reads status_word from memory (translate_fstsw).
static void x87_flush_top(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                          int Wd_tmp) {
    if (a1.x87_cache_top_dirty) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
        a1.x87_cache_top_dirty = 0;
    }
}

// FLDZ -- push +0.0 onto the x87 stack.
//
// x87 semantics:
//   TOP = (TOP - 1) & 7
//   ST(0).mantissa = 0x0000000000000000  (+0.0 as IEEE 754 double)
//   status_word[13:11] = new TOP
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base = X18 + x87_state_offset
//   Wd_top  (gpr pool 1) -- TOP; updated in-place by emit_x87_push
//   Wd_tmp  (gpr pool 2) -- scratch for emit_store_top RMW and offset math
//   Dd_val  (fpr free pool) -- holds +0.0 for the FSTR
//
// OPT-2: Wd_tmp2 (pool slot 3) removed — tag word maintenance eliminated.
// OPT-5: MOVI Dd, #0 replaces FMOV Dd, XZR — removes GPR dependency, allows
//         the zero instruction to issue in parallel with the Xbase ADD.
//
auto translate_fldz(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_val = alloc_free_fpr(*a1);

    x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);

    // OPT-5: MOVI Dd, #0 — zero the D register with no GPR dependency.
    emit_movi_d_zero(buf, Dd_val);
    emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);

    free_fpr(*a1, Dd_val);
    free_gpr(*a1, Wd_tmp2);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// FLD1 -- push +1.0 onto the x87 stack.
//
// x87 semantics:
//   TOP = (TOP - 1) & 7
//   ST(0).mantissa = 0x3FF0000000000000  (+1.0 as IEEE 754 double)
//   status_word[13:11] = new TOP
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base = X18 + x87_state_offset
//   Wd_top  (gpr pool 1) -- TOP; updated in-place by emit_x87_push
//   Wd_tmp  (gpr pool 2) -- scratch for emit_x87_push RMW and offset math
//   Dd_val  (fpr free pool) -- holds +1.0 for the FSTR
//
// OPT-2: Wd_tmp2 (pool slot 3) removed — tag word maintenance eliminated.
// OPT-5: FMOV Dd, #1.0 replaces MOVZ+FMOV (2 insns → 1 insn), eliminates
//         Wd_tmp usage for the constant, and removes cross-domain latency.
//
auto translate_fld1(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_val = alloc_free_fpr(*a1);

    x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);

    // OPT-5: FMOV Dd, #1.0 — single instruction, no GPR intermediate.
    emit_fmov_d_one(buf, Dd_val);
    emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);

    free_fpr(*a1, Dd_val);
    free_gpr(*a1, Wd_tmp2);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// Constant-push helpers — fldl2e, fldl2t, fldlg2, fldln2, fldpi
//
// All five push a known IEEE 754 double constant onto the x87 stack.
// The pattern is identical to fld1 but all four 16-bit chunks are non-zero,
// requiring MOVZ hw=3 + three MOVK instructions.
//
// Shared static helper — keeps each translate_fldXX to a single call.
// =============================================================================
static void translate_fld_const(TranslationResult* a1, uint64_t bits) {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_val = alloc_free_fpr(*a1);

    x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // Load the 64-bit constant into Wd_tmp via MOVZ hw=3 + up to three MOVKs.
    // Chunks are emitted high-to-low; zero chunks after the first are skipped.
    const uint16_t hw3 = (uint16_t)(bits >> 48);
    const uint16_t hw2 = (uint16_t)(bits >> 32);
    const uint16_t hw1 = (uint16_t)(bits >> 16);
    const uint16_t hw0 = (uint16_t)(bits);

    emit_movn(buf, /*is_64bit=*/1, /*opc=*/2 /*MOVZ*/, /*hw=*/3, hw3, Wd_tmp);
    if (hw2)
        emit_movn(buf, 1, /*MOVK=*/3, /*hw=*/2, hw2, Wd_tmp);
    if (hw1)
        emit_movn(buf, 1, /*MOVK=*/3, /*hw=*/1, hw1, Wd_tmp);
    if (hw0)
        emit_movn(buf, 1, /*MOVK=*/3, /*hw=*/0, hw0, Wd_tmp);

    emit_fmov_x_to_d(buf, Dd_val, Wd_tmp);
    emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);

    free_fpr(*a1, Dd_val);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// FLDL2E — push log2(e) = 0x3FF71547652B82FE
auto translate_fldl2e(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    translate_fld_const(a1, 0x3FF71547652B82FEULL);
}

// FLDL2T — push log2(10) = 0x400A934F0979A371
auto translate_fldl2t(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    translate_fld_const(a1, 0x400A934F0979A371ULL);
}

// FLDLG2 — push log10(2) = 0x3FD34413509F79FF
auto translate_fldlg2(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    translate_fld_const(a1, 0x3FD34413509F79FFULL);
}

// FLDLN2 — push ln(2) = 0x3FE62E42FEFA39EF
auto translate_fldln2(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    translate_fld_const(a1, 0x3FE62E42FEFA39EFULL);
}

// FLDPI — push pi = 0x400921FB54442D18
auto translate_fldpi(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    translate_fld_const(a1, 0x400921FB54442D18ULL);
}

// =============================================================================
// FLD — D9 /0 (m32fp), DD /0 (m64fp), DB /5 (m80fp), D9 C0+i (ST(i))
//
// Pushes a floating-point value onto the x87 stack.
//
// Operand encoding (Rosetta IR):
//   FLD ST(i)   D9 C0+i  operands = [ST(0) dst Register, ST(i) src Register]
//   FLD m32fp   D9 /0    operands = [m32fp MemRef src]  — operands[0].size == S32
//   FLD m64fp   DD /0    operands = [m64fp MemRef src]  — operands[0].size == S64
//   FLD m80fp   DB /5    operands = [m80fp MemRef src]  — operands[0].size == S80
//
// m80fp is handled via kRuntimeRoutine_fld_fp80 and early-returns before any
// direct x87-state setup. All other variants use direct AArch64 emission.
//
// ST(i) ordering requirement:
//   Intel spec: temp = ST(i); TOP--; ST(0) = temp.
//   The value MUST be read before emit_x87_push because push decrements TOP,
//   which would change the physical slot that depth i maps to.
//   (Special case: FLD ST(0) duplicates the top — still correct with load-before-push.)
//
// Register allocation (direct-emit paths):
//   Xbase   (gpr pool 0) -- X87State base pointer
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_push
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_{load,store}_st;
//                           reused as RMW scratch inside emit_x87_push
//   Dd_val  (fpr free pool) -- the loaded value
//   addr_reg (free pool) -- memory paths only; freed after FP load (OPT-4)
//
// Register allocation (m80fp runtime path):
//   W_lo    (gpr pool 0) -- low  8 bytes of the f80 value (mantissa)
//   W_hi    (gpr pool 1) -- high 2 bytes of the f80 value (sign + 15-bit exponent)
//   addr_reg (free pool) -- freed before the BL placeholder is emitted
// =============================================================================
auto translate_fld(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;

    // -------------------------------------------------------------------------
    // FLD m80fp — DB /5  (early-out, handed off to runtime routine)
    // -------------------------------------------------------------------------
    if (a2->operands[0].kind != IROperandKind::Register &&
        a2->operands[0].mem.size == IROperandSize::S80) {
        // OPT-1: Release any cached base/top GPRs — the BL below clobbers
        // all scratch registers, and we need pool slots 0+1 for W_lo/W_hi.
        x87_cache_force_release(*a1, buf);

        const int W_lo = alloc_gpr(*a1, 0);
        const int W_hi = alloc_gpr(*a1, 1);
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);
        emit_ldr_imm(buf, /*size=*/3, W_lo, addr_reg, /*imm12=*/0);
        emit_ldr_imm(buf, /*size=*/1, W_hi, addr_reg, /*imm12=*/4);
        free_gpr(*a1, addr_reg);

        Fixup fixup;
        fixup.kind = FixupKind::Branch26;
        fixup.insn_offset = static_cast<uint32_t>(a1->insn_buf.end);
        fixup.target = kRuntimeRoutine_fld_fp80;
        a1->_fixups.push_back(fixup);
        a1->insn_buf.emit(0x94000000u);

        free_gpr(*a1, W_hi);
        free_gpr(*a1, W_lo);
        return;
    }

    // -------------------------------------------------------------------------
    // Common setup for ST(i), m32fp, m64fp paths
    // -------------------------------------------------------------------------
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_val = alloc_free_fpr(*a1);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // FLD ST(i) — D9 C0+i
        const int depth_src = a2->operands[1].reg.reg.index();
        emit_load_st(buf, Xbase, Wd_top, depth_src, Wd_tmp, Dd_val, Xst_base);
        x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        free_gpr(*a1, Wd_tmp2);
        emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);
    } else if (a2->operands[0].mem.size == IROperandSize::S32) {
        // FLD m32fp — D9 /0
        //
        // OPT-4: load the f32 value directly into an FP register via LDR Sd,
        // then widen with FCVT Dd, Sd.  Replaces the old path that went through
        // a GPR intermediate (read_operand_to_gpr → FMOV Dd, Xn → FCVT),
        // saving 1 instruction and eliminating the ~4-cycle cross-domain
        // transfer penalty on Apple M-series.
        //
        // Bug 4: addr_size derived from the operand (not hardcoded 64-bit) so
        // 32-bit guest code computes effective addresses correctly.
        x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        free_gpr(*a1, Wd_tmp2);

        const bool addr_is_64 = (a2->operands[0].mem.addr_size == IROperandSize::S64);
        const int addr_reg = compute_operand_address(*a1, addr_is_64, &a2->operands[0], GPR::XZR);
        // LDR Sd, [addr_reg] — load f32 directly into FP register
        emit_fldr_imm(buf, /*size=*/2 /*S=f32*/, Dd_val, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        // FCVT Dd, Sd — widen single → double
        emit_fcvt_s_to_d(buf, Dd_val, Dd_val);
        emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);
    } else {
        // FLD m64fp — DD /0
        //
        // OPT-4: load f64 directly into FP register via LDR Dd.  Replaces the
        // old GPR-intermediate path (read_operand_to_gpr → FMOV Dd, Xn),
        // saving 1 instruction + cross-domain latency.
        x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        free_gpr(*a1, Wd_tmp2);

        const bool addr_is_64 = (a2->operands[0].mem.addr_size == IROperandSize::S64);
        const int addr_reg = compute_operand_address(*a1, addr_is_64, &a2->operands[0], GPR::XZR);
        // LDR Dd, [addr_reg] — load f64 directly into FP register
        emit_fldr_imm(buf, /*size=*/3 /*D=f64*/, Dd_val, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);
    }

    free_fpr(*a1, Dd_val);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
    return;
}

// =============================================================================
// FILD — DB /0 (m32int), DF /0 (m16int), DF /5 (m64int)
//
// Loads a signed integer from memory, converts it to f64, and pushes it onto
// the x87 stack as ST(0).
//
// x87 semantics:
//   TOP = (TOP - 1) & 7
//   ST(0) = ConvertToDouble((signed)mem)
//
// Operand encoding (Rosetta IR):
//   DF /0:  FILD m16int  — operands = [m16int MemRef]  operands[0].size == S16
//   DB /0:  FILD m32int  — operands = [m32int MemRef]  operands[0].size == S32
//   DF /5:  FILD m64int  — operands = [m64int MemRef]  operands[0].size == S64
//
// Sequence:
//   1. Compute source memory address → addr_reg (free pool).
//   2. Load integer from memory into Wd_int (free pool), sign-extending as needed:
//        m16int: LDRH Wd_int, [addr_reg]  (zero-extend into W)
//                SXTH Wd_int, Wd_int      (sign-extend bits[15:0] → W)
//        m32int: LDR  Wd_int, [addr_reg]  (32-bit; SCVTF treats W as signed)
//        m64int: LDR  Xd_int, [addr_reg]  (64-bit)
//   3. Free addr_reg.
//   4. emit_x87_push — decrements TOP, updates status_word.
//      Clobbers Wd_tmp (used as RMW scratch).
//      Wd_int is held in a separate free-pool register and is NOT clobbered.
//   5. SCVTF Dd_val, Wd_int/Xd_int — signed integer → f64.
//        m16/m32: is_64bit_int=0 (W source)
//        m64:     is_64bit_int=1 (X source)
//   6. Store Dd_val into the freshly allocated ST(0).
//   7. Free Wd_int.
//
// Critical ordering constraint:
//   Wd_int MUST be a separate register from Wd_tmp.  emit_x87_push clobbers
//   Wd_tmp as its status_word RMW scratch (see emit_store_top).  If the
//   integer were held in Wd_tmp it would be destroyed before SCVTF in step 5,
//   producing garbage results whenever the push actually modifies Wd_tmp
//   (i.e. almost always, since TOP changes on every push).
//
// Why load-before-push?
//   The memory address is independent of TOP, so the load can happen in either
//   order relative to the push.  We load first to get addr_reg freed early,
//   keeping peak register pressure low.
//
// Why LDRH + SXTH for m16, not LDRSH?
//   emit_ldr_str_imm exposes opc=1 (LDR = zero-extend). LDRSH is opc=2 in
//   the AArch64 encoding, which the helper does not wrap.
//   LDRH + SXTH (SBFM W, W, #0, #15) is the correct two-instruction equivalent.
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_push
//   Wd_tmp  (gpr pool 2) -- RMW scratch consumed by emit_x87_push,
//                           then offset scratch for emit_store_st
//   Wd_int  (gpr free pool) -- holds the loaded integer across the push;
//                              freed after SCVTF
//   Dd_val  (fpr free pool) -- converted f64 value; stored into ST(0)
// =============================================================================
auto translate_fild(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const IROperandSize int_size = a2->operands[0].mem.size;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Wd_int = alloc_free_gpr(*a1);  // survives emit_x87_push
    const int Dd_val = alloc_free_fpr(*a1);

    // Step 1: compute source memory address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 2: load integer from memory into Wd_int, sign-extending as needed.
    // Wd_int is a free-pool register distinct from Wd_tmp, so emit_x87_push
    // cannot clobber it.
    if (int_size == IROperandSize::S16) {
        // LDRH Wd_int, [addr_reg]  — 16-bit zero-extending load into W
        emit_ldr_str_imm(buf, /*size=*/1 /*16-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, Wd_int);
        // SXTH Wd_int, Wd_int  — sign-extend bits[15:0] → W (SBFM W,W,#0,#15)
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, Wd_int, Wd_int);
    } else if (int_size == IROperandSize::S32) {
        // LDR Wd_int, [addr_reg]  — 32-bit load; SCVTF(is_64bit_int=0) treats W as signed
        emit_ldr_str_imm(buf, /*size=*/2 /*32-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, Wd_int);
    } else {
        // LDR Xd_int, [addr_reg]  — 64-bit load (m64int, DF /5)
        emit_ldr_str_imm(buf, /*size=*/3 /*64-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, Wd_int);
    }

    // Step 3: free addr_reg — no longer needed
    free_gpr(*a1, addr_reg);

    // Step 4: push — allocates a new ST(0) slot, decrements TOP.
    // Clobbers Wd_tmp and Wd_tmp2.  Wd_int is unaffected (separate
    // free-pool register).
    x87_push(buf, *a1, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // Step 5: SCVTF — convert signed integer in Wd_int/Xd_int to f64.
    // m16 and m32 use a W (32-bit) source register: is_64bit_int=0
    // m64 uses an X (64-bit) source register:        is_64bit_int=1
    const int is_64bit_int = (int_size == IROperandSize::S64) ? 1 : 0;
    emit_scvtf(buf, is_64bit_int, /*ftype=*/1 /*f64*/, Dd_val, Wd_int);

    // Step 6: store the converted value into the freshly pushed ST(0).
    // Wd_tmp is now clean (emit_x87_push is done with it) and used here
    // as the byte-offset scratch inside emit_store_st.
    emit_store_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);

    // Step 7: free in reverse allocation order
    free_fpr(*a1, Dd_val);
    free_gpr(*a1, Wd_int);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FADD — D8 /0, DC /0, D8 C0+i, DC C0+i
//
// Handles all four non-popping ADD variants under opcode kOpcodeName_fadd.
// Dispatch is on operands[0].kind:
//
//   Register → ST-ST path
//     D8 C0+i:  FADD ST(0), ST(i)  — operands = [ST(0), ST(i)]
//     DC C0+i:  FADD ST(i), ST(0)  — operands = [ST(i), ST(0)]
//     Both are handled identically: dst=operands[0].index, src=operands[1].index.
//
//   MemRef → Memory float path
//     D8 /0:  FADD m32fp  — operands = [m32fp MemRef, ST(0)]
//     DC /0:  FADD m64fp  — operands = [m64fp MemRef, ST(0)]
//     Source is operands[0] (MemRef). Destination is always ST(0).
// =============================================================================
auto translate_fadd(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // -----------------------------------------------------------------
        // ST-ST path: FADD ST(depth_dst), ST(depth_src)
        // D8 C0+i: operands = [ST(0),  ST(i)]
        // DC C0+i: operands = [ST(i),  ST(0)]
        // -----------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();
        const int depth_src = a2->operands[1].reg.reg.index();

        // Opt 3: load src first (its offset is discarded), then dst last so
        // Wd_tmp holds offset(depth_dst) and emit_store_st_at_offset can reuse it.
        emit_load_st(buf, Xbase, Wd_top, depth_src, Wd_tmp, Dd_src, Xst_base);
        const int Wk = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);
        emit_fadd_f64(buf, Dd_dst, Dd_dst, Dd_src);
        emit_store_st_at_offset(buf, Xbase, Wk, Dd_dst, Xst_base);
    } else {
        // -----------------------------------------------------------------
        // Memory float path: FADD m32fp / m64fp
        //
        // Rosetta encodes these as [mem_src, ST(0)_dst]:
        //   D8 /0: operands = [m32fp MemRef, ST(0)]
        //   DC /0: operands = [m64fp MemRef, ST(0)]
        //
        // Source is operands[0] (MemRef). Destination is always ST(0).
        // -----------------------------------------------------------------
        const bool is_f32 = (a2->operands[0].mem.size == IROperandSize::S32);

        // Step 1: load ST(0) — Wd_tmp receives the byte offset for ST(0).
        const int Wk2 =
            emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_dst, Xst_base);

        // Step 2: compute memory address from operands[0]
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

        // Step 3: load memory operand
        //   size 2 = S-register (f32), size 3 = D-register (f64)
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);

        // Return the address register to the free pool immediately — done with it.
        free_gpr(*a1, addr_reg);

        // Step 4: widen f32 → f64 if needed
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);

        // Step 5: add
        emit_fadd_f64(buf, Dd_dst, Dd_dst, Dd_src);

        // Step 6: store back to ST(0).
        // Opt 3: addr_reg is a different free-pool register, so Wd_tmp still
        // holds the ST(0) byte offset from emit_load_st above.
        emit_store_st_at_offset(buf, Xbase, Wk2, Dd_dst, Xst_base);
    }

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FADDP — DE C0+i, DE C1
//
// x87 semantics:
//   ST(i) = ST(i) + ST(0)
//   TOP   = (TOP + 1) & 7   (pop: ST(0) slot becomes logically empty)
//
// DE C1 is the implicit form "FADDP" (no written operands in assembly) which
// the CPU decodes as FADDP ST(1), ST(0). Rosetta encodes it identically to
// FADDP ST(1), ST(0) in the IR, so depth_dst == 1 naturally; no special
// casing needed here.
//
// Ordering: store result first under the current TOP, then pop. Popping first
// would shift physical indices, causing ST(i) to resolve to the wrong slot
// when depth_dst > 0.
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_pop
//   Wd_tmp  (gpr pool 2) -- offset scratch; reused for emit_x87_pop RMW
//   Dd_dst  (fpr free pool) -- ST(i) value; receives the sum
//   Dd_src  (fpr free pool) -- ST(0) value
//
auto translate_faddp(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int depth_dst = a2->operands[0].reg.reg.index();  // ST(i)
    // operands[1] is always ST(0); depth_src == 0 by definition.

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // Opt 3: load ST(0) (src) first — its offset is discarded.
    // Load ST(depth_dst) (dst) second so Wd_tmp holds offset(depth_dst).
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
    const int Wk3 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);
    emit_fadd_f64(buf, Dd_dst, Dd_dst, Dd_src);
    emit_store_st_at_offset(buf, Xbase, Wk3, Dd_dst, Xst_base);

    // Pop: TOP = (TOP + 1) & 7.  Wd_tmp is dead after emit_store_st_at_offset,
    // safe to reuse as the status_word RMW scratch inside emit_x87_pop.
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FSUB / FSUBR — D8 /4, DC /4, D8 E0+i, DC E0+i  (non-popping)
//              — D8 /5, DC /5, D8 E8+i, DC E8+i  (reversed, non-popping)
//
// Handles all non-popping subtract variants under kOpcodeName_fsub and
// kOpcodeName_fsubr in a single function, dispatching on opcode to determine
// operand order.
//
// x87 semantics:
//   fsub:  ST(dst) = ST(dst) - ST(src)        (or ST(0) = ST(0) - mem)
//   fsubr: ST(dst) = ST(src) - ST(dst)        (or ST(0) = mem   - ST(0))
//
// Dispatch is on operands[0].kind:
//
//   Register → ST-ST path
//     D8 E0+i:  FSUB  ST(0), ST(i)  — operands = [ST(0), ST(i)]
//     DC E0+i:  FSUB  ST(i), ST(0)  — operands = [ST(i), ST(0)]
//     D8 E8+i:  FSUBR ST(0), ST(i)  — operands = [ST(0), ST(i)]
//     DC E8+i:  FSUBR ST(i), ST(0)  — operands = [ST(i), ST(0)]
//     dst = operands[0].index, src = operands[1].index in all cases.
//     For fsubr the arithmetic operands are swapped: result = Dd_src - Dd_dst.
//
//   MemRef → Memory float path
//     D8 /4:  FSUB  m32fp  — operands = [m32fp MemRef, ST(0)]
//     DC /4:  FSUB  m64fp  — operands = [m64fp MemRef, ST(0)]
//     D8 /5:  FSUBR m32fp  — operands = [m32fp MemRef, ST(0)]
//     DC /5:  FSUBR m64fp  — operands = [m64fp MemRef, ST(0)]
//     Source is operands[0] (MemRef). Destination is always ST(0).
//     fsub:  ST(0) = ST(0) - mem
//     fsubr: ST(0) = mem   - ST(0)
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP (read-only; no push/pop)
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_{load,store}_st
//   Dd_dst  (fpr free pool) -- destination / minuend operand
//   Dd_src  (fpr free pool) -- source / subtrahend operand
// =============================================================================
auto translate_fsub(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_fsubr = (a2->opcode == kOpcodeName_fsubr);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // -----------------------------------------------------------------
        // ST-ST path
        // dst = operands[0].index, src = operands[1].index.
        // fsub:  result = Dd_dst - Dd_src  → stored into ST(dst)
        // fsubr: result = Dd_src - Dd_dst  → stored into ST(dst)
        // -----------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();
        const int depth_src = a2->operands[1].reg.reg.index();

        // Opt 3: load src first (offset discarded), then dst last so Wd_tmp
        // holds offset(depth_dst) for emit_store_st_at_offset.
        emit_load_st(buf, Xbase, Wd_top, depth_src, Wd_tmp, Dd_src, Xst_base);
        const int Wk4 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);

        if (is_fsubr)
            emit_fsub_f64(buf, Dd_dst, Dd_src, Dd_dst);  // dst = src - dst
        else
            emit_fsub_f64(buf, Dd_dst, Dd_dst, Dd_src);  // dst = dst - src

        emit_store_st_at_offset(buf, Xbase, Wk4, Dd_dst, Xst_base);
    } else {
        // -----------------------------------------------------------------
        // Memory float path
        // Rosetta encodes as [mem_src, ST(0)_dst]:
        //   D8 /4, DC /4: operands = [m32/64fp MemRef, ST(0)]  (fsub)
        //   D8 /5, DC /5: operands = [m32/64fp MemRef, ST(0)]  (fsubr)
        // fsub:  ST(0) = ST(0) - mem   →  Dd_dst - Dd_src
        // fsubr: ST(0) = mem   - ST(0) →  Dd_src - Dd_dst
        // -----------------------------------------------------------------
        const bool is_f32 = (a2->operands[0].mem.size == IROperandSize::S32);

        const int Wk5 =
            emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_dst, Xst_base);

        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);

        if (is_fsubr)
            emit_fsub_f64(buf, Dd_dst, Dd_src, Dd_dst);  // ST(0) = mem - ST(0)
        else
            emit_fsub_f64(buf, Dd_dst, Dd_dst, Dd_src);  // ST(0) = ST(0) - mem

        // Opt 3: addr_reg is a separate free-pool register; Wd_tmp still holds
        // the ST(0) byte offset set by emit_load_st above.
        emit_store_st_at_offset(buf, Xbase, Wk5, Dd_dst, Xst_base);
    }

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FSUBP / FSUBRP — DE E8+i, DE E9  (popping subtract / reversed popping subtract)
//
// Handles both popping variants under kOpcodeName_fsubp and kOpcodeName_fsubrp
// in a single function, dispatching on opcode for operand order.
//
// x87 semantics:
//   fsubp:  ST(i) = ST(i) - ST(0);  TOP = (TOP + 1) & 7
//   fsubrp: ST(i) = ST(0) - ST(i);  TOP = (TOP + 1) & 7
//
// Encoding:
//   DE E8+i  FSUBP  ST(i), ST(0) — operands = [ST(i), ST(0)]
//   DE E9    FSUBP               — implicit ST(1), ST(0); depth_dst == 1
//   DE E0+i  FSUBRP ST(i), ST(0) — operands = [ST(i), ST(0)]
//   DE E1    FSUBRP              — implicit ST(1), ST(0); depth_dst == 1
//
// Pop ordering: result is written to ST(i) before popping so the physical
// index for ST(i) is still valid under the current TOP.
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_pop
//   Wd_tmp  (gpr pool 2) -- offset scratch; reused for emit_x87_pop RMW
//   Dd_dst  (fpr free pool) -- ST(i) value; receives the result
//   Dd_src  (fpr free pool) -- ST(0) value
// =============================================================================
auto translate_fsubp(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_fsubrp = (a2->opcode == kOpcodeName_fsubrp);
    const int depth_dst = a2->operands[0].reg.reg.index();  // ST(i)
    // operands[1] is always ST(0); depth_src == 0 by definition.

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // Opt 3: load ST(0) (src) first — its offset is discarded.
    // Load ST(depth_dst) (dst) second so Wd_tmp holds offset(depth_dst).
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
    const int Wk6 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);

    if (is_fsubrp)
        emit_fsub_f64(buf, Dd_dst, Dd_src, Dd_dst);  // ST(i) = ST(0) - ST(i)
    else
        emit_fsub_f64(buf, Dd_dst, Dd_dst, Dd_src);  // ST(i) = ST(i) - ST(0)

    emit_store_st_at_offset(buf, Xbase, Wk6, Dd_dst, Xst_base);

    // Pop: TOP = (TOP + 1) & 7.  Wd_tmp is dead after emit_store_st_at_offset.
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FDIV / FDIVR — D8 /6, DC /6, D8 F0+i, DC F0+i  (non-popping)
//              — D8 /7, DC /7, D8 F8+i, DC F8+i  (reversed, non-popping)
//
// Handles all non-popping divide variants under kOpcodeName_fdiv and
// kOpcodeName_fdivr in a single function, dispatching on opcode to determine
// operand order.
//
// x87 semantics:
//   fdiv:  ST(dst) = ST(dst) / ST(src)        (or ST(0) = ST(0) / mem)
//   fdivr: ST(dst) = ST(src) / ST(dst)        (or ST(0) = mem   / ST(0))
//
// Dispatch is on operands[0].kind:
//
//   Register → ST-ST path
//     D8 F0+i:  FDIV  ST(0), ST(i)  — operands = [ST(0), ST(i)]
//     DC F0+i:  FDIV  ST(i), ST(0)  — operands = [ST(i), ST(0)]
//     D8 F8+i:  FDIVR ST(0), ST(i)  — operands = [ST(0), ST(i)]
//     DC F8+i:  FDIVR ST(i), ST(0)  — operands = [ST(i), ST(0)]
//     dst = operands[0].index, src = operands[1].index in all cases.
//     fdiv:  result = Dd_dst / Dd_src  → stored into ST(dst)
//     fdivr: result = Dd_src / Dd_dst  → stored into ST(dst)
//
//   MemRef → Memory float path
//     D8 /6:  FDIV  m32fp  — operands = [m32fp MemRef, ST(0)]
//     DC /6:  FDIV  m64fp  — operands = [m64fp MemRef, ST(0)]
//     D8 /7:  FDIVR m32fp  — operands = [m32fp MemRef, ST(0)]
//     DC /7:  FDIVR m64fp  — operands = [m64fp MemRef, ST(0)]
//     Source is operands[0] (MemRef). Destination is always ST(0).
//     fdiv:  ST(0) = ST(0) / mem   →  Dd_dst / Dd_src
//     fdivr: ST(0) = mem   / ST(0) →  Dd_src / Dd_dst
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP (read-only; no push/pop)
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_{load,store}_st
//   Dd_dst  (fpr free pool) -- destination / dividend operand
//   Dd_src  (fpr free pool) -- source / divisor operand
// =============================================================================
auto translate_fdiv(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_fdivr = (a2->opcode == kOpcodeName_fdivr);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // -----------------------------------------------------------------
        // ST-ST path
        // dst = operands[0].index, src = operands[1].index.
        // fdiv:  result = Dd_dst / Dd_src  → stored into ST(dst)
        // fdivr: result = Dd_src / Dd_dst  → stored into ST(dst)
        // -----------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();
        const int depth_src = a2->operands[1].reg.reg.index();

        // Opt 3: load src first (offset discarded), then dst last so Wd_tmp
        // holds offset(depth_dst) for emit_store_st_at_offset.
        emit_load_st(buf, Xbase, Wd_top, depth_src, Wd_tmp, Dd_src, Xst_base);
        const int Wk7 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);

        if (is_fdivr)
            emit_fdiv_f64(buf, Dd_dst, Dd_src, Dd_dst);  // dst = src / dst
        else
            emit_fdiv_f64(buf, Dd_dst, Dd_dst, Dd_src);  // dst = dst / src

        emit_store_st_at_offset(buf, Xbase, Wk7, Dd_dst, Xst_base);
    } else {
        // -----------------------------------------------------------------
        // Memory float path
        // Rosetta encodes as [mem_src, ST(0)_dst]:
        //   D8 /6, DC /6: operands = [m32/64fp MemRef, ST(0)]  (fdiv)
        //   D8 /7, DC /7: operands = [m32/64fp MemRef, ST(0)]  (fdivr)
        // fdiv:  ST(0) = ST(0) / mem   →  Dd_dst / Dd_src
        // fdivr: ST(0) = mem   / ST(0) →  Dd_src / Dd_dst
        // -----------------------------------------------------------------
        const bool is_f32 = (a2->operands[0].mem.size == IROperandSize::S32);

        const int Wk8 =
            emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_dst, Xst_base);

        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);

        if (is_fdivr)
            emit_fdiv_f64(buf, Dd_dst, Dd_src, Dd_dst);  // ST(0) = mem / ST(0)
        else
            emit_fdiv_f64(buf, Dd_dst, Dd_dst, Dd_src);  // ST(0) = ST(0) / mem

        // Opt 3: addr_reg is a separate free-pool register; Wd_tmp still holds
        // the ST(0) byte offset set by emit_load_st above.
        emit_store_st_at_offset(buf, Xbase, Wk8, Dd_dst, Xst_base);
    }

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FDIVP / FDIVRP — DE F8+i, DE F9  (popping divide / reversed popping divide)
//
// Handles both popping variants under kOpcodeName_fdivp and kOpcodeName_fdivrp
// in a single function, dispatching on opcode for operand order.
//
// x87 semantics:
//   fdivp:  ST(i) = ST(i) / ST(0);  TOP = (TOP + 1) & 7
//   fdivrp: ST(i) = ST(0) / ST(i);  TOP = (TOP + 1) & 7
//
// Encoding:
//   DE F8+i  FDIVP  ST(i), ST(0) — operands = [ST(i), ST(0)]
//   DE F9    FDIVP               — implicit ST(1), ST(0); depth_dst == 1
//   DE F0+i  FDIVRP ST(i), ST(0) — operands = [ST(i), ST(0)]
//   DE F1    FDIVRP              — implicit ST(1), ST(0); depth_dst == 1
//
// Pop ordering: result is written to ST(i) before popping so the physical
// index for ST(i) is still valid under the current TOP.
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_pop
//   Wd_tmp  (gpr pool 2) -- offset scratch; reused for emit_x87_pop RMW
//   Dd_dst  (fpr free pool) -- ST(i) value; receives the result
//   Dd_src  (fpr free pool) -- ST(0) value
// =============================================================================
auto translate_fdivp(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_fdivrp = (a2->opcode == kOpcodeName_fdivrp);
    const int depth_dst = a2->operands[0].reg.reg.index();  // ST(i)
    // operands[1] is always ST(0); depth_src == 0 by definition.

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // Opt 3: load ST(0) (src) first — its offset is discarded.
    // Load ST(depth_dst) (dst) second so Wd_tmp holds offset(depth_dst).
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
    const int Wk9 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);

    if (is_fdivrp)
        emit_fdiv_f64(buf, Dd_dst, Dd_src, Dd_dst);  // ST(i) = ST(0) / ST(i)
    else
        emit_fdiv_f64(buf, Dd_dst, Dd_dst, Dd_src);  // ST(i) = ST(i) / ST(0)

    emit_store_st_at_offset(buf, Xbase, Wk9, Dd_dst, Xst_base);

    // Pop: TOP = (TOP + 1) & 7.  Wd_tmp is dead after emit_store_st_at_offset.
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FIADD — DA /0, DE /0
//
// x87 semantics:
//   ST(0) = ST(0) + ConvertToDouble(src_int)
//
// Source is a memory integer (Rosetta encodes as [mem_src, ST(0)_dst]):
//   DA /0:  FIADD m32int  — operands = [m32int MemRef, ST(0)]
//   DE /0:  FIADD m16int  — operands = [m16int MemRef, ST(0)]
//
// Destination is always ST(0).
//
// Sequence:
//   1. Load ST(0) as f64 into Dd_st0.
//   2. Compute source address → addr_reg.
//   3. Load 32-bit or 16-bit integer from memory into Wd_tmp.
//      For 16-bit: LDRH (zero-extend into W) then SXTH (sign-extend to W).
//      For 32-bit: LDR W (loads a signed 32-bit directly).
//   4. SCVTF Dd_int, Wd_tmp  — signed integer → f64.
//   5. FADD Dd_st0, Dd_st0, Dd_int.
//   6. Store result back into ST(0).
//
// Why LDRH + SXTH for 16-bit, not LDRSH?
//   emit_ldr_str_imm exposes opc=0 (STR) and opc=1 (LDR = zero-extend).
//   LDRSH uses opc=2 in the AArch64 encoding, which the helper doesn't wrap.
//   LDRH + SXTH (SBFM immr=0, imms=15) is a clean two-instruction equivalent.
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP (read-only; no push/pop here)
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_load_st, then reused as
//                           the integer load target and SCVTF source
//   Dd_st0  (fpr free pool) -- ST(0) value; receives the sum
//   Dd_int  (fpr free pool) -- converted integer value
//
auto translate_fiadd(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    // Rosetta encodes FIADD as [mem_src, ST(0)_dst]:
    //   DA /0: operands = [m32int MemRef, ST(0)]
    //   DE /0: operands = [m16int MemRef, ST(0)]
    // Source size is in operands[0].mem.size.
    const bool is_m16 = (a2->operands[0].mem.size == IROperandSize::S16);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_int = alloc_free_fpr(*a1);

    // Step 1: load ST(0).  Wd_tmp receives the byte offset for ST(0).
    const int Wk10 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: compute source memory address — allocates a separate free-pool GPR.
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 3: load integer from memory into addr_reg (reusing it for the value).
    // Opt 3: loading into addr_reg (not Wd_tmp) preserves the ST(0) byte offset
    // in Wd_tmp so emit_store_st_at_offset can skip recomputing it below.
    if (is_m16) {
        // LDRH addr_reg, [addr_reg]  — 16-bit zero-extending load
        emit_ldr_str_imm(buf, /*size=*/1 /*16-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
        // SXTH addr_reg, addr_reg  — sign-extend bits[15:0] → W
        // Encoded as SBFM W, W, #0, #15
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, addr_reg, addr_reg);
    } else {
        // LDR addr_reg, [addr_reg]  — 32-bit load (signed by virtue of SCVTF below)
        emit_ldr_str_imm(buf, /*size=*/2 /*32-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
    }

    // Step 4: convert signed integer W → f64
    // emit_scvtf: is_64bit_int=0 (32-bit source W), ftype=1 (f64 destination)
    emit_scvtf(buf, /*is_64bit_int=*/0, /*ftype=*/1, Dd_int, addr_reg);

    free_gpr(*a1, addr_reg);

    // Step 5: add
    emit_fadd_f64(buf, Dd_st0, Dd_st0, Dd_int);

    // Step 6: store result back to ST(0).
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk10, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_int);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FMUL / FMULP
//
// Handles all multiply variants under kOpcodeName_fmul and kOpcodeName_fmulp.
//
// Opcode / encoding breakdown:
//
//   kOpcodeName_fmul  (non-popping)
//     D8 C8+i  FMUL ST(0), ST(i)  — operands = [ST(0), ST(i)]   Register path
//     DC C8+i  FMUL ST(i), ST(0)  — operands = [ST(i), ST(0)]   Register path
//     D8 /1    FMUL m32fp         — operands = [m32fp MemRef]    Memory path
//     DC /1    FMUL m64fp         — operands = [m64fp MemRef]    Memory path
//
//   kOpcodeName_fmulp  (popping)
//     DE C8+i  FMULP ST(i), ST(0) — operands = [ST(i), ST(0)]   Register path
//     DE C9    FMULP              — implicit ST(1), ST(0)        Register path
//                                   (Rosetta encodes as depth_dst == 1)
//
// x87 semantics:
//   fmul  ST(dst) = ST(dst) * ST(src)        (no pop)
//   fmulp ST(i)   = ST(i)   * ST(0); TOP++   (pop after)
//
// Register allocation:
//   Xbase   (gpr pool 0) -- X87State base = X18 + x87_state_offset
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_pop
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_{load,store}_st;
//                           reused as RMW scratch inside emit_x87_pop
//   Dd_dst  (free pool)  -- destination operand; receives the product
//   Dd_src  (free pool)  -- source operand (ST-ST and memory paths)
//                           not allocated for the fmulp path (single load suffices)
//
// Memory path note:
//   Source is operands[0] (MemRef). Destination is always ST(0).
//   Mirrors translate_fadd's memory path exactly, substituting FMUL for FADD.
//
// Pop ordering (fmulp):
//   Result is written to ST(i) before popping.  Popping first would shift
//   physical indices, causing ST(i) to resolve to the wrong slot when
//   depth_dst > 0.  Matches the ordering used in translate_faddp.
// =============================================================================
auto translate_fmul(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_fmulp = (a2->opcode == kOpcodeName_fmulp);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_dst = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    if (is_fmulp) {
        // ---------------------------------------------------------------------
        // FMULP ST(i), ST(0) — DE C8+i
        //
        // ST(i) = ST(i) * ST(0); TOP = (TOP + 1) & 7
        //
        // operands[0] is ST(i) dst; operands[1] is ST(0) src (depth == 0).
        // Store result before popping so ST(i) physical index is still valid.
        // ---------------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();  // ST(i)
        // operands[1] is always ST(0); depth_src == 0 implicitly.

        // Opt 3: load ST(0) (src) first — its offset is discarded.
        // Load ST(depth_dst) (dst) second so Wd_tmp holds offset(depth_dst).
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
        const int Wk11 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);
        emit_fmul_f64(buf, Dd_dst, Dd_dst, Dd_src);
        emit_store_st_at_offset(buf, Xbase, Wk11, Dd_dst, Xst_base);

        // Pop: TOP = (TOP + 1) & 7.  Wd_tmp is dead after emit_store_st_at_offset.
        x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);
    } else if (a2->operands[0].kind == IROperandKind::Register) {
        // ---------------------------------------------------------------------
        // ST-ST path — D8 C8+i / DC C8+i
        //
        // D8 C8+i: FMUL ST(0), ST(i) — operands = [ST(0), ST(i)]
        // DC C8+i: FMUL ST(i), ST(0) — operands = [ST(i), ST(0)]
        //
        // Both encoded the same way: dst = operands[0].index,
        //                            src = operands[1].index.
        // ---------------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();
        const int depth_src = a2->operands[1].reg.reg.index();

        // Opt 3: load src first (offset discarded), then dst last so Wd_tmp
        // holds offset(depth_dst) for emit_store_st_at_offset.
        emit_load_st(buf, Xbase, Wd_top, depth_src, Wd_tmp, Dd_src, Xst_base);
        const int Wk12 = emit_load_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_dst, Xst_base);
        emit_fmul_f64(buf, Dd_dst, Dd_dst, Dd_src);
        emit_store_st_at_offset(buf, Xbase, Wk12, Dd_dst, Xst_base);
    } else {
        // ---------------------------------------------------------------------
        // Memory path — D8 /1 (m32fp) / DC /1 (m64fp)
        //
        // Rosetta encodes these as [mem_src, ST(0)_dst]:
        //   D8 /1: operands = [m32fp MemRef, ST(0)]
        //   DC /1: operands = [m64fp MemRef, ST(0)]
        //
        // Source is operands[0] (MemRef). Destination is always ST(0).
        // ---------------------------------------------------------------------
        const bool is_f32 = (a2->operands[0].mem.size == IROperandSize::S32);

        // Step 1: load ST(0) — Wd_tmp receives the byte offset for ST(0).
        const int Wk13 =
            emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_dst, Xst_base);

        // Step 2: compute memory address
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

        // Step 3: load memory operand
        //   size 2 = S-register (f32), size 3 = D-register (f64)
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        // Step 4: widen f32 → f64 if needed
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);

        // Step 5: multiply
        emit_fmul_f64(buf, Dd_dst, Dd_dst, Dd_src);

        // Step 6: store back to ST(0).
        // Opt 3: addr_reg is a separate free-pool register; Wd_tmp still holds
        // the ST(0) byte offset set by emit_load_st above.
        emit_store_st_at_offset(buf, Xbase, Wk13, Dd_dst, Xst_base);
    }

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_dst);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FST / FSTP (memory) — store ST(0) to a memory operand, optional pop.
//
// x87 semantics:
//   FST  mXX:  mem = convert(ST(0), size)
//   FSTP mXX:  mem = convert(ST(0), size); TOP = (TOP + 1) & 7
//
// operands[0] is the memory destination (IROperandMemRef).
// operands[0].size encodes the store width: S32 → float32, S64 → float64,
//                                           S80 → float80 (runtime routine).
// Source is always ST(0).
//
// Register allocation (S32 / S64 direct-emit paths):
//   Xbase   (gpr pool 0) -- X87State base
//   Wd_top  (gpr pool 1) -- current TOP; updated in-place by emit_x87_pop
//   Wd_tmp  (gpr pool 2) -- offset scratch for emit_load_st; reused as
//                           RMW scratch inside emit_x87_pop
//   Dd_src  (fpr free pool) -- ST(0) value; narrowed in-place to Sd_src for S32
//
// Register allocation (S80 runtime path):
//   Xaddr   (gpr pool 0) -- destination address passed to runtime routine
//
// FST / FSTP / FST_STACK / FSTP_STACK
//
// Opcode encoding:
//   fst        DD /2      operands[0] = MemRef m32fp/m64fp/m80fp
//   fstp       DD /3      operands[0] = MemRef m32fp/m64fp/m80fp  (+ pop)
//   fst_stack  DD C0+i    operands[0] = Register ST(i) dst
//   fstp_stack DD D8+i    operands[0] = Register ST(i) dst        (+ pop)
//
// The Register path (fst_stack / fstp_stack) copies ST(0) into ST(depth_dst).
// Special case: when dst == 0 (FST ST(0)), it is a no-op — reading and writing
// the same slot, so the load/store is skipped. The pop still fires for fstp_stack.
//
// The Memory path (fst / fstp) stores ST(0) to a memory address.
// S80 is handed off to a runtime routine (kRuntimeRoutine_fstp_fp80 / fst_fp80)
// because the 80-bit extended format has a different exponent bias (16383 vs
// 1023) and an explicit integer bit — it cannot be produced from a 64-bit double
// via a plain FCVT, and writing only 8 bytes to an m80fp destination corrupts
// the 2-byte exponent field at addr+8.
// is_f32 is only valid for the S32/S64 direct-emit memory path.
auto translate_fst(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;

    const bool is_fstp = (a2->opcode == kOpcodeName_fstp || a2->opcode == kOpcodeName_fstp_stack);

    // -------------------------------------------------------------------------
    // FSTP m80fp — DB /7  (inline double → f80 conversion + store + pop)
    //
    // Converts the IEEE 754 double in ST(0) to x87 80-bit extended format and
    // writes the 10-byte result directly to the destination memory address.
    //
    // IEEE 754 double:  [63] sign | [62:52] exp (11-bit, bias 1023) | [51:0] mantissa
    // x87 f80:          bytes 0-7 mantissa (64-bit, explicit integer bit at 63)
    //                   bytes 8-9 [15] sign | [14:0] exp (15-bit, bias 16383)
    //
    // Instruction layout (22 instructions, 3 paths):
    //   [0-4]   extract sign/exp/mantissa from double bits
    //   [5-7]   dispatch: CBZ→zero/denorm, B.EQ→inf/nan
    //   [8-14]  normal: set integer bit, bias-adjust exp, store, B .done
    //   [15-17] zero/denorm: store zero mantissa + sign, B .done
    //   [18-21] inf/nan: set integer bit, store, sign|0x7FFF, store
    //   [22]    .done: pop + end
    // -------------------------------------------------------------------------
    if (a2->operands[0].kind != IROperandKind::Register &&
        a2->operands[0].mem.size == IROperandSize::S80) {
        auto [Xbase, Wd_top] = x87_begin(*a1, buf);
        const int Xst_base = x87_get_st_base(*a1);
        const int Wd_tmp = alloc_gpr(*a1, 2);   // sign scratch, then pop scratch
        const int Xbits  = alloc_gpr(*a1, 3);   // raw double bits → f80 mantissa
        const int Wexp   = alloc_gpr(*a1, 4);   // exponent → f80 exponent word
        const int Dd_src = alloc_free_fpr(*a1);

        // Load ST(0) as double
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);

        // Compute destination address
        const int Xaddr =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

        // [0] FMOV Xbits, Dd_src — raw double bits to GPR
        emit_fmov_d_to_x(buf, Xbits, Dd_src);
        free_fpr(*a1, Dd_src);

        // [1] UBFX Xexp, Xbits, #52, #11 — extract 11-bit exponent
        emit_bitfield(buf, /*is_64bit=*/1, /*opc=*/2, /*N=*/1, /*immr=*/52, /*imms=*/62,
                      Xbits, Wexp);

        // [2] LSR Wd_tmp, Xbits, #48 — shift sign from bit 63 to bit 15
        emit_bitfield(buf, 1, 2, 1, 48, 63, Xbits, Wd_tmp);

        // [3] AND Wd_tmp, Wd_tmp, #0x8000 — isolate sign at bit 15
        LogicalImmEncoding enc_sign;
        is_bitmask_immediate(/*is_64bit=*/false, 0x8000, enc_sign);
        emit_and_imm(buf, 0, Wd_tmp, enc_sign.N, enc_sign.immr, enc_sign.imms, Wd_tmp);

        // [4] LSL Xbits, Xbits, #11 — position 52-bit mantissa for f80 (bits [63:12])
        //     UBFM Xd, Xn, #53, #52 is the alias for LSL Xd, Xn, #11
        emit_bitfield(buf, 1, 2, 1, 53, 52, Xbits, Xbits);

        // [5] CBZ Wexp, .zero_denorm (+10 insns = +40 bytes)
        buf.emit(0x34000000u | (10u << 5) | uint32_t(Wexp));

        // [6] CMP Wexp, #0x7FF  (SUBS WZR, Wexp, #2047)
        emit_add_imm(buf, /*is_64bit=*/0, /*is_sub=*/1, /*is_set_flags=*/1,
                     /*shift=*/0, /*imm12=*/0x7FF, Wexp, /*Rd=*/31);

        // [7] B.EQ .inf_nan (+11 insns = +44 bytes)
        buf.emit(0x54000000u | (11u << 5) | 0x0u);

        // ── Normal number ──
        // [8] ORR Xbits, Xbits, #0x8000000000000000 — set explicit integer bit
        LogicalImmEncoding enc_intbit;
        is_bitmask_immediate(/*is_64bit=*/true, 0x8000000000000000ULL, enc_intbit);
        emit_orr_imm(buf, 1, Xbits, Xbits, enc_intbit.N, enc_intbit.immr, enc_intbit.imms);

        // [9]  ADD Wexp, Wexp, #3, LSL#12  (+12288)
        emit_add_imm(buf, 0, 0, 0, /*shift=*/1, /*imm12=*/3, Wexp, Wexp);
        // [10] ADD Wexp, Wexp, #0xC00      (+3072; total +15360 = 16383−1023)
        emit_add_imm(buf, 0, 0, 0, 0, 0xC00, Wexp, Wexp);

        // [11] ORR Wexp, Wexp, Wd_tmp — combine biased exponent + sign
        emit_logical_shifted_reg(buf, 0, /*opc=*/1, /*n=*/0, /*shift_type=*/0,
                                 Wd_tmp, /*shift_amount=*/0, Wexp, Wexp);

        // [12] STR Xbits, [Xaddr] — 8-byte mantissa
        emit_str_imm(buf, /*size=*/3, Xbits, Xaddr, /*imm12=*/0);
        // [13] STRH Wexp, [Xaddr, #8] — 2-byte exponent (imm12=4, scaled by 2)
        emit_str_imm(buf, /*size=*/1, Wexp, Xaddr, /*imm12=*/4);

        // [14] B .done (+8 insns = +32 bytes)
        buf.emit(0x14000000u | 8u);

        // ── Zero / denormal (treated as ±0.0) ──
        // [15] STR XZR, [Xaddr] — mantissa = 0
        emit_str_imm(buf, 3, /*Rt=*/31, Xaddr, 0);
        // [16] STRH Wd_tmp, [Xaddr, #8] — exponent = sign only
        emit_str_imm(buf, 1, Wd_tmp, Xaddr, 4);
        // [17] B .done (+5 insns = +20 bytes)
        buf.emit(0x14000000u | 5u);

        // ── Infinity / NaN ──
        // [18] ORR Xbits, Xbits, #0x8000000000000000 — set explicit integer bit
        emit_orr_imm(buf, 1, Xbits, Xbits, enc_intbit.N, enc_intbit.immr, enc_intbit.imms);
        // [19] STR Xbits, [Xaddr] — mantissa
        emit_str_imm(buf, 3, Xbits, Xaddr, 0);
        // [20] ORR Wexp, Wd_tmp, #0x7FFF — sign | max exponent
        LogicalImmEncoding enc_7fff;
        is_bitmask_immediate(/*is_64bit=*/false, 0x7FFF, enc_7fff);
        emit_orr_imm(buf, 0, Wexp, Wd_tmp, enc_7fff.N, enc_7fff.immr, enc_7fff.imms);
        // [21] STRH Wexp, [Xaddr, #8] — exponent
        emit_str_imm(buf, 1, Wexp, Xaddr, 4);

        // ── .done ──
        free_gpr(*a1, Xaddr);
        free_gpr(*a1, Wexp);
        free_gpr(*a1, Xbits);

        // Pop (always true for m80fp — there is no non-popping FST m80fp)
        if (is_fstp)
            x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

        free_fpr(*a1, Dd_src);
        x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
        free_gpr(*a1, Wd_tmp);
        return;
    }

    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_src = alloc_free_fpr(*a1);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // -----------------------------------------------------------------
        // Register path — fst_stack / fstp_stack
        //
        // operands[0] = ST(i) destination register
        // Copies ST(0) → ST(depth_dst). When depth_dst == 0 the copy is a
        // no-op (same slot). The pop still fires for fstp_stack.
        // -----------------------------------------------------------------
        const int depth_dst = a2->operands[0].reg.reg.index();

        if (depth_dst != 0) {
            // Load ST(0), store into ST(depth_dst).
            emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
            emit_store_st(buf, Xbase, Wd_top, depth_dst, Wd_tmp, Dd_src, Xst_base);
        }
        // else: ST(0) → ST(0) is a no-op, skip load+store.
    } else {
        // -----------------------------------------------------------------
        // Memory path — fst / fstp  (S32 and S64 only; S80 handled above)
        // -----------------------------------------------------------------
        const bool is_f32 = (a2->operands[0].mem.size == IROperandSize::S32);

        // Load ST(0) as f64, then narrow to f32 if needed.
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_src, Xst_base);
        if (is_f32)
            emit_fcvt_d_to_s(buf, Dd_src, Dd_src);

        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);
        emit_fstr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);
    }

    // Pop if FSTP / FSTP_STACK: TOP = (TOP + 1) & 7.
    if (is_fstp)
        x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    free_fpr(*a1, Dd_src);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FNSTSW — store x87 status_word to AX or memory.
//
// x87 semantics:
//   FNSTSW AX   (DF E0): AX ← status_word   (16-bit value into bits[15:0] of EAX)
//   FNSTSW m16  (DD /7): mem16 ← status_word
//
// Opcode encoding (Rosetta strips the FN prefix):
//   fstsw   DD /7   operands[0] = MemRef m16   (memory destination)
//   fstsw   DF E0   operands[0] = Register AX  (register destination)
//
// The AX path reads the status_word as a 16-bit halfword and inserts it into
// bits[15:0] of W0 (the 32-bit view of RAX) via BFI, leaving bits[31:16]
// untouched so the upper 16 bits of EAX are preserved per x86 semantics.
//
// BFI W_ax, Wd_sw, #0, #16  encodes as BFM with immr=0, imms=15:
//   When immr <= imms: inserts Wn[imms-immr : 0] = Wn[15:0] into Wd[15:0].
//
// The memory path just stores the 16-bit halfword directly via STRH.
//
// Register allocation:
//   Xbase   (gpr pool 0) — X87State base (X18 + x87_state_offset)
//   Wd_sw   (gpr pool 1) — loaded status_word (16-bit); becomes the store src
//   addr_reg (free pool) — memory path only: effective address from
//                          compute_operand_address; freed after STRH
//
// No TOP mutation.  No FPR needed.  Two pool registers suffice for both paths.
// =============================================================================
auto translate_fstsw(TranslationResult* a1, IRInstr* a2) -> void {
    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;  // = 1

    AssemblerBuffer& buf = a1->insn_buf;

    // OPT-1: fstsw only needs Xbase, not TOP.  Use the cache for Xbase if
    // active; allocate Wd_sw from the free pool (not pool slot 1, which is
    // pinned for TOP when the cache is active).
    const bool base_cached = (a1->x87_cache_run_remaining > 0 && a1->x87_cache_gprs_valid);
    int Xbase;
    if (base_cached) {
        Xbase = a1->x87_cache_base_gpr;
    } else {
        Xbase = alloc_gpr(*a1, 0);
        emit_x87_base(buf, *a1, Xbase);
    }
    const int Wd_sw = base_cached ? alloc_free_gpr(*a1) : alloc_gpr(*a1, 1);

    // OPT-C: If a prior deferred push left TOP dirty, flush it now — FSTSW
    // reads status_word from memory and needs the correct TOP.
    // Use Wd_sw as scratch for store_top (it hasn't been loaded yet).
    if (a1->x87_cache_top_dirty && base_cached) {
        emit_store_top(buf, Xbase, a1->x87_cache_top_gpr, Wd_sw);
        a1->x87_cache_top_dirty = 0;
    }

    // LDRH Wd_sw, [Xbase, #0x02]   — load status_word (16-bit halfword)
    // imm12=1 because LDRH scales by 2: byte offset = 1*2 = 2
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1, kX87StatusWordImm12, Xbase, Wd_sw);

    if (a2->operands[0].kind == IROperandKind::Register) {
        // -----------------------------------------------------------------
        // AX path — FNSTSW AX  (DF E0)
        //
        // operands[0].reg.reg.value == 0x30 (size_class=3 → 16-bit, index=0 → AX)
        //
        // In Rosetta's GPR mapping, x86 register index 0 (RAX) maps directly
        // to AArch64 register X0.  Write the status_word into bits[15:0] of W0,
        // leaving the upper 16 bits of EAX untouched.
        //
        // BFI W0, Wd_sw, #lsb=0, #width=16
        //   → BFM immr=(32-0)&31=0, imms=width-1=15
        //   → copies Wd_sw[15:0] into W0[15:0]
        // -----------------------------------------------------------------
        const int W_ax = a2->operands[0].reg.reg.index();  // = 0 (RAX/EAX/AX)

        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/1 /*BFM*/,
                      /*N=*/0, /*immr=*/0, /*imms=*/15,
                      /*Rn=*/Wd_sw, /*Rd=*/W_ax);
    } else {
        // -----------------------------------------------------------------
        // Memory path — FNSTSW m16  (DD /7)
        //
        // Compute destination address, then STRH the status_word.
        // -----------------------------------------------------------------
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

        // STRH Wd_sw, [addr_reg, #0]
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/0,
                         /*imm12=*/0, addr_reg, Wd_sw);

        free_gpr(*a1, addr_reg);
    }

    free_gpr(*a1, Wd_sw);
    if (!base_cached)
        free_gpr(*a1, Xbase);
}

// =============================================================================
// FCOM / FCOMP / FCOMPP — compare ST(0) with a source operand, update C0/C2/C3
// in the x87 status_word, and optionally pop the stack.
//
// x87 semantics:
//   FCOM   ST(i) / m32fp / m64fp  — compare, no pop
//   FCOMP  ST(i) / m32fp / m64fp  — compare, pop once  (TOP++)
//   FCOMPP                        — compare ST(0) vs ST(1), pop twice
//
// AArch64 FCMP flag semantics (verified against ARM DDI 0487):
//   ST(0) > src:  N=0, Z=0, C=1, V=0
//   ST(0) < src:  N=1, Z=0, C=0, V=0
//   ST(0) = src:  N=0, Z=1, C=1, V=0
//   Unordered:    N=0, Z=0, C=1, V=1   ← Z is NOT set for unordered!
//
// C0/C2/C3 derivation (all four cases verified):
//   C3 = EQ | VS  = (Z==1) | (V==1)    ← needs both; Z alone misses unordered
//   C2 = VS       = (V==1)
//   C0 = CC | VS  = (C==0) | (V==1)    ← CC alone misses unordered when C=1
//
//   GT: Z=0,C=1,V=0 → C3=0, C2=0, C0=0  ✓
//   LT: Z=0,C=0,V=0 → C3=0, C2=0, C0=1  ✓
//   EQ: Z=1,C=1,V=0 → C3=1, C2=0, C0=0  ✓
//   UN: Z=0,C=1,V=1 → C3=1, C2=1, C0=1  ✓
//
// NOTE: emit_fcom_flags_to_sw() is NOT used here. That helper derives C0
// directly from the C flag and C3 from Z alone — both wrong for some cases.
//
// Operand encoding (Rosetta convention, matching fadd):
//   All forms:   operands[0] = ST(0) Register  (implicit)
//   Register:    operands[1] = ST(i) Register  (comparand depth)
//   Memory:      operands[1] = m32/64fp MemRef (comparand address)
//   FCOMPP:      no operands at all (is_fcompp flag used instead)
//
//   Dispatch uses operands[1].kind, NOT operands[0].kind, because the memory
//   form also has a Register at operands[0] (ST(0)), so checking [0] alone
//   cannot distinguish the register form from the memory form.
//
// Register allocation:
//   Xbase   (gpr pool 0) — X87State base
//   Wd_top  (gpr pool 1) — current TOP; updated by each emit_x87_pop
//   Wd_tmp  (gpr pool 2) — scratch for emit_load_st and CSET results
//   Wd_tmp2 (gpr pool 3) — accumulates packed C3/C2/C0 bits
//   Dd_st0  (fpr free)   — ST(0) value
//   Dd_src  (fpr free)   — comparand value
//   addr_reg (free gpr)  — memory path only: effective address; freed after fldr
// =============================================================================
auto translate_fcom(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;  // = 1

    const bool is_fcompp = (a2->opcode == kOpcodeName_fcompp || a2->opcode == kOpcodeName_fucompp);
    const bool is_popping = (a2->opcode == kOpcodeName_fcomp || a2->opcode == kOpcodeName_fcompp ||
                             a2->opcode == kOpcodeName_fucomp || a2->opcode == kOpcodeName_fucompp);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // Step 1: load ST(0) into Dd_st0.
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: load the comparand into Dd_src.
    if (is_fcompp) {
        // FCOMPP: comparand is always ST(1).
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/1, Wd_tmp, Dd_src, Xst_base);
    } else if (a2->operands[1].kind == IROperandKind::Register) {
        // FCOM / FCOMP ST(i): Rosetta encodes as [ST(0) Register, ST(i) Register].
        // operands[0] = ST(0) (implicit), operands[1] = ST(i) (comparand).
        // We check operands[1] (not [0]) because the memory path also has a
        // Register at operands[0] (ST(0)), so checking [0] alone can't distinguish.
        const int depth = a2->operands[1].reg.reg.index();
        emit_load_st(buf, Xbase, Wd_top, depth, Wd_tmp, Dd_src, Xst_base);
    } else {
        // FCOM / FCOMP m32fp / m64fp.
        // Rosetta encodes as [ST(0) Register, mem MemRef].
        // The memory operand is operands[1].
        const bool is_f32 = (a2->operands[1].mem.size == IROperandSize::S32);

        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[1], GPR::XZR);

        // size 2 = S (f32), size 3 = D (f64)
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);

        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);
    }

    // Step 3: Save host NZCV, compare, map flags, restore NZCV.
    //
    // CRITICAL: Rosetta maps x86 EFLAGS to AArch64 NZCV.  Non-x87 instructions
    // like TEST/CMP set NZCV, and subsequent Jcc reads it.  If an x87 FCOM sits
    // between a TEST and a Jcc, our FCMP would clobber NZCV and the Jcc would
    // branch on the FP comparison result instead of the TEST result.
    //
    // Fix: MRS to save NZCV into a GPR before FCMP, then MSR to restore after
    // we've finished reading the FP condition codes.
    //
    // MRS NZCV encoding: 0xD53B4200 | Rt   (op0=3, op1=3, CRn=4, CRm=2, op2=0, L=1)
    // MSR NZCV encoding: 0xD51B4200 | Rt   (same sysreg, L=0)
    //
    // NOTE: emit_mrs_nzcv in AssemblerHelpers uses 0xD5334200 which has o0=0
    // (op0=2, debug registers) — WRONG and crashes at El0.  We inline the
    // correct encoding here.

    // MRS Wd_tmp2, NZCV — save current NZCV (from prior x86 ALU ops)
    buf.emit(0xD53B4200u | uint32_t(Wd_tmp2));

    // FCMP Dd_st0, Dd_src — clobbers NZCV with FP comparison result
    emit_fcmp_f64(buf, Dd_st0, Dd_src);

    // FPRs are no longer needed.
    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_st0);

    // Step 4: Map FCMP NZCV → x87 CC bits via conditional branches, then
    // restore the saved NZCV so subsequent x86 Jcc sees the correct flags.
    //
    // AArch64 FCMP sets NZCV:
    //   GT: 0010  LT: 1000  EQ: 0110  UN: 0011
    //
    // B.GT  = !(Z) && (N==V) — true for GT only  (excludes UN: N=0,V=1)
    // B.MI  = N==1           — true for LT only
    // B.VC  = V==0           — true for GT, LT, EQ (excludes UN)
    //
    // Code layout (7 insns for flag mapping + 1 for MSR restore):
    //   pos 0: MOVZ  Wd_tmp, #0x0000       GT
    //   pos 1: B.GT  +6 → pos 7            GT confirmed
    //   pos 2: MOVZ  Wd_tmp, #0x0100       LT (C0=1)
    //   pos 3: B.MI  +4 → pos 7            LT confirmed (N==1)
    //   pos 4: MOVZ  Wd_tmp, #0x4000       EQ (C3=1)
    //   pos 5: B.VC  +2 → pos 7            EQ confirmed (V==0)
    //   pos 6: MOVZ  Wd_tmp, #0x4500       UN (C0|C2|C3) — fallthrough
    //   pos 7: MSR   NZCV, Wd_tmp2         restore saved flags

    // B.cond encoding: 0x54000000 | (imm19 << 5) | cond
    //   GT=0xC, MI=0x4, VC=0x7

    emit_movn(buf, 0, 2, 0, 0x0000, Wd_tmp);   // pos 0
    buf.emit(0x54000000u | (6u << 5) | 0xCu);  // pos 1: B.GT +6
    emit_movn(buf, 0, 2, 0, 0x0100, Wd_tmp);   // pos 2
    buf.emit(0x54000000u | (4u << 5) | 0x4u);  // pos 3: B.MI +4
    emit_movn(buf, 0, 2, 0, 0x4000, Wd_tmp);   // pos 4
    buf.emit(0x54000000u | (2u << 5) | 0x7u);  // pos 5: B.VC +2
    emit_movn(buf, 0, 2, 0, 0x4500, Wd_tmp);   // pos 6

    // pos 7: MSR NZCV, Wd_tmp2 — restore the saved x86 EFLAGS
    buf.emit(0xD51B4200u | uint32_t(Wd_tmp2));

    free_gpr(*a1, Wd_tmp2);

    // Wd_tmp holds the new CC bits (0x0000 / 0x0100 / 0x4000 / 0x4500).
    // RMW status_word: load, clear C0|C2|C3, OR in new bits, store.
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // LDRH Wd_sw, [Xbase, #0x02]
        emit_ldr_str_imm(buf, 1, 0, 1, kX87StatusWordImm12, Xbase, Wd_sw);

        // Clear bits 8, 10, 14 (C0, C2, C3) — matches helper library
        emit_bitfield(buf, 0, 1, 0, 24, 0, GPR::XZR, Wd_sw);  // bit 8
        emit_bitfield(buf, 0, 1, 0, 22, 0, GPR::XZR, Wd_sw);  // bit 10
        emit_bitfield(buf, 0, 1, 0, 18, 0, GPR::XZR, Wd_sw);  // bit 14

        // ORR Wd_sw, Wd_sw, Wd_tmp
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);

        // STRH Wd_sw, [Xbase, #0x02]
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // Step 5: pop the stack as required.
    // Wd_tmp is dead after the status_word store — safe to reuse as RMW scratch.
    if (is_popping) {
        if (is_fcompp)
            x87_pop_n(buf, *a1, Xbase, Wd_top, Wd_tmp, 2);  // OPT-A: fused double-pop
        else
            x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);
    }

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FXCH — exchange ST(0) with ST(i).
//
// x87 semantics:
//   FXCH ST(i)   D9 C8+i   swap ST(0) ↔ ST(i)
//
// Special case: FXCH ST(0) is a no-op (swapping a register with itself).
// Rosetta may or may not filter this upstream; we guard it explicitly.
//
// Both slots are already live on the stack, so the tag word does not change.
// No push or pop — TOP is read for addressing but never mutated.
//
// Instruction sequence:
//   1. load ST(0)    → Dd_a
//   2. load ST(i)    → Dd_b
//   3. store Dd_b    → ST(0)     (write ST(i)'s value into slot 0)
//   4. store Dd_a    → ST(i)     (write ST(0)'s value into slot i)
//
// Store ordering is safe: emit_store_st computes the physical slot from Wd_top
// + depth each time, and Wd_top is not modified between the two stores, so both
// slots resolve correctly regardless of order.
//
// Register allocation:
//   Xbase  (gpr pool 0) — X87State base
//   Wd_top (gpr pool 1) — current TOP (read-only; no push/pop)
//   Wd_tmp (gpr pool 2) — offset scratch for emit_{load,store}_st
//   Dd_a   (fpr free)   — holds ST(0) value
//   Dd_b   (fpr free)   — holds ST(i) value
// =============================================================================
auto translate_fxch(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    // Rosetta normalizes register operands as [ST(0), ST(i)], so the target
    // depth is at operands[1] — not operands[0].  Reading [0] always gives
    // depth=0, which fires the no-op guard every time and silently skips
    // every swap.  Matches the convention used by translate_fld register path.
    const int depth = a2->operands[1].reg.reg.index();  // ST(i)

    // FXCH ST(0) is a no-op — but must still call x87_end for
    // end-of-run dirty flush (OPT-C).
    if (depth == 0) {
        const int Wd_scratch = alloc_gpr(*a1, 2);
        x87_end(*a1, buf, Xbase, Wd_top, Wd_scratch);
        free_gpr(*a1, Wd_scratch);
        return;
    }

    // OPT-E: Use two offset registers to avoid recomputing offset_0 for the
    // second store.  Saves 3 insns (15 → 12) by replacing emit_store_st
    // (which recomputes the offset via emit_st_offset) with a second
    // emit_store_st_at_offset using the preserved Wd_off0.
    const int Wd_off0 = alloc_gpr(*a1, 2);  // byte offset of ST(0)
    const int Wd_offi = alloc_gpr(*a1, 3);  // byte offset of ST(i)
    const int Dd_a = alloc_free_fpr(*a1);
    const int Dd_b = alloc_free_fpr(*a1);

    const int Wk15 = emit_load_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_off0, Dd_a,
                                  Xst_base);  // Wd_off0 = offset(0)
    const int Wk14 =
        emit_load_st(buf, Xbase, Wd_top, depth, Wd_offi, Dd_b, Xst_base);  // Wd_offi = offset(i)

    emit_store_st_at_offset(buf, Xbase, Wk14, Dd_a, Xst_base);  // ST(i) ← old ST(0)
    emit_store_st_at_offset(buf, Xbase, Wk15, Dd_b, Xst_base);  // ST(0) ← old ST(i)

    free_fpr(*a1, Dd_b);
    free_fpr(*a1, Dd_a);
    free_gpr(*a1, Wd_offi);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_off0);  // use Wd_off0 as scratch
    free_gpr(*a1, Wd_off0);
}

// =============================================================================
// FCHS — change sign of ST(0).
//
// x87 semantics:
//   FCHS   D9 E0   ST(0) ← −ST(0)
//
// No explicit operands; ST(0) is always the source and destination.
// No stack mutation — TOP is read for addressing only.
//
// Instruction sequence:
//   1. load ST(0) → Dd
//   2. FNEG Dd, Dd
//   3. store Dd   → ST(0)
//
// Register allocation:
//   Xbase  (gpr pool 0) — X87State base
//   Wd_top (gpr pool 1) — current TOP (read-only)
//   Wd_tmp (gpr pool 2) — offset scratch for emit_{load,store}_st
//   Dd     (fpr free)   — ST(0) value
// =============================================================================
auto translate_fchs(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd = alloc_free_fpr(*a1);

    const int Wk16 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd, Xst_base);
    emit_fneg_f64(buf, Dd, Dd);
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk16, Dd, Xst_base);

    free_fpr(*a1, Dd);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FABS — absolute value of ST(0).
//
// x87 semantics:
//   FABS   D9 E1   ST(0) ← |ST(0)|
//
// No explicit operands; ST(0) is always the source and destination.
// No stack mutation — TOP is read for addressing only.
//
// Instruction sequence:
//   1. load ST(0) → Dd
//   2. FABS Dd, Dd
//   3. store Dd   → ST(0)
//
// Register allocation: identical to translate_fchs.
// =============================================================================
auto translate_fabs(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd = alloc_free_fpr(*a1);

    const int Wk17 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd, Xst_base);
    emit_fabs_f64(buf, Dd, Dd);
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk17, Dd, Xst_base);

    free_fpr(*a1, Dd);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FSQRT — square root of ST(0).
//
// x87 semantics:
//   FSQRT  D9 FA   ST(0) ← sqrt(ST(0))
//
// No explicit operands; ST(0) is always the source and destination.
// No stack mutation — TOP is read for addressing only.
//
// Instruction sequence:
//   1. load ST(0) → Dd
//   2. FSQRT Dd, Dd
//   3. store Dd   → ST(0)
//
// Register allocation: identical to translate_fchs.
// =============================================================================
auto translate_fsqrt(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd = alloc_free_fpr(*a1);

    const int Wk18 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd, Xst_base);
    emit_fsqrt_f64(buf, Dd, Dd);
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk18, Dd, Xst_base);

    free_fpr(*a1, Dd);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FISTP — store ST(0) as signed integer to memory, then pop
//
// x87 semantics:
//   mem ← (int) ST(0)    (truncate toward zero, i.e. FCVTZS)
//   TOP ← (TOP + 1) & 7
//
// Operand encoding (Rosetta encodes memory destination at operands[0]):
//   DF /2   FISTP m16int   operands[0].mem.size = S16
//   DB /3   FISTP m32int   operands[0].mem.size = S32
//   DF /7   FISTP m64int   operands[0].mem.size = S64
//
// Instruction sequence:
//   1. load ST(0) mantissa → Dd_val
//   2. FCVTZS Wd_int/Xd_int, Dd_val   (truncate toward zero)
//   3. compute destination address → addr_reg
//   4. STRH/STR Wd_int or STR Xd_int  (size matches operand)
//   5. free addr_reg
//   6. emit_x87_pop                   (TOP++, updates status_word)
//
// For S16: FCVTZS to W (32-bit), STRH stores low 16 bits.
// For S32: FCVTZS to W (32-bit), STR stores 32 bits.
// For S64: FCVTZS to X (64-bit, is_64bit_int=1), STR stores 64 bits.
// The register number for Wd_int and Xd_int is the same; only the instruction
// width differs via the size and is_64bit_int parameters.
//
// Register allocation:
//   Xbase   (gpr pool 0) — X87State base
//   Wd_top  (gpr pool 1) — current TOP; updated by emit_x87_pop
//   Wd_tmp  (gpr pool 2) — offset scratch (emit_load_st, emit_x87_pop)
//   Wd_int  (free pool)  — FCVTZS result (W or X view of same reg)
//   Dd_val  (fpr free)   — ST(0) mantissa
//   addr_reg (free pool) — destination address; freed before pop
// =============================================================================
auto translate_fistp(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const IROperandSize int_size = a2->operands[0].mem.size;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_int = alloc_free_gpr(*a1);
    const int Dd_val = alloc_free_fpr(*a1);

    // Step 1: load ST(0) mantissa → Dd_val
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_val, Xst_base);

    // Step 2: convert f64 to signed integer, respecting the rounding mode in
    // control_word bits [11:10] (RC field).
    //
    // x87 RC → AArch64 FCVT instruction:
    //   RC=00 (RN nearest)    → FCVTNS  aarch64_rmode=0
    //   RC=01 (RD toward -∞)  → FCVTMS  aarch64_rmode=2
    //   RC=10 (RU toward +∞)  → FCVTPS  aarch64_rmode=1
    //   RC=11 (RZ truncate)   → FCVTZS  aarch64_rmode=3
    //
    // FCVTZS (always-truncate) is WRONG when RC=01 (floor). That is the
    // classic FLDCW+FISTP pattern used by this game for coordinate rounding,
    // and it causes incorrect tile/chunk indexing for negative coordinates
    // (e.g. position -0.1 truncates to 0 instead of flooring to -1).
    //
    // All four FCVT*S variants share the same encoding structure:
    //   base = 0x1E200000 | (sf<<31) | (ftype<<22) | (aarch64_rmode<<19)
    //   insn = base | (Rn<<5) | Rd
    //
    // We dispatch at runtime via a 3-branch CBZ chain. The fall-through path
    // (RC=3, truncate) is kept last since it is the default x87 mode and
    // requires no rounding-specific branch. All branch offsets are fixed and
    // small — no fixup system is needed.
    //
    //   Instruction layout (each idx = 1 AArch64 instruction = 4 bytes):
    //   [0] LDRH  Wd_rc, [Xbase, #0]          ; load control_word
    //   [1] UBFM  Wd_rc, Wd_rc, #10, #11      ; UBFX bits[11:10] → bits[1:0]
    //   [2] CBZ   Wd_rc, +28                  ; RC==0 → [9] FCVTNS
    //   [3] SUB   Wd_rc, Wd_rc, #1
    //   [4] CBZ   Wd_rc, +28                  ; RC==1 → [11] FCVTMS
    //   [5] SUB   Wd_rc, Wd_rc, #1
    //   [6] CBZ   Wd_rc, +28                  ; RC==2 → [13] FCVTPS
    //   [7] FCVTZS Wd_int, Dd_val             ; RC=3 truncate (fall-through)
    //   [8] B     +24                         ; → [14] done
    //   [9] FCVTNS Wd_int, Dd_val             ; RC=0 nearest
    //  [10] B     +16                         ; → [14] done
    //  [11] FCVTMS Wd_int, Dd_val             ; RC=1 floor (the crash case)
    //  [12] B     +8                          ; → [14] done
    //  [13] FCVTPS Wd_int, Dd_val             ; RC=2 ceil
    //  [14] ; done — fall through to store
    //
    // Wd_rc reuses Wd_tmp (free after emit_load_st).
    //
    // FCVT*S encoding: 0x1E200000 | (sf<<31) | (ftype<<22) | (aarch64_rmode<<19) | (Rn<<5) | Rd
    //   sf=0 for 32-bit int result, sf=1 for 64-bit.  ftype=1 for f64 source.
    //   rmode field: NS=0, PS=1, MS=2, ZS=3.

    const int is_64bit_int = (int_size == IROperandSize::S64) ? 1 : 0;
    const int Wd_rc = Wd_tmp;  // free after emit_load_st — reuse as RC scratch

    // [0] LDRH Wd_rc, [Xbase, #0]  ; control_word (offset 0, imm12=0)
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, /*imm12=*/0, Xbase, Wd_rc);

    // [1] UBFX Wd_rc, Wd_rc, #10, #2  → bits[11:10] in bits[1:0]
    // UBFM: immr=lsb=10, imms=lsb+width-1=11
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0, /*immr*/ 10, /*imms*/ 11, Wd_rc, Wd_rc);

    // [2] CBZ Wd_rc, +28  (+7 instructions → idx 9)
    // CBZ encoding: 0x34000000 | (imm19<<5) | Rt;  imm19 = byte_offset/4
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));

    // [3] SUB Wd_rc, Wd_rc, #1
    emit_add_imm(buf, /*is_64=*/0, /*is_sub*/ 1, /*S*/ 0, /*shift*/ 0, 1, Wd_rc, Wd_rc);

    // [4] CBZ Wd_rc, +28  (+7 instructions → idx 11)
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));

    // [5] SUB Wd_rc, Wd_rc, #1
    emit_add_imm(buf, /*is_64=*/0, /*is_sub*/ 1, /*S*/ 0, /*shift*/ 0, 1, Wd_rc, Wd_rc);

    // [6] CBZ Wd_rc, +28  (+7 instructions → idx 13)
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));

    // Helper lambda (expressed as inline macro-style) to emit FCVT*S:
    // base = 0x1E200000 | (sf<<31) | (ftype=1<<22) | (rmode<<19) | (Rn<<5) | Rd
    const uint32_t fcvt_base = 0x1E200000u | (uint32_t(is_64bit_int) << 31) |
                               (1u << 22)  // ftype=01 (f64)
                               | (uint32_t(Dd_val & 0x1F) << 5) | uint32_t(Wd_int & 0x1F);

    // [7] FCVTZS (rmode=3 → aarch64_rmode=3)  RC=3 truncate
    buf.emit(fcvt_base | (3u << 19));
    // [8] B +24  (+6 instructions → idx 14)
    buf.emit(0x14000000u | 6u);

    // [9] FCVTNS (rmode=0 → aarch64_rmode=0)  RC=0 nearest
    buf.emit(fcvt_base | (0u << 19));
    // [10] B +16  (+4 instructions → idx 14)
    buf.emit(0x14000000u | 4u);

    // [11] FCVTMS (rmode=2 → aarch64_rmode=2)  RC=1 floor  ← fixes the crash
    buf.emit(fcvt_base | (2u << 19));
    // [12] B +8  (+2 instructions → idx 14)
    buf.emit(0x14000000u | 2u);

    // [13] FCVTPS (rmode=1 → aarch64_rmode=1)  RC=2 ceil
    buf.emit(fcvt_base | (1u << 19));
    // [14] done — Wd_int now holds the correctly rounded integer.

    // Step 3: compute destination address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 4: store integer to memory
    // size=1 → STRH (16-bit, stores low 16 bits of Wd_int)
    // size=2 → STR  (32-bit W)
    // size=3 → STR  (64-bit X — same register number as Wd_int)
    const int store_size = (int_size == IROperandSize::S16)   ? 1
                           : (int_size == IROperandSize::S32) ? 2
                                                              : 3;
    emit_str_imm(buf, store_size, Wd_int, addr_reg, /*imm12=*/0);

    // Step 5: free addr_reg
    free_gpr(*a1, addr_reg);

    // Step 6: pop — TOP++, updates status_word.  Wd_tmp is clean here.
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    free_fpr(*a1, Dd_val);
    free_gpr(*a1, Wd_int);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FIDIV — divide ST(0) by integer from memory
//
// x87 semantics:
//   ST(0) ← ST(0) / (double)(signed integer at mem)
//
// Operand encoding (memory source at operands[0]):
//   DE /6   FIDIV m16int   operands[0].mem.size = S16
//   DA /6   FIDIV m32int   operands[0].mem.size = S32
//
// Instruction sequence: identical to translate_fiadd but with FDIV.
// Register allocation: identical to translate_fiadd.
// =============================================================================
auto translate_fidiv(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_m16 = (a2->operands[0].mem.size == IROperandSize::S16);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_int = alloc_free_fpr(*a1);

    // Step 1: load ST(0).  Wd_tmp receives the byte offset for ST(0).
    const int Wk19 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: compute source address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 3: load integer from memory into addr_reg (reusing it for the value).
    // Opt 3: loading into addr_reg (not Wd_tmp) preserves the ST(0) byte offset
    // in Wd_tmp so emit_store_st_at_offset can skip recomputing it below.
    if (is_m16) {
        emit_ldr_str_imm(buf, /*size=*/1 /*16-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
        // SXTH addr_reg, addr_reg — sign-extend bits[15:0] → W
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, addr_reg, addr_reg);
    } else {
        emit_ldr_str_imm(buf, /*size=*/2 /*32-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
    }

    // Step 4: SCVTF Dd_int, addr_reg — signed W → f64
    emit_scvtf(buf, /*is_64bit_int=*/0, /*ftype=*/1, Dd_int, addr_reg);

    free_gpr(*a1, addr_reg);

    // Step 5: FDIV ST(0), integer
    emit_fdiv_f64(buf, Dd_st0, Dd_st0, Dd_int);

    // Step 6: store result back to ST(0).
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk19, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_int);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FIMUL — multiply ST(0) by integer from memory
//
// x87 semantics:
//   ST(0) ← ST(0) * (double)(signed integer at mem)
//
// Operand encoding (memory source at operands[0]):
//   DE /1   FIMUL m16int   operands[0].mem.size = S16
//   DA /1   FIMUL m32int   operands[0].mem.size = S32
//
// Instruction sequence: identical to translate_fidiv but with FMUL.
// Register allocation: identical to translate_fidiv.
// =============================================================================
auto translate_fimul(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_m16 = (a2->operands[0].mem.size == IROperandSize::S16);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_int = alloc_free_fpr(*a1);

    // Step 1: load ST(0).  Wd_tmp receives the byte offset for ST(0).
    const int Wk20 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: compute source address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 3: load integer from memory into addr_reg (reusing it for the value).
    // Opt 3: loading into addr_reg (not Wd_tmp) preserves the ST(0) byte offset
    // in Wd_tmp so emit_store_st_at_offset can skip recomputing it below.
    if (is_m16) {
        emit_ldr_str_imm(buf, /*size=*/1 /*16-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
        // SXTH addr_reg, addr_reg — sign-extend bits[15:0] → W
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, addr_reg, addr_reg);
    } else {
        emit_ldr_str_imm(buf, /*size=*/2 /*32-bit*/, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
    }

    // Step 4: SCVTF Dd_int, addr_reg — signed W → f64
    emit_scvtf(buf, /*is_64bit_int=*/0, /*ftype=*/1, Dd_int, addr_reg);

    free_gpr(*a1, addr_reg);

    // Step 5: FMUL ST(0), integer
    emit_fmul_f64(buf, Dd_st0, Dd_st0, Dd_int);

    // Step 6: store result back to ST(0).
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk20, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_int);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FISUB — subtract integer from ST(0)
//
// x87 semantics:
//   ST(0) ← ST(0) - (double)(signed integer at mem)
//
// Operand encoding (memory source at operands[0]):
//   DE /4   FISUB m16int   operands[0].mem.size = S16
//   DA /4   FISUB m32int   operands[0].mem.size = S32
//
// Identical to translate_fiadd with emit_fsub_f64 instead of emit_fadd_f64.
// =============================================================================
auto translate_fisub(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_m16 = (a2->operands[0].mem.size == IROperandSize::S16);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_int = alloc_free_fpr(*a1);

    // Step 1: load ST(0).  Wd_tmp receives the byte offset for ST(0).
    const int Wk21 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: compute source address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 3: load integer from memory into addr_reg (reusing it for the value).
    // Opt 3: loading into addr_reg (not Wd_tmp) preserves the ST(0) byte offset
    // in Wd_tmp so emit_store_st_at_offset can skip recomputing it below.
    if (is_m16) {
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, addr_reg, addr_reg);
    } else {
        emit_ldr_str_imm(buf, /*size=*/2, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
    }

    // Step 4: SCVTF Dd_int, addr_reg — signed W → f64
    emit_scvtf(buf, /*is_64bit_int=*/0, /*ftype=*/1, Dd_int, addr_reg);

    free_gpr(*a1, addr_reg);

    // Step 5: FSUB ST(0) = ST(0) - integer
    emit_fsub_f64(buf, Dd_st0, Dd_st0, Dd_int);

    // Step 6: store result back to ST(0).
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk21, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_int);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FIDIVR — reverse-divide: integer / ST(0)
//
// x87 semantics:
//   ST(0) ← (double)(signed integer at mem) / ST(0)
//
// Operand encoding (memory source at operands[0]):
//   DE /7   FIDIVR m16int   operands[0].mem.size = S16
//   DA /7   FIDIVR m32int   operands[0].mem.size = S32
//
// Identical to translate_fidiv except the FDIV operand order is swapped:
//   fidiv:  FDIV Dd_st0, Dd_st0, Dd_int   (ST(0) / int)
//   fidivr: FDIV Dd_st0, Dd_int,  Dd_st0  (int   / ST(0))
// =============================================================================
auto translate_fidivr(TranslationResult* a1, IRInstr* a2) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const bool is_m16 = (a2->operands[0].mem.size == IROperandSize::S16);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_int = alloc_free_fpr(*a1);

    // Step 1: load ST(0).  Wd_tmp receives the byte offset for ST(0).
    const int Wk22 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // Step 2: compute source address
    const int addr_reg =
        compute_operand_address(*a1, /*is_64bit=*/true, &a2->operands[0], GPR::XZR);

    // Step 3: load integer from memory into addr_reg (reusing it for the value).
    // Opt 3: loading into addr_reg (not Wd_tmp) preserves the ST(0) byte offset
    // in Wd_tmp so emit_store_st_at_offset can skip recomputing it below.
    if (is_m16) {
        emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
        emit_bitfield(buf, /*is_64bit=*/0, /*opc=*/0 /*SBFM*/, /*N=*/0,
                      /*immr=*/0, /*imms=*/15, addr_reg, addr_reg);
    } else {
        emit_ldr_str_imm(buf, /*size=*/2, /*is_fp=*/0, /*opc=*/1 /*LDR*/,
                         /*imm12=*/0, addr_reg, addr_reg);
    }

    // Step 4: SCVTF Dd_int, addr_reg — signed W → f64
    emit_scvtf(buf, /*is_64bit_int=*/0, /*ftype=*/1, Dd_int, addr_reg);

    free_gpr(*a1, addr_reg);

    // Step 5: FDIV Dd_st0, Dd_int, Dd_st0  — integer / ST(0)  (reversed)
    emit_fdiv_f64(buf, Dd_st0, Dd_int, Dd_st0);

    // Step 6: store result back to ST(0).
    // Opt 3: Wd_tmp still holds the ST(0) byte offset from emit_load_st above.
    emit_store_st_at_offset(buf, Xbase, Wk22, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_int);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// FRNDINT — round ST(0) to integer
//
// x87 semantics:
//   ST(0) ← round(ST(0))   using current x87 rounding mode (RC, bits[11:10]
//                           of control_word).  Result is still a double, not
//                           an integer type.  TOP is not modified.
//
// AArch64 mapping:
//   FRINT* Dd, Dn — round to integral floating-point value.
//   We dispatch at runtime to the variant matching the x87 RC field:
//     RC=00 (round nearest)  → FRINTN  (opcode=8)
//     RC=01 (round toward −∞) → FRINTM (opcode=10)
//     RC=10 (round toward +∞) → FRINTP (opcode=9)
//     RC=11 (round toward 0)  → FRINTZ (opcode=11)
//
// WHY NOT FRINTI:
//   FRINTI uses FPCR.RMode.  The x87 RC field and FPCR.RMode use the SAME
//   two bits to mean DIFFERENT things:
//     x87 RC 01 = floor (−∞)   but   FPCR.RMode 01 = ceil (+∞)
//     x87 RC 10 = ceil  (+∞)   but   FPCR.RMode 10 = floor (−∞)
//   Rosetta would have to swap the 01/10 values when copying RC into FPCR.
//   Relying on that sync is fragile and has been observed to round incorrectly
//   when the guest changes the rounding mode (e.g. FLDCW before FRNDINT).
//   Reading the control_word at JIT-time (like translate_fistp does for FISTP)
//   removes the dependency entirely.
//
// Dispatch sequence layout (indices relative to first CBZ):
//   [D+ 0] CBZ  Wd_rc, +28     →  [D+28] FRINTN  (RC=0, nearest)
//   [D+ 4] SUB  Wd_rc, Wd_rc, #1
//   [D+ 8] CBZ  Wd_rc, +28     →  [D+36] FRINTM  (RC=1, floor)
//   [D+12] SUB  Wd_rc, Wd_rc, #1
//   [D+16] CBZ  Wd_rc, +28     →  [D+44] FRINTP  (RC=2, ceil)
//   [D+20] FRINTZ  Dd, Dd       (RC=3, truncate — fall-through, default)
//   [D+24] B    +24             →  [D+48] done
//   [D+28] FRINTN  Dd, Dd
//   [D+32] B    +16             →  [D+48] done
//   [D+36] FRINTM  Dd, Dd
//   [D+40] B    +8              →  [D+48] done
//   [D+44] FRINTP  Dd, Dd
//   [D+48] (done — fall through to emit_store_st_at_offset)
//
// Register allocation:
//   Xbase   (gpr pool 0) — X87State base
//   Wd_top  (gpr pool 1) — current TOP (read-only; no push/pop)
//   Wd_tmp  (gpr pool 2) — byte offset of ST(0); held across the full dispatch
//                          for opt-3 (cannot alias Wd_rc, unlike translate_fistp
//                          which stores to memory and does not need the offset
//                          after emit_load_st).
//   Wd_rc   (gpr pool 3) — RC scratch; clobbered by LDRH + UBFX + SUBs
//   Dd      (fpr pool)   — ST(0) value, rounded in-place
// =============================================================================
auto translate_frndint(TranslationResult* a1, IRInstr* /*a2*/) -> void {
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_rc = alloc_gpr(*a1, 3);  // RC dispatch scratch — must NOT alias Wd_tmp
    const int Dd = alloc_free_fpr(*a1);

    // Load ST(0) into Dd; Wd_tmp receives the byte offset of ST(0) for opt-3.
    const int Wk23 = emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd, Xst_base);

    // ── Read and extract x87 RC field ────────────────────────────────────────
    // control_word is at [Xbase + 0] (X87State offset 0).
    // LDRH Wd_rc, [Xbase, #0]   imm12=0 → byte offset 0
    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/ 1, /*imm12=*/0, Xbase, Wd_rc);
    // UBFX Wd_rc, Wd_rc, #10, #2   →  bits[11:10] in bits[1:0]
    // UBFM immr=10, imms=11  (width = imms-immr+1 = 2 bits → RC values 0..3)
    emit_bitfield(buf, /*is_64=*/0, /*UBFM*/ 2, /*N*/ 0, /*immr*/ 10, /*imms*/ 11, Wd_rc, Wd_rc);

    // ── Runtime dispatch: CBZ/SUB chain (identical structure to translate_fistp)
    //
    // [D+0] CBZ Wd_rc, +28  (imm19=7 → branch offset 28 bytes → [D+28] FRINTN)
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));
    // [D+4] SUB Wd_rc, Wd_rc, #1
    emit_add_imm(buf, /*is_64=*/0, /*sub*/ 1, /*S*/ 0, /*shift*/ 0, 1, Wd_rc, Wd_rc);
    // [D+8] CBZ Wd_rc, +28  (target = D+8+28 = D+36 → [D+36] FRINTM)
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));
    // [D+12] SUB Wd_rc, Wd_rc, #1
    emit_add_imm(buf, /*is_64=*/0, /*sub*/ 1, /*S*/ 0, /*shift*/ 0, 1, Wd_rc, Wd_rc);
    // [D+16] CBZ Wd_rc, +28  (target = D+16+28 = D+44 → [D+44] FRINTP)
    buf.emit(0x34000000u | (7u << 5) | uint32_t(Wd_rc));

    // [D+20] FRINTZ Dd, Dd   RC=3 (truncate) — fall-through path
    emit_fp_dp1(buf, /*type=*/1 /*f64*/, /*FRINTZ=*/11, Dd, Dd);
    // [D+24] B +24           skip to done  (imm26=6 → offset 24 → D+24+24 = D+48)
    buf.emit(0x14000000u | 6u);

    // [D+28] FRINTN Dd, Dd   RC=0 (round nearest, ties to even)
    emit_fp_dp1(buf, /*type=*/1 /*f64*/, /*FRINTN=*/8, Dd, Dd);
    // [D+32] B +16           (imm26=4 → offset 16 → D+32+16 = D+48)
    buf.emit(0x14000000u | 4u);

    // [D+36] FRINTM Dd, Dd   RC=1 (floor, toward −∞)
    emit_fp_dp1(buf, /*type=*/1 /*f64*/, /*FRINTM=*/10, Dd, Dd);
    // [D+40] B +8            (imm26=2 → offset 8 → D+40+8 = D+48)
    buf.emit(0x14000000u | 2u);

    // [D+44] FRINTP Dd, Dd   RC=2 (ceil, toward +∞)
    emit_fp_dp1(buf, /*type=*/1 /*f64*/, /*FRINTP=*/9, Dd, Dd);
    // [D+48] done ─────────────────────────────────────────────────────────────

    // Opt 3: Wd_tmp still holds the ST(0) byte offset written by emit_load_st.
    // The dispatch chain above only touches Wd_rc and Dd; Wd_tmp is intact.
    emit_store_st_at_offset(buf, Xbase, Wk23, Dd, Xst_base);

    free_fpr(*a1, Dd);
    free_gpr(*a1, Wd_rc);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);
}

// =============================================================================
// OPT-1: Lookahead — count consecutive x87 instructions we handle inline
// =============================================================================

static bool is_handled_x87(uint16_t op) {
    switch (op) {
        case kOpcodeName_fldz:
        case kOpcodeName_fld1:
        case kOpcodeName_fldl2e:
        case kOpcodeName_fldl2t:
        case kOpcodeName_fldlg2:
        case kOpcodeName_fldln2:
        case kOpcodeName_fldpi:
        case kOpcodeName_fld:
        case kOpcodeName_fild:
        case kOpcodeName_fadd:
        case kOpcodeName_faddp:
        case kOpcodeName_fiadd:
        case kOpcodeName_fsub:
        case kOpcodeName_fsubr:
        case kOpcodeName_fsubp:
        case kOpcodeName_fsubrp:
        case kOpcodeName_fdiv:
        case kOpcodeName_fdivr:
        case kOpcodeName_fdivp:
        case kOpcodeName_fdivrp:
        case kOpcodeName_fmul:
        case kOpcodeName_fmulp:
        case kOpcodeName_fst:
        case kOpcodeName_fst_stack:
        case kOpcodeName_fstp:
        case kOpcodeName_fstp_stack:
        case kOpcodeName_fstsw:
        case kOpcodeName_fcom:
        case kOpcodeName_fcomp:
        case kOpcodeName_fcompp:
        case kOpcodeName_fucom:
        case kOpcodeName_fucomp:
        case kOpcodeName_fucompp:
        case kOpcodeName_fxch:
        case kOpcodeName_fchs:
        case kOpcodeName_fabs:
        case kOpcodeName_fsqrt:
        case kOpcodeName_fistp:
        case kOpcodeName_fidiv:
        case kOpcodeName_fimul:
        case kOpcodeName_fisub:
        case kOpcodeName_fidivr:
        case kOpcodeName_frndint:
            return true;
        default:
            return false;
    }
}

// =============================================================================
// Peephole: FLD + popping-arithmetic fusion
//
// Recognises pairs like  FLD ST(i) + FADDP ST(1)  whose push and pop cancel,
// and emits the net effect as a single non-pushing/non-popping arithmetic:
//
//   load old_ST(0) → Dd_st0
//   load/materialise fld_value → Dd_fld
//   <arithmetic> Dd_st0, Dd_st0, Dd_fld   (or reversed for FSUBR/FDIVR)
//   store Dd_st0 → ST(0)
//
// Saves ~14 emitted AArch64 instructions per fused pair (push=8 + pop=5 + the
// extra load/store overhead = eliminated).
//
// Returns 1 if the pair was fused (caller must consume 2 IR instructions).
// Returns 0 if the pair is not fusable (caller translates individually).
// =============================================================================

int try_fuse_fld_arithp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* arithp_instr) {
    // ── 1. Classify the FLD source ───────────────────────────────────────────

    enum FldSource {
        kFldReg,
        kFldM32,
        kFldM64,
        kFldZero,
        kFldOne,
        kFldConst64,
        kFildM16,
        kFildM32,
        kFildM64
    };

    const auto fld_op = fld_instr->opcode;
    FldSource fld_src;
    int fld_reg_depth = 0;
    uint64_t fld_const_bits = 0;

    switch (fld_op) {
        case kOpcodeName_fld:
            if (fld_instr->operands[0].kind == IROperandKind::Register) {
                fld_src = kFldReg;
                fld_reg_depth = fld_instr->operands[1].reg.reg.index();
            } else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFldM32;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S64)
                fld_src = kFldM64;
            else
                return 0;  // m80 — not fusable
            break;
        case kOpcodeName_fild:
            if (fld_instr->operands[0].mem.size == IROperandSize::S16)
                fld_src = kFildM16;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFildM32;
            else
                fld_src = kFildM64;
            break;
        case kOpcodeName_fldz:
            fld_src = kFldZero;
            break;
        case kOpcodeName_fld1:
            fld_src = kFldOne;
            break;
        case kOpcodeName_fldl2e:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FF71547652B82FEULL;
            break;
        case kOpcodeName_fldl2t:
            fld_src = kFldConst64;
            fld_const_bits = 0x400A934F0979A371ULL;
            break;
        case kOpcodeName_fldlg2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FD34413509F79FFULL;
            break;
        case kOpcodeName_fldln2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FE62E42FEFA39EFULL;
            break;
        case kOpcodeName_fldpi:
            fld_src = kFldConst64;
            fld_const_bits = 0x400921FB54442D18ULL;
            break;
        default:
            return 0;
    }

    // ── 2. Classify the popping arithmetic op ────────────────────────────────

    enum ArithOp { kAdd, kSub, kSubR, kMul, kDiv, kDivR };

    const auto arith_opcode = arithp_instr->opcode;
    ArithOp arith;

    switch (arith_opcode) {
        case kOpcodeName_faddp:
            arith = kAdd;
            break;
        case kOpcodeName_fsubp:
            arith = kSub;
            break;
        case kOpcodeName_fsubrp:
            arith = kSubR;
            break;
        case kOpcodeName_fmulp:
            arith = kMul;
            break;
        case kOpcodeName_fdivp:
            arith = kDiv;
            break;
        case kOpcodeName_fdivrp:
            arith = kDivR;
            break;
        default:
            return 0;
    }

    // Must target ST(1) — that's old_ST(0) after the FLD push.
    // If depth != 1, the result goes to a different slot and the
    // push/pop don't cancel into a simple overwrite of ST(0).
    if (arithp_instr->operands[0].reg.reg.index() != 1)
        return 0;

    // ── 3. Emit fused code ───────────────────────────────────────────────────
    //
    // Net effect:  ST(0) = arith(old_ST(0), fld_value)
    // No TOP change — push and pop cancel.
    //
    // Strategy:
    //   (a) materialise fld_value → Dd_fld  (may use Wd_tmp as scratch)
    //   (b) load old_ST(0) → Dd_st0 last, so Wd_tmp retains its key for store
    //   (c) arithmetic
    //   (d) store result via emit_store_st_at_offset using Wd_tmp key

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // OPT-C: flush any deferred TOP writeback from a prior push.  The fused
    // instruction doesn't push/pop so it won't set or clear dirty, but if the
    // cache run expires after this pair the dirty writeback would be lost.
    x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_fld = alloc_free_fpr(*a1);

    // ── 3a: Load / materialise fld_value → Dd_fld ───────────────────────────

    switch (fld_src) {
        case kFldReg:
            emit_load_st(buf, Xbase, Wd_top, fld_reg_depth, Wd_tmp, Dd_fld, Xst_base);
            break;

        case kFldM32: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/2 /*S*/, Dd_fld, addr, 0);
            free_gpr(*a1, addr);
            emit_fcvt_s_to_d(buf, Dd_fld, Dd_fld);
            break;
        }
        case kFldM64: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/3 /*D*/, Dd_fld, addr, 0);
            free_gpr(*a1, addr);
            break;
        }

        case kFildM16:
        case kFildM32:
        case kFildM64: {
            // Integer load + sign-extend + SCVTF, mirroring translate_fild.
            const int Wd_int = alloc_free_gpr(*a1);
            const int addr =
                compute_operand_address(*a1, /*is_64bit=*/true, &fld_instr->operands[0], GPR::XZR);
            if (fld_src == kFildM16) {
                emit_ldr_str_imm(buf, 1, 0, 1, 0, addr, Wd_int);     // LDRH
                emit_bitfield(buf, 0, 0, 0, 0, 15, Wd_int, Wd_int);  // SXTH
            } else if (fld_src == kFildM32) {
                emit_ldr_str_imm(buf, 2, 0, 1, 0, addr, Wd_int);  // LDR W
            } else {
                emit_ldr_str_imm(buf, 3, 0, 1, 0, addr, Wd_int);  // LDR X
            }
            free_gpr(*a1, addr);
            const int is_64 = (fld_src == kFildM64) ? 1 : 0;
            emit_scvtf(buf, is_64, 1 /*f64*/, Dd_fld, Wd_int);
            free_gpr(*a1, Wd_int);
            break;
        }

        case kFldZero:
            emit_movi_d_zero(buf, Dd_fld);
            break;

        case kFldOne:
            emit_fmov_d_one(buf, Dd_fld);
            break;

        case kFldConst64: {
            // Use Wd_tmp for MOVZ+MOVK chain — overwritten by ST(0) load below.
            const uint16_t h3 = (uint16_t)(fld_const_bits >> 48);
            const uint16_t h2 = (uint16_t)(fld_const_bits >> 32);
            const uint16_t h1 = (uint16_t)(fld_const_bits >> 16);
            const uint16_t h0 = (uint16_t)(fld_const_bits);
            emit_movn(buf, 1, 2, 3, h3, Wd_tmp);
            if (h2)
                emit_movn(buf, 1, 3, 2, h2, Wd_tmp);
            if (h1)
                emit_movn(buf, 1, 3, 1, h1, Wd_tmp);
            if (h0)
                emit_movn(buf, 1, 3, 0, h0, Wd_tmp);
            emit_fmov_x_to_d(buf, Dd_fld, Wd_tmp);
            break;
        }
    }

    // ── 3b: Load old ST(0) → Dd_st0  (Wd_tmp now holds ST(0) key) ──────────

    const int Wk24 = emit_load_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── 3c: Arithmetic ──────────────────────────────────────────────────────
    //
    // After FLD src + F*P ST(1):
    //   new_ST(0) = fld_val,  new_ST(1) = old_ST(0)
    //   F*P ST(1),ST(0) computes f(new_ST(1), new_ST(0)) = f(old_ST(0), fld_val)
    //
    // So for non-reversed ops: result = old_ST(0) OP fld_val
    //    for reversed ops:     result = fld_val OP old_ST(0)

    switch (arith) {
        case kAdd:
            emit_fadd_f64(buf, Dd_st0, Dd_st0, Dd_fld);
            break;
        case kSub:
            emit_fsub_f64(buf, Dd_st0, Dd_st0, Dd_fld);
            break;
        case kSubR:
            emit_fsub_f64(buf, Dd_st0, Dd_fld, Dd_st0);
            break;
        case kMul:
            emit_fmul_f64(buf, Dd_st0, Dd_st0, Dd_fld);
            break;
        case kDiv:
            emit_fdiv_f64(buf, Dd_st0, Dd_st0, Dd_fld);
            break;
        case kDivR:
            emit_fdiv_f64(buf, Dd_st0, Dd_fld, Dd_st0);
            break;
    }

    // ── 3d: Store result to ST(0) using key from step 3b ────────────────────

    emit_store_st_at_offset(buf, Xbase, Wk24, Dd_st0, Xst_base);

    free_fpr(*a1, Dd_fld);
    free_fpr(*a1, Dd_st0);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);

    return 1;  // fused — caller consumes 2 instructions
}

// =============================================================================
// Peephole: FLD + non-popping arithmetic (memory) + FSTP (memory)
//
// Recognizes the common pattern:
//   FLD  [src_a]        — push value onto x87 stack
//   FMUL [src_b]        — multiply ST(0) by memory operand (non-popping)
//   FSTP [dst]          — pop result to memory
//
// The push from FLD and pop from FSTP cancel (TOP returns to its original
// value, tag slot cycles Valid→Empty = net unchanged).  The arithmetic only
// touches ST(0).  Net effect: *dst = convert(fld_val OP arith_mem_val).
//
// By emitting a single fused sequence we skip ALL push/pop/tag overhead,
// reducing e.g. flds+fmuls+fstps from ~37 ARM64 instructions to ~10.
//
// Returns 1 if fused (3 instructions consumed), 0 otherwise.
// =============================================================================

int try_fuse_fld_arith_fstp(TranslationResult* a1, IRInstr* fld_instr,
                             IRInstr* arith_instr, IRInstr* fstp_instr) {
    // ── 1. Classify the FLD source ───────────────────────────────────────────

    enum FldSource {
        kFldReg,
        kFldM32,
        kFldM64,
        kFldZero,
        kFldOne,
        kFldConst64,
        kFildM16,
        kFildM32,
        kFildM64
    };

    const auto fld_op = fld_instr->opcode;
    FldSource fld_src;
    int fld_reg_depth = 0;
    uint64_t fld_const_bits = 0;

    switch (fld_op) {
        case kOpcodeName_fld:
            if (fld_instr->operands[0].kind == IROperandKind::Register) {
                fld_src = kFldReg;
                fld_reg_depth = fld_instr->operands[1].reg.reg.index();
            } else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFldM32;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S64)
                fld_src = kFldM64;
            else
                return 0;  // m80 — not fusable
            break;
        case kOpcodeName_fild:
            if (fld_instr->operands[0].mem.size == IROperandSize::S16)
                fld_src = kFildM16;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFildM32;
            else
                fld_src = kFildM64;
            break;
        case kOpcodeName_fldz:
            fld_src = kFldZero;
            break;
        case kOpcodeName_fld1:
            fld_src = kFldOne;
            break;
        case kOpcodeName_fldl2e:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FF71547652B82FEULL;
            break;
        case kOpcodeName_fldl2t:
            fld_src = kFldConst64;
            fld_const_bits = 0x400A934F0979A371ULL;
            break;
        case kOpcodeName_fldlg2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FD34413509F79FFULL;
            break;
        case kOpcodeName_fldln2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FE62E42FEFA39EFULL;
            break;
        case kOpcodeName_fldpi:
            fld_src = kFldConst64;
            fld_const_bits = 0x400921FB54442D18ULL;
            break;
        default:
            return 0;
    }

    // ── 2. Classify the non-popping arithmetic op (memory source) ────────────

    enum ArithOp { kAdd, kSub, kSubR, kMul, kDiv, kDivR };

    const auto arith_opcode = arith_instr->opcode;
    ArithOp arith;

    switch (arith_opcode) {
        case kOpcodeName_fadd:
            arith = kAdd;
            break;
        case kOpcodeName_fsub:
            arith = kSub;
            break;
        case kOpcodeName_fsubr:
            arith = kSubR;
            break;
        case kOpcodeName_fmul:
            arith = kMul;
            break;
        case kOpcodeName_fdiv:
            arith = kDiv;
            break;
        case kOpcodeName_fdivr:
            arith = kDivR;
            break;
        default:
            return 0;
    }

    // Arithmetic must have a memory source operand (not register form).
    if (arith_instr->operands[0].kind != IROperandKind::MemRef)
        return 0;

    // Only f32 or f64 memory operand sizes.
    const auto arith_size = arith_instr->operands[0].mem.size;
    if (arith_size != IROperandSize::S32 && arith_size != IROperandSize::S64)
        return 0;

    // ── 3. Classify the FSTP destination ─────────────────────────────────────

    if (fstp_instr->opcode != kOpcodeName_fstp && fstp_instr->opcode != kOpcodeName_fstp_stack)
        return 0;

    // Must be memory destination (not register).
    if (fstp_instr->operands[0].kind == IROperandKind::Register)
        return 0;

    // Only f32 or f64 (not m80).
    const auto fstp_size = fstp_instr->operands[0].mem.size;
    if (fstp_size != IROperandSize::S32 && fstp_size != IROperandSize::S64)
        return 0;

    // ── 4. Emit fused code ──────────────────────────────────────────────────
    //
    // Net effect: *fstp_dest = convert(fld_val OP arith_mem_val)
    // No TOP change — push and pop cancel.  No tag word updates needed.

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // Flush any deferred TOP writeback from a prior push.
    x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_arith = alloc_free_fpr(*a1);

    // ── 4a: Materialise FLD value → Dd_fld ──────────────────────────────────

    switch (fld_src) {
        case kFldReg:
            // Use current TOP (pre-push) since push/pop cancel.
            emit_load_st(buf, Xbase, Wd_top, fld_reg_depth, Wd_tmp, Dd_fld, Xst_base);
            break;
        case kFldM32: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/2 /*S*/, Dd_fld, addr, 0);
            free_gpr(*a1, addr);
            emit_fcvt_s_to_d(buf, Dd_fld, Dd_fld);
            break;
        }
        case kFldM64: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/3 /*D*/, Dd_fld, addr, 0);
            free_gpr(*a1, addr);
            break;
        }
        case kFildM16:
        case kFildM32:
        case kFildM64: {
            const int Wd_int = alloc_free_gpr(*a1);
            const int addr =
                compute_operand_address(*a1, /*is_64bit=*/true, &fld_instr->operands[0], GPR::XZR);
            if (fld_src == kFildM16) {
                emit_ldr_str_imm(buf, 1, 0, 1, 0, addr, Wd_int);     // LDRH
                emit_bitfield(buf, 0, 0, 0, 0, 15, Wd_int, Wd_int);  // SXTH
            } else if (fld_src == kFildM32) {
                emit_ldr_str_imm(buf, 2, 0, 1, 0, addr, Wd_int);  // LDR W
            } else {
                emit_ldr_str_imm(buf, 3, 0, 1, 0, addr, Wd_int);  // LDR X
            }
            free_gpr(*a1, addr);
            const int is_64 = (fld_src == kFildM64) ? 1 : 0;
            emit_scvtf(buf, is_64, 1 /*f64*/, Dd_fld, Wd_int);
            free_gpr(*a1, Wd_int);
            break;
        }
        case kFldZero:
            emit_movi_d_zero(buf, Dd_fld);
            break;
        case kFldOne:
            emit_fmov_d_one(buf, Dd_fld);
            break;
        case kFldConst64: {
            const uint16_t h3 = (uint16_t)(fld_const_bits >> 48);
            const uint16_t h2 = (uint16_t)(fld_const_bits >> 32);
            const uint16_t h1 = (uint16_t)(fld_const_bits >> 16);
            const uint16_t h0 = (uint16_t)(fld_const_bits);
            emit_movn(buf, 1, 2, 3, h3, Wd_tmp);
            if (h2)
                emit_movn(buf, 1, 3, 2, h2, Wd_tmp);
            if (h1)
                emit_movn(buf, 1, 3, 1, h1, Wd_tmp);
            if (h0)
                emit_movn(buf, 1, 3, 0, h0, Wd_tmp);
            emit_fmov_x_to_d(buf, Dd_fld, Wd_tmp);
            break;
        }
    }

    // ── 4b: Load arithmetic memory operand → Dd_arith ───────────────────────

    {
        const bool arith_is_f32 = (arith_size == IROperandSize::S32);
        const bool a64 = (arith_instr->operands[0].mem.addr_size == IROperandSize::S64);
        const int addr = compute_operand_address(*a1, a64, &arith_instr->operands[0], GPR::XZR);
        emit_fldr_imm(buf, arith_is_f32 ? 2 : 3, Dd_arith, addr, 0);
        free_gpr(*a1, addr);
        if (arith_is_f32)
            emit_fcvt_s_to_d(buf, Dd_arith, Dd_arith);
    }

    // ── 4c: Arithmetic ──────────────────────────────────────────────────────
    //
    // The non-popping arith computes ST(0) = ST(0) OP mem.
    // After virtual FLD push, ST(0) = fld_val, so result = fld_val OP arith_mem.
    // For reversed ops: result = arith_mem OP fld_val.

    switch (arith) {
        case kAdd:
            emit_fadd_f64(buf, Dd_fld, Dd_fld, Dd_arith);
            break;
        case kSub:
            emit_fsub_f64(buf, Dd_fld, Dd_fld, Dd_arith);
            break;
        case kSubR:
            emit_fsub_f64(buf, Dd_fld, Dd_arith, Dd_fld);
            break;
        case kMul:
            emit_fmul_f64(buf, Dd_fld, Dd_fld, Dd_arith);
            break;
        case kDiv:
            emit_fdiv_f64(buf, Dd_fld, Dd_fld, Dd_arith);
            break;
        case kDivR:
            emit_fdiv_f64(buf, Dd_fld, Dd_arith, Dd_fld);
            break;
    }

    // ── 4d: Store to FSTP memory destination ─────────────────────────────────

    {
        const bool fstp_is_f32 = (fstp_size == IROperandSize::S32);
        if (fstp_is_f32)
            emit_fcvt_d_to_s(buf, Dd_fld, Dd_fld);

        const int addr =
            compute_operand_address(*a1, /*is_64bit=*/true, &fstp_instr->operands[0], GPR::XZR);
        emit_fstr_imm(buf, fstp_is_f32 ? 2 : 3, Dd_fld, addr, 0);
        free_gpr(*a1, addr);
    }

    free_fpr(*a1, Dd_arith);
    free_fpr(*a1, Dd_fld);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);

    return 1;  // fused — caller consumes 3 instructions
}

// =============================================================================
// Peephole: FXCH ST(1) + popping-arithmetic fusion
//
// FXCH ST(1) swaps ST(0) and ST(1). When followed by a popping arithmetic op
// targeting ST(1), the swap can be eliminated entirely:
//
//   Commutative (FADDP, FMULP): operand order doesn't matter → skip FXCH.
//   Non-commutative: FXCH + FSUBP = FSUBRP, FXCH + FSUBRP = FSUBP, etc.
//
// Implementation: dispatch to the existing translate_* function with the
// original (commutative) or opcode-swapped (non-commutative) instruction.
// For the swap case, we make a shallow copy of the IRInstr with the modified
// opcode so the translator's `a2->opcode == kOpcodeName_fsubrp` check works.
//
// Returns 1 if fused (2 instructions consumed), 0 otherwise.
// =============================================================================

int try_fuse_fxch_arithp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* next_instr) {
    // Only fuse FXCH ST(1) — other depths change which slots the arith op sees.
    if (fxch_instr->opcode != kOpcodeName_fxch)
        return 0;
    if (fxch_instr->operands[1].reg.reg.index() != 1)
        return 0;

    // The popping op must target ST(1) (the standard form).
    const auto next_op = next_instr->opcode;
    bool is_popping_arith = false;
    switch (next_op) {
        case kOpcodeName_faddp:
        case kOpcodeName_fmulp:
        case kOpcodeName_fsubp:
        case kOpcodeName_fsubrp:
        case kOpcodeName_fdivp:
        case kOpcodeName_fdivrp:
            is_popping_arith = true;
            break;
        default:
            break;
    }
    if (!is_popping_arith)
        return 0;
    if (next_instr->operands[0].reg.reg.index() != 1)
        return 0;

    // Determine what to emit.  For commutative ops, emit as-is.
    // For non-commutative, swap normal↔reversed.
    switch (next_op) {
        case kOpcodeName_faddp:
            translate_faddp(a1, next_instr);
            break;
        case kOpcodeName_fmulp:
            translate_fmul(a1, next_instr);  // translate_fmul handles fmulp via opcode check
            break;
        case kOpcodeName_fsubp: {
            // FXCH + FSUBP = FSUBRP: swap operand order.
            IRInstr copy = *next_instr;
            copy.opcode = kOpcodeName_fsubrp;
            translate_fsubp(a1, &copy);
            break;
        }
        case kOpcodeName_fsubrp: {
            IRInstr copy = *next_instr;
            copy.opcode = kOpcodeName_fsubp;
            translate_fsubp(a1, &copy);
            break;
        }
        case kOpcodeName_fdivp: {
            IRInstr copy = *next_instr;
            copy.opcode = kOpcodeName_fdivrp;
            translate_fdivp(a1, &copy);
            break;
        }
        case kOpcodeName_fdivrp: {
            IRInstr copy = *next_instr;
            copy.opcode = kOpcodeName_fdivp;
            translate_fdivp(a1, &copy);
            break;
        }
        default:
            return 0;
    }

    return 1;
}

// =============================================================================
// Peephole: FLD + FSTP fusion (register copy / memory load-store)
//
// When FLD pushes a value and the immediately following FSTP pops it, the
// push and pop cancel.  The net effect depends on the FSTP destination:
//
//   FSTP ST(1)  → ST(0) overwritten with fld_value   (register copy)
//   FSTP m32/m64 → fld_value stored to memory         (memory write)
//
// Only FSTP ST(1) is handled for register destinations (the push/pop only
// cancel to a TOP-preserving overwrite of ST(0) when j == 1).
// FSTP m32/m64 is handled for any memory destination.
//
// NOT handled: FSTP m80 (runtime helper), FSTP ST(j) with j != 1.
//
// Returns 1 if fused (2 instructions consumed), 0 otherwise.
// =============================================================================

int try_fuse_fld_fstp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* fstp_instr) {
    // The second instruction must be FSTP (popping store).
    if (fstp_instr->opcode != kOpcodeName_fstp && fstp_instr->opcode != kOpcodeName_fstp_stack)
        return 0;

    // Determine FSTP destination.
    const bool fstp_is_reg = (fstp_instr->operands[0].kind == IROperandKind::Register);
    const bool fstp_is_mem = !fstp_is_reg;

    if (fstp_is_reg) {
        // Only handle FSTP ST(1) — push/pop cancel for this depth only.
        if (fstp_instr->operands[0].reg.reg.index() != 1)
            return 0;
    } else {
        // Memory FSTP — reject m80 (runtime helper).
        if (fstp_instr->operands[0].mem.size == IROperandSize::S80)
            return 0;
    }

    // ── Classify the FLD source (same as try_fuse_fld_arithp) ────────────────

    enum FldSource {
        kFldReg,
        kFldM32,
        kFldM64,
        kFldZero,
        kFldOne,
        kFldConst64,
        kFildM16,
        kFildM32,
        kFildM64
    };

    const auto fld_op = fld_instr->opcode;
    FldSource fld_src;
    int fld_reg_depth = 0;
    uint64_t fld_const_bits = 0;

    switch (fld_op) {
        case kOpcodeName_fld:
            if (fld_instr->operands[0].kind == IROperandKind::Register) {
                fld_src = kFldReg;
                fld_reg_depth = fld_instr->operands[1].reg.reg.index();
            } else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFldM32;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S64)
                fld_src = kFldM64;
            else
                return 0;  // m80
            break;
        case kOpcodeName_fild:
            if (fld_instr->operands[0].mem.size == IROperandSize::S16)
                fld_src = kFildM16;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                fld_src = kFildM32;
            else
                fld_src = kFildM64;
            break;
        case kOpcodeName_fldz:
            fld_src = kFldZero;
            break;
        case kOpcodeName_fld1:
            fld_src = kFldOne;
            break;
        case kOpcodeName_fldl2e:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FF71547652B82FEULL;
            break;
        case kOpcodeName_fldl2t:
            fld_src = kFldConst64;
            fld_const_bits = 0x400A934F0979A371ULL;
            break;
        case kOpcodeName_fldlg2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FD34413509F79FFULL;
            break;
        case kOpcodeName_fldln2:
            fld_src = kFldConst64;
            fld_const_bits = 0x3FE62E42FEFA39EFULL;
            break;
        case kOpcodeName_fldpi:
            fld_src = kFldConst64;
            fld_const_bits = 0x400921FB54442D18ULL;
            break;
        default:
            return 0;
    }

    // ── Emit fused code ──────────────────────────────────────────────────────

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_val = alloc_free_fpr(*a1);

    // ── Materialise the FLD value into Dd_val ────────────────────────────────

    switch (fld_src) {
        case kFldReg:
            emit_load_st(buf, Xbase, Wd_top, fld_reg_depth, Wd_tmp, Dd_val, Xst_base);
            break;
        case kFldM32: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, 2, Dd_val, addr, 0);
            free_gpr(*a1, addr);
            emit_fcvt_s_to_d(buf, Dd_val, Dd_val);
            break;
        }
        case kFldM64: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(*a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, 3, Dd_val, addr, 0);
            free_gpr(*a1, addr);
            break;
        }
        case kFildM16:
        case kFildM32:
        case kFildM64: {
            const int Wd_int = alloc_free_gpr(*a1);
            const int addr = compute_operand_address(*a1, true, &fld_instr->operands[0], GPR::XZR);
            if (fld_src == kFildM16) {
                emit_ldr_str_imm(buf, 1, 0, 1, 0, addr, Wd_int);
                emit_bitfield(buf, 0, 0, 0, 0, 15, Wd_int, Wd_int);
            } else if (fld_src == kFildM32) {
                emit_ldr_str_imm(buf, 2, 0, 1, 0, addr, Wd_int);
            } else {
                emit_ldr_str_imm(buf, 3, 0, 1, 0, addr, Wd_int);
            }
            free_gpr(*a1, addr);
            emit_scvtf(buf, (fld_src == kFildM64) ? 1 : 0, 1, Dd_val, Wd_int);
            free_gpr(*a1, Wd_int);
            break;
        }
        case kFldZero:
            emit_movi_d_zero(buf, Dd_val);
            break;
        case kFldOne:
            emit_fmov_d_one(buf, Dd_val);
            break;
        case kFldConst64: {
            const uint16_t h3 = (uint16_t)(fld_const_bits >> 48);
            const uint16_t h2 = (uint16_t)(fld_const_bits >> 32);
            const uint16_t h1 = (uint16_t)(fld_const_bits >> 16);
            const uint16_t h0 = (uint16_t)(fld_const_bits);
            emit_movn(buf, 1, 2, 3, h3, Wd_tmp);
            if (h2)
                emit_movn(buf, 1, 3, 2, h2, Wd_tmp);
            if (h1)
                emit_movn(buf, 1, 3, 1, h1, Wd_tmp);
            if (h0)
                emit_movn(buf, 1, 3, 0, h0, Wd_tmp);
            emit_fmov_x_to_d(buf, Dd_val, Wd_tmp);
            break;
        }
    }

    // ── Store to destination ─────────────────────────────────────────────────

    if (fstp_is_reg) {
        // FSTP ST(1) → net effect: ST(0) = fld_value. Store to ST(0).
        emit_store_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_val, Xst_base);
    } else {
        // FSTP m32/m64 → net effect: mem = fld_value. Store to memory.
        const bool is_f32 = (fstp_instr->operands[0].mem.size == IROperandSize::S32);
        if (is_f32)
            emit_fcvt_d_to_s(buf, Dd_val, Dd_val);

        const int addr =
            compute_operand_address(*a1, /*is_64bit=*/true, &fstp_instr->operands[0], GPR::XZR);
        emit_fstr_imm(buf, is_f32 ? 2 : 3, Dd_val, addr, 0);
        free_gpr(*a1, addr);
    }

    free_fpr(*a1, Dd_val);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);

    return 1;
}

// =============================================================================
// Peephole: FXCH ST(1) + FSTP ST(1) → just pop
//
// FXCH ST(1) swaps the contents of ST(0) and ST(1).  When followed by
// FSTP ST(1), the FSTP stores the new ST(0) (= old_ST(1)) back into
// ST(1)'s slot, then pops.  This means ST(1)'s slot ends up containing
// old_ST(1) — exactly what was there before the FXCH.  The pop then
// promotes ST(1) to the new ST(0), giving new ST(0) = old_ST(1).
//
// This is identical to a plain pop (which also gives new ST(0) = old_ST(1)).
//
// State trace:
//   Before:           slot[T]=A, slot[T+1]=B
//   After FXCH:       slot[T]=B, slot[T+1]=A
//   FSTP ST(1):       store slot[T]=B → slot[T+1].  slot[T+1]=B.  TOP++.
//   New ST(0) =       slot[T+1] = B
//   Plain pop:        TOP++.  New ST(0) = slot[T+1] = B.  ✓ Same.
//
// NOT safe for FSTP m32/m64: the FXCH puts old_ST(0)=A into slot[T+1],
// which becomes new ST(0) after pop.  A naive fusion that skips the FXCH
// would leave slot[T+1]=B, giving the wrong new ST(0).
//
// Savings: eliminates FXCH (6 insns) + the redundant load/store in FSTP
// (which stores B to the slot that already contains B).  Emits only the
// pop sequence (5 insns) instead of FXCH(6) + FSTP(~10) = ~16 insns.
//
// Returns 1 if fused (2 instructions consumed), 0 otherwise.
// =============================================================================

int try_fuse_fxch_fstp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* fstp_instr) {
    // Must be FXCH ST(1).
    if (fxch_instr->opcode != kOpcodeName_fxch)
        return 0;
    if (fxch_instr->operands[1].reg.reg.index() != 1)
        return 0;

    // Must be FSTP ST(1) (register, popping).
    if (fstp_instr->opcode != kOpcodeName_fstp_stack)
        return 0;
    if (fstp_instr->operands[0].kind != IROperandKind::Register)
        return 0;
    if (fstp_instr->operands[0].reg.reg.index() != 1)
        return 0;

    // ── Emit: just a pop ─────────────────────────────────────────────────────

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp);
    free_gpr(*a1, Wd_tmp);

    return 1;
}

int x87_cache_lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx) {
    int count = 0;
    for (int64_t i = insn_idx; i < num_instrs; i++) {
        if (!is_handled_x87(instr_array[i].opcode))
            break;
        count++;
    }
    return count;
}

};  // namespace TranslatorX87