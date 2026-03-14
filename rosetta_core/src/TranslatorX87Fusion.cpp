#include "rosetta_core/TranslatorX87Fusion.h"

#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/TranslatorX87.h"
#include "TranslatorX87Internal.hpp"
#include "rosetta_config/Config.h"

namespace TranslatorX87 {

static inline bool fusion_disabled(uint64_t mask, FusionId id) {
    return (mask >> static_cast<int>(id)) & 1u;
}

// =============================================================================
// Shared FLD source classification
// =============================================================================

enum FldSource {
    kFldReg,
    kFldM32,
    kFldM64,
    kFldZero,
    kFldOne,
    kFldConst64,
    kFildM16,
    kFildM32,
    kFildM64,
    kFldInvalid
};

struct FldClassification {
    FldSource source = kFldInvalid;
    int reg_depth = 0;
    uint64_t const_bits = 0;
};

static FldClassification classify_fld_source(IRInstr* fld_instr) {
    FldClassification cls;
    const auto fld_op = fld_instr->opcode;

    switch (fld_op) {
        case kOpcodeName_fld:
            if (fld_instr->operands[0].kind == IROperandKind::Register) {
                cls.source = kFldReg;
                cls.reg_depth = fld_instr->operands[1].reg.reg.index();
            } else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                cls.source = kFldM32;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S64)
                cls.source = kFldM64;
            // else m80 — kFldInvalid
            break;
        case kOpcodeName_fild:
            if (fld_instr->operands[0].mem.size == IROperandSize::S16)
                cls.source = kFildM16;
            else if (fld_instr->operands[0].mem.size == IROperandSize::S32)
                cls.source = kFildM32;
            else
                cls.source = kFildM64;
            break;
        case kOpcodeName_fldz:
            cls.source = kFldZero;
            break;
        case kOpcodeName_fld1:
            cls.source = kFldOne;
            break;
        case kOpcodeName_fldl2e:
            cls.source = kFldConst64;
            cls.const_bits = 0x3FF71547652B82FEULL;
            break;
        case kOpcodeName_fldl2t:
            cls.source = kFldConst64;
            cls.const_bits = 0x400A934F0979A371ULL;
            break;
        case kOpcodeName_fldlg2:
            cls.source = kFldConst64;
            cls.const_bits = 0x3FD34413509F79FFULL;
            break;
        case kOpcodeName_fldln2:
            cls.source = kFldConst64;
            cls.const_bits = 0x3FE62E42FEFA39EFULL;
            break;
        case kOpcodeName_fldpi:
            cls.source = kFldConst64;
            cls.const_bits = 0x400921FB54442D18ULL;
            break;
        default:
            break;
    }
    return cls;
}

static bool fld_source_is_x86_memory(FldSource src) {
    switch (src) {
        case kFldM32:
        case kFldM64:
        case kFildM16:
        case kFildM32:
        case kFildM64:
            return true;
        default:
            return false;
    }
}

// Returns true if a preceding non-x87 instruction in the same block stores to
// the same memory address that the FLD at instrs[fld_idx] reads from.
//
// When Rosetta's IR-level optimiser sees a store (e.g. MOVSD [rbp-8], XMM0)
// followed by an FLD from the same address, it forwards the value via a
// register — never emitting an ARM STR.  Our fused code emits an ARM LDR and
// reads stale/uninitialised data.  By scanning backwards we detect this case
// and reject the fusion, letting standalone translate_fld handle it correctly.
//
// X87 stores (FST/FSTP/FIST/etc.) are safe — our translator always emits the
// ARM STR for those.
static bool is_memory_fld_with_store_conflict(IRInstr* instrs, int64_t fld_idx) {
    auto cls = classify_fld_source(&instrs[fld_idx]);
    if (!fld_source_is_x86_memory(cls.source))
        return false;

    const auto& fld_mem = instrs[fld_idx].operands[0].mem;

    for (int64_t i = fld_idx - 1; i >= 0; --i) {
        const auto& instr = instrs[i];

        // Skip x87 instructions — our translator emits their stores correctly.
        const uint16_t op = instr.opcode;
        if ((op >= 0x25 && op <= 0x30) || (op >= 0xBD && op <= 0x10C))
            continue;

        // Only check instructions whose first operand is a memory destination
        // (potential store).
        if (instr.operands[0].kind != IROperandKind::MemRef)
            continue;

        // Structural address match: same base, index, scale, displacement.
        const auto& st = instr.operands[0].mem;
        if (st.mem_flags == fld_mem.mem_flags &&
            st.base_reg == fld_mem.base_reg &&
            st.index_reg == fld_mem.index_reg &&
            st.shift_amount == fld_mem.shift_amount &&
            st.disp == fld_mem.disp) {
            return true;
        }
    }

    return false;
}

// =============================================================================
// Shared FLD value materialisation
//
// Emits code to load/materialise an FLD source value into Dd_val.
// Wd_tmp is available as scratch (may be overwritten).
// =============================================================================

static void emit_fld_value(AssemblerBuffer& buf, TranslationResult& a1,
                           const FldClassification& cls, IRInstr* fld_instr,
                           int Xbase, int Wd_top, int Wd_tmp, int Dd_val, int Xst_base) {
    switch (cls.source) {
        case kFldReg:
            emit_load_st(buf, Xbase, Wd_top, cls.reg_depth, Wd_tmp, Dd_val, Xst_base);
            break;

        case kFldM32: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/2 /*S*/, Dd_val, addr, 0);
            free_gpr(a1, addr);
            emit_fcvt_s_to_d(buf, Dd_val, Dd_val);
            break;
        }
        case kFldM64: {
            const bool a64 = (fld_instr->operands[0].mem.addr_size == IROperandSize::S64);
            const int addr = compute_operand_address(a1, a64, &fld_instr->operands[0], GPR::XZR);
            emit_fldr_imm(buf, /*size=*/3 /*D*/, Dd_val, addr, 0);
            free_gpr(a1, addr);
            break;
        }

        case kFildM16:
        case kFildM32:
        case kFildM64: {
            const int Wd_int = alloc_free_gpr(a1);
            const int addr =
                compute_operand_address(a1, /*is_64bit=*/true, &fld_instr->operands[0], GPR::XZR);
            if (cls.source == kFildM16) {
                emit_ldr_str_imm(buf, 1, 0, 1, 0, addr, Wd_int);     // LDRH
                emit_bitfield(buf, 0, 0, 0, 0, 15, Wd_int, Wd_int);  // SXTH
            } else if (cls.source == kFildM32) {
                emit_ldr_str_imm(buf, 2, 0, 1, 0, addr, Wd_int);  // LDR W
            } else {
                emit_ldr_str_imm(buf, 3, 0, 1, 0, addr, Wd_int);  // LDR X
            }
            free_gpr(a1, addr);
            const int is_64 = (cls.source == kFildM64) ? 1 : 0;
            emit_scvtf(buf, is_64, 1 /*f64*/, Dd_val, Wd_int);
            free_gpr(a1, Wd_int);
            break;
        }

        case kFldZero:
            emit_movi_d_zero(buf, Dd_val);
            break;

        case kFldOne:
            emit_fmov_d_one(buf, Dd_val);
            break;

        case kFldConst64: {
            const uint16_t h3 = (uint16_t)(cls.const_bits >> 48);
            const uint16_t h2 = (uint16_t)(cls.const_bits >> 32);
            const uint16_t h1 = (uint16_t)(cls.const_bits >> 16);
            const uint16_t h0 = (uint16_t)(cls.const_bits);
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

        case kFldInvalid:
            break;
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

static auto try_fuse_fld_arithp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* arithp_instr)
    -> std::optional<int> {
    // ── 1. Classify the FLD source ───────────────────────────────────────────

    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

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
            return std::nullopt;
    }

    // Must target ST(1) — that's old_ST(0) after the FLD push.
    if (arithp_instr->operands[0].reg.reg.index() != 1)
        return std::nullopt;

    // ── 3. Emit fused code ───────────────────────────────────────────────────

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
    if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_fld = alloc_free_fpr(*a1);

    // ── 3a: Load / materialise fld_value → Dd_fld ───────────────────────────

    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 3b: Load old ST(0) → Dd_st0  (Wd_tmp now holds ST(0) key) ──────────

    const int Wk24 = emit_load_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── 3c: Arithmetic ──────────────────────────────────────────────────────

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
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/2);
    free_gpr(*a1, Wd_tmp);

    return 2;
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
// Returns 2 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fxch_arithp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* next_instr)
    -> std::optional<int> {
    if (fxch_instr->opcode != kOpcodeName_fxch)
        return std::nullopt;
    if (fxch_instr->operands[1].reg.reg.index() != 1)
        return std::nullopt;

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
        return std::nullopt;
    if (next_instr->operands[0].reg.reg.index() != 1)
        return std::nullopt;

    // The FXCH is absorbed (no code emitted), but it consumes one tick.
    // Pre-decrement run_remaining so the delegated translate function's
    // x87_end(consumed=1) sees the correct budget and flushes deferred
    // state when the fusion is at the end of a cache run.
    if (a1->x87_cache.run_remaining > 0)
        a1->x87_cache.run_remaining--;

    switch (next_op) {
        case kOpcodeName_faddp:
            translate_faddp(a1, next_instr);
            break;
        case kOpcodeName_fmulp:
            translate_fmul(a1, next_instr);
            break;
        case kOpcodeName_fsubp: {
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
            return std::nullopt;
    }

    return 2;
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
// Returns 2 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_fstp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* fstp_instr)
    -> std::optional<int> {
    if (fstp_instr->opcode != kOpcodeName_fstp && fstp_instr->opcode != kOpcodeName_fstp_stack)
        return std::nullopt;

    const bool fstp_is_reg = (fstp_instr->operands[0].kind == IROperandKind::Register);

    if (fstp_is_reg) {
        if (fstp_instr->operands[0].reg.reg.index() != 1)
            return std::nullopt;
    } else {
        if (fstp_instr->operands[0].mem.size == IROperandSize::S80)
            return std::nullopt;
    }

    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // ── Emit fused code ──────────────────────────────────────────────────────

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
    if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_val = alloc_free_fpr(*a1);

    // ── Materialise the FLD value into Dd_val ────────────────────────────────

    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_val, Xst_base);

    // ── Store to destination ─────────────────────────────────────────────────

    if (fstp_is_reg) {
        emit_store_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_val, Xst_base);
    } else {
        const bool is_f32 = (fstp_instr->operands[0].mem.size == IROperandSize::S32);
        if (is_f32)
            emit_fcvt_d_to_s(buf, Dd_val, Dd_val);

        const int addr =
            compute_operand_address(*a1, /*is_64bit=*/true, &fstp_instr->operands[0], GPR::XZR);
        emit_fstr_imm(buf, is_f32 ? 2 : 3, Dd_val, addr, 0);
        free_gpr(*a1, addr);
    }

    free_fpr(*a1, Dd_val);
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/2);
    free_gpr(*a1, Wd_tmp);

    return 2;
}

// =============================================================================
// Peephole: FXCH ST(1) + FSTP ST(1) → just pop
//
// The swap's effect is destroyed by the pop — both instructions collapse
// into a single pop sequence.
//
// Returns 2 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fxch_fstp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* fstp_instr)
    -> std::optional<int> {
    if (fxch_instr->opcode != kOpcodeName_fxch)
        return std::nullopt;
    if (fxch_instr->operands[1].reg.reg.index() != 1)
        return std::nullopt;

    if (fstp_instr->opcode != kOpcodeName_fstp_stack)
        return std::nullopt;
    if (fstp_instr->operands[0].kind != IROperandKind::Register)
        return std::nullopt;
    if (fstp_instr->operands[0].reg.reg.index() != 1)
        return std::nullopt;

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/2);
    free_gpr(*a1, Wd_tmp);

    return 2;
}

// =============================================================================
// Peephole: FCOM/FCOMP/FUCOM/FUCOMP/FCOMPP/FUCOMPP + FSTSW AX fusion (OPT-F6)
//
// The canonical pre-SSE2 comparison idiom is:
//   FCOM/FCOMP ST(i) / m32fp / m64fp
//   FSTSW AX
//   SAHF
//   Jcc
//
// Without fusion, FCOM writes CC bits to status_word (STRH), and FSTSW
// immediately reads them back (LDRH) — a redundant store→load round-trip
// with ~4 cycles of store-forwarding latency on Apple M-series.
//
// Fused: we keep the status_word value in a register after FCOM's RMW,
// BFI it into W_AX, then STRH once.  Saves the LDRH + the OPT-C flush
// check in translate_fstsw (2-3 instructions + latency).
//
// Also fuses FCOMPP/FUCOMPP (double-pop): pops twice after the compare.
// NOT fused for: FSTSW m16 (memory path — rare).
//
// Returns 2 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fcom_fstsw(TranslationResult* a1, IRInstr* fcom_instr, IRInstr* fstsw_instr)
    -> std::optional<int> {
    // The second instruction must be FSTSW with a register (AX) destination.
    if (fstsw_instr->opcode != kOpcodeName_fstsw)
        return std::nullopt;
    if (fstsw_instr->operands[0].kind != IROperandKind::Register)
        return std::nullopt;

    const auto fcom_op = fcom_instr->opcode;
    const bool is_double_pop = (fcom_op == kOpcodeName_fcompp || fcom_op == kOpcodeName_fucompp);
    const bool is_popping = is_double_pop ||
                            (fcom_op == kOpcodeName_fcomp || fcom_op == kOpcodeName_fucomp);

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_st0 = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // ── Load ST(0) ──────────────────────────────────────────────────────────
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── Load comparand ──────────────────────────────────────────────────────
    if (is_double_pop) {
        // FCOMPP/FUCOMPP: comparand is always ST(1) (no explicit operands).
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/1, Wd_tmp, Dd_src, Xst_base);
    } else if (fcom_instr->operands[1].kind == IROperandKind::Register) {
        const int depth = fcom_instr->operands[1].reg.reg.index();
        emit_load_st(buf, Xbase, Wd_top, depth, Wd_tmp, Dd_src, Xst_base);
    } else {
        const bool is_f32 = (fcom_instr->operands[1].mem.size == IROperandSize::S32);
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &fcom_instr->operands[1], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);
    }

    // ── MRS save NZCV, FCMP, branchless CC mapping, MSR restore ─────────────
    emit_mrs_nzcv(buf, Wd_tmp2);
    emit_fcmp_f64(buf, Dd_st0, Dd_src);

    free_fpr(*a1, Dd_src);
    free_fpr(*a1, Dd_st0);

    const int Wd_cc = alloc_free_gpr(*a1);
    const int Wd_vs = alloc_free_gpr(*a1);

    emit_cset(buf, 0, /*CC=*/3, Wd_cc);
    emit_cset(buf, 0, /*VS=*/6, Wd_vs);
    emit_cset(buf, 0, /*EQ=*/0, Wd_tmp);

    emit_msr_nzcv(buf, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // C0 = CC | VS, C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_tmp, Wd_tmp);

    // Pack: Wd_tmp = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, 0, 2, 0, 24, 23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 14, Wd_cc, Wd_tmp);

    free_gpr(*a1, Wd_vs);
    free_gpr(*a1, Wd_cc);

    // ── Build status_word from scratch + BFI into AX ──────────────────────
    const int W_ax = fstsw_instr->operands[0].reg.reg.index();
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // OPT-C: flush deferred TOP before building status_word.
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_sw);

        // Build SW from registers: Wd_sw = (Wd_top << 11) | packed_CC
        emit_bitfield(buf, 0, 2, 0, /*immr=*/21, /*imms=*/20, Wd_top, Wd_sw);  // LSL #11
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);    // ORR CC bits

        // OPT-F6: BFI directly into W_AX
        emit_bitfield(buf, 0, 1, 0, /*immr=*/0, /*imms=*/15, Wd_sw, W_ax);

        // STRH Wd_sw → status_word (still needed for other readers)
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // ── Pop if FCOMP/FUCOMP/FCOMPP/FUCOMPP ─────────────────────────────────
    if (is_popping) {
        if (is_double_pop)
            x87_pop_n(buf, *a1, Xbase, Wd_top, Wd_tmp, 2);
        else
            x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);
        // AX was BFI'd before the pop — TOP bits [13:11] are stale (pre-pop).
        // Patch in the post-pop TOP value (correct for both single and double pop).
        // BFI W_ax, Wd_top, #11, #3  →  BFM immr=21, imms=2
        emit_bitfield(buf, 0, 1, 0, /*immr=*/21, /*imms=*/2, Wd_top, W_ax);
    }

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/2);
    free_gpr(*a1, Wd_tmp);

    return 2;
}

// =============================================================================
// Peephole: FLD + non-popping arithmetic + FSTP fusion (OPT-F7)
//
// The pattern  FLD src / ARITH / FSTP dst  appears ~7700 times in typical
// x87-heavy binaries.  The FLD push and FSTP pop cancel, so the fused code
// materialises fld_value, performs the arithmetic, and stores the result
// without any stack manipulation.  Saves ~13 emitted AArch64 instructions
// per fused triple (push ≈ 8 + pop ≈ 5).
//
// Two arithmetic forms are handled:
//   Register-register:  ARITH ST(0), ST(1) — result = op(fld_value, old_ST(0))
//   Memory:             ARITH [mem]        — result = op(fld_value, [mem])
//
// Returns 3 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================


static auto try_fuse_fld_arith_fstp(TranslationResult* a1, IRInstr* fld_instr,
                                    IRInstr* arith_instr, IRInstr* fstp_instr)
    -> std::optional<int> {
    // ── 1. Classify FLD source ──────────────────────────────────────────────

    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // // ── 2. Classify non-popping arithmetic ──────────────────────────────────

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
            return std::nullopt;
    }

    const bool arith_is_mem = (arith_instr->operands[0].kind != IROperandKind::Register);

    if (!arith_is_mem) {
        // Register-register: after FLD push, dst must be ST(0) and src must be
        // ST(1) (= old_ST(0)).  Other register combinations are rare and the
        // FSTP store destination would reference shifted indices — not worth it.
        if (arith_instr->operands[0].reg.reg.index() != 0)
            return std::nullopt;
        if (arith_instr->operands[1].reg.reg.index() != 1)
            return std::nullopt;
    }

    // ── 3. Validate FSTP ────────────────────────────────────────────────────

    if (fstp_instr->opcode != kOpcodeName_fstp && fstp_instr->opcode != kOpcodeName_fstp_stack)
        return std::nullopt;

    const bool fstp_is_reg = (fstp_instr->operands[0].kind == IROperandKind::Register);

    if (fstp_is_reg) {
        // FSTP ST(1) after FLD push = store to old_ST(0) position, pop.
        // Net: ST(0) = result.
        if (fstp_instr->operands[0].reg.reg.index() != 1)
            return std::nullopt;
    } else {
        if (fstp_instr->operands[0].mem.size == IROperandSize::S80)
            return std::nullopt;
    }
    // // ── 4. Emit fused code ──────────────────────────────────────────────────

    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
    if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_src = alloc_free_fpr(*a1);

    // ── 4a: Materialise FLD value → Dd_fld ──────────────────────────────────

    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 4b: Load the arithmetic's other operand → Dd_src ────────────────────

    int Wk_st0 = -1;  // byte-offset key for old ST(0), needed for FSTP ST(1) path

    if (arith_is_mem) {
        // Memory form: ARITH [mem] — load from memory
        const bool is_f32 = (arith_instr->operands[0].mem.size == IROperandSize::S32);
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &arith_instr->operands[0], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_src, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_src, Dd_src);
    } else {
        // Register-register: src = ST(1) = old ST(0).  Load it and capture the
        // byte-offset key in case FSTP stores back to ST(1).
        Wk_st0 = emit_load_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_src, Xst_base);
    }

    // ── 4c: Arithmetic ─────────────────────────────────────────────────────

    switch (arith) {
        case kAdd:
            emit_fadd_f64(buf, Dd_fld, Dd_fld, Dd_src);
            break;
        case kSub:
            emit_fsub_f64(buf, Dd_fld, Dd_fld, Dd_src);
            break;
        case kSubR:
            emit_fsub_f64(buf, Dd_fld, Dd_src, Dd_fld);
            break;
        case kMul:
            emit_fmul_f64(buf, Dd_fld, Dd_fld, Dd_src);
            break;
        case kDiv:
            emit_fdiv_f64(buf, Dd_fld, Dd_fld, Dd_src);
            break;
        case kDivR:
            emit_fdiv_f64(buf, Dd_fld, Dd_src, Dd_fld);
            break;
    }

    free_fpr(*a1, Dd_src);

    // ── 4d: Store result to FSTP destination ────────────────────────────────

    if (fstp_is_reg) {
        // FSTP ST(1): store to old ST(0) slot.  Push/pop cancel → depth 0 in
        // the un-pushed frame.
        if (Wk_st0 >= 0) {
            // Register-arith path: reuse offset key from emit_load_st.
            emit_store_st_at_offset(buf, Xbase, Wk_st0, Dd_fld, Xst_base);
        } else {
            // Memory-arith path: compute offset fresh.
            emit_store_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_fld, Xst_base);
        }
    } else {
        const bool is_f32 = (fstp_instr->operands[0].mem.size == IROperandSize::S32);
        if (is_f32)
            emit_fcvt_d_to_s(buf, Dd_fld, Dd_fld);

        const int addr =
            compute_operand_address(*a1, /*is_64bit=*/true, &fstp_instr->operands[0], GPR::XZR);
        emit_fstr_imm(buf, is_f32 ? 2 : 3, Dd_fld, addr, 0);
        free_gpr(*a1, addr);
    }

    free_fpr(*a1, Dd_fld);

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/3);
    free_gpr(*a1, Wd_tmp);

    return 3;
}

// =============================================================================
// Peephole: FLD + non-popping ARITH + popping ARITHp fusion
//
// The pattern  FLD src / ARITH ST(0),ST(1) / ARITHp ST(1)  appears ~1555+
// times in a real-world MMO binary (fld|fmul|faddp alone = 1555).
// After FLD push: ST(0)=fld_value, ST(1)=old_ST(0).
// Non-popping arith: ST(0) = op1(fld_value, old_ST0).  No stack change.
// Popping arith (ARITHp ST(1)): ST(1) = op2(old_ST0, intermediate), pop.
// Push + pop cancel → net zero stack.  Result lands in ST(0).
//
// Fused: load old ST(0), materialise FLD value, apply middle arith on them,
// apply final arith on intermediate + old_ST0, store result to ST(0).
// No push/pop emitted.  Saves ~16 AArch64 instructions.
//
// Returns 3 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_arith_arithp(TranslationResult* a1, IRInstr* fld_instr,
                                       IRInstr* arith_instr, IRInstr* arithp_instr)
    -> std::optional<int> {
    // ── 1. Classify FLD source ──────────────────────────────────────────────
    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // ── 2. Classify non-popping middle arithmetic ────────────────────────────
    enum ArithOp { kAdd, kSub, kSubR, kMul, kDiv, kDivR };

    const auto arith_opcode = arith_instr->opcode;
    ArithOp arith1;
    switch (arith_opcode) {
        case kOpcodeName_fadd:  arith1 = kAdd;  break;
        case kOpcodeName_fsub:  arith1 = kSub;  break;
        case kOpcodeName_fsubr: arith1 = kSubR; break;
        case kOpcodeName_fmul:  arith1 = kMul;  break;
        case kOpcodeName_fdiv:  arith1 = kDiv;  break;
        case kOpcodeName_fdivr: arith1 = kDivR; break;
        default: return std::nullopt;
    }

    const bool arith1_is_mem = (arith_instr->operands[0].kind != IROperandKind::Register);
    if (!arith1_is_mem) {
        // Register form: after FLD push, must be ST(0) op ST(1).
        if (arith_instr->operands[0].reg.reg.index() != 0)
            return std::nullopt;
        if (arith_instr->operands[1].reg.reg.index() != 1)
            return std::nullopt;
    }

    // ── 3. Classify popping final arithmetic ────────────────────────────────
    const auto arithp_opcode = arithp_instr->opcode;
    ArithOp arith2;
    switch (arithp_opcode) {
        case kOpcodeName_faddp:  arith2 = kAdd;  break;
        case kOpcodeName_fsubp:  arith2 = kSub;  break;
        case kOpcodeName_fsubrp: arith2 = kSubR; break;
        case kOpcodeName_fmulp:  arith2 = kMul;  break;
        case kOpcodeName_fdivp:  arith2 = kDiv;  break;
        case kOpcodeName_fdivrp: arith2 = kDivR; break;
        default: return std::nullopt;
    }

    // After FLD push, ARITHp must target ST(1) (= old_ST(0) before push).
    if (arithp_instr->operands[0].reg.reg.index() != 1)
        return std::nullopt;

    // ── 4. Emit fused code ──────────────────────────────────────────────────
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);
    const int Wd_tmp = alloc_gpr(*a1, 2);

    // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
    if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_tmp);

    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_st0 = alloc_free_fpr(*a1);

    // ── 4a: Materialise FLD value → Dd_fld ──────────────────────────────────
    // Must happen before the emit_load_st below: for kFldReg, emit_fld_value
    // calls emit_load_st with a non-zero depth, which (in uncached mode) writes
    // the depth-N byte-offset into Wd_tmp.  If we captured Wk_st0 = Wd_tmp
    // first, emit_fld_value would clobber it and the final store would land in
    // the wrong ST slot.
    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 4b: Load old ST(0) → Dd_st0 ─────────────────────────────────────────
    // Capture key for storing back (net-zero push/pop means same physical slot).
    // Wd_tmp is now free to be reused as the depth-0 offset key.
    const int Wk_st0 = emit_load_st(buf, Xbase, Wd_top, /*depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── 4c: Middle arithmetic — operates on Dd_fld (new ST(0)) and Dd_st0 (ST(1))
    //        Result in Dd_fld (the intermediate).
    if (arith1_is_mem) {
        // Memory operand: load it into a temporary, then operate.
        const int Dd_mem = alloc_free_fpr(*a1);
        const bool is_f32 = (arith_instr->operands[0].mem.size == IROperandSize::S32);
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &arith_instr->operands[0], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_mem, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_mem, Dd_mem);
        switch (arith1) {
            case kAdd:  emit_fadd_f64(buf, Dd_fld, Dd_fld, Dd_mem); break;
            case kSub:  emit_fsub_f64(buf, Dd_fld, Dd_fld, Dd_mem); break;
            case kSubR: emit_fsub_f64(buf, Dd_fld, Dd_mem, Dd_fld); break;
            case kMul:  emit_fmul_f64(buf, Dd_fld, Dd_fld, Dd_mem); break;
            case kDiv:  emit_fdiv_f64(buf, Dd_fld, Dd_fld, Dd_mem); break;
            case kDivR: emit_fdiv_f64(buf, Dd_fld, Dd_mem, Dd_fld); break;
        }
        free_fpr(*a1, Dd_mem);
    } else {
        // Register form: Dd_fld = op1(Dd_fld, Dd_st0).
        switch (arith1) {
            case kAdd:  emit_fadd_f64(buf, Dd_fld, Dd_fld, Dd_st0); break;
            case kSub:  emit_fsub_f64(buf, Dd_fld, Dd_fld, Dd_st0); break;
            case kSubR: emit_fsub_f64(buf, Dd_fld, Dd_st0, Dd_fld); break;
            case kMul:  emit_fmul_f64(buf, Dd_fld, Dd_fld, Dd_st0); break;
            case kDiv:  emit_fdiv_f64(buf, Dd_fld, Dd_fld, Dd_st0); break;
            case kDivR: emit_fdiv_f64(buf, Dd_fld, Dd_st0, Dd_fld); break;
        }
    }

    // ── 4d: Final popping arithmetic — ARITHp ST(1):
    //        ST(1) = op2(ST(1), ST(0)) = op2(old_ST0=Dd_st0, intermediate=Dd_fld).
    //        Result stored back to ST(0) slot (push+pop cancel → same depth=0 slot).
    switch (arith2) {
        case kAdd:  emit_fadd_f64(buf, Dd_st0, Dd_st0, Dd_fld); break;
        case kSub:  emit_fsub_f64(buf, Dd_st0, Dd_st0, Dd_fld); break;
        case kSubR: emit_fsub_f64(buf, Dd_st0, Dd_fld, Dd_st0); break;
        case kMul:  emit_fmul_f64(buf, Dd_st0, Dd_st0, Dd_fld); break;
        case kDiv:  emit_fdiv_f64(buf, Dd_st0, Dd_st0, Dd_fld); break;
        case kDivR: emit_fdiv_f64(buf, Dd_st0, Dd_fld, Dd_st0); break;
    }

    free_fpr(*a1, Dd_fld);

    // ── 4e: Store result back to ST(0) (same physical slot, net-zero stack) ─
    emit_store_st_at_offset(buf, Xbase, Wk_st0, Dd_st0, Xst_base);
    free_fpr(*a1, Dd_st0);

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/3);
    free_gpr(*a1, Wd_tmp);

    return 3;
}

// =============================================================================
// Peephole: FLD + FCOMP/FUCOMP + FNSTSW AX fusion (OPT-F8)
//
// The pattern  FLD src / FCOMP ST(1) / FNSTSW AX  appears ~1578 times in
// typical x87-heavy binaries.  After FLD pushes, ST(0)=loaded value and
// ST(1)=old_ST(0).  FCOMP ST(1) compares ST(0) vs ST(1) and pops.
// Push + pop cancel → no net stack change.
//
// Fused: materialise FLD value + load old_ST(0), FCMP, map NZCV → x87 CC,
// BFI into AX (OPT-F6 trick).  Saves push/pop overhead + redundant
// status_word LDRH.
//
// Returns 3 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_fcomp_fstsw(TranslationResult* a1, IRInstr* fld_instr,
                                      IRInstr* fcomp_instr, IRInstr* fstsw_instr)
    -> std::optional<int> {
    // ── 1. Validate FCOMP/FUCOMP ────────────────────────────────────────────
    const auto fcomp_op = fcomp_instr->opcode;
    if (fcomp_op != kOpcodeName_fcomp && fcomp_op != kOpcodeName_fucomp)
        return std::nullopt;

    // After FLD push, FCOMP can be:
    //   Register form: FCOMP ST(0), ST(1)  — compares fld_value vs old_ST(0)
    //   Memory form:   FCOMP ST(0), m32/m64 — compares fld_value vs memory
    // Rosetta IR: operands[0] = ST(0) (implicit), operands[1] = comparand.
    const bool fcomp_is_mem = (fcomp_instr->operands[1].kind != IROperandKind::Register);
    if (!fcomp_is_mem) {
        if (fcomp_instr->operands[1].reg.reg.index() != 1)
            return std::nullopt;
    } else {
        if (fcomp_instr->operands[1].mem.size == IROperandSize::S80)
            return std::nullopt;
    }

    // ── 2. Validate FNSTSW AX ───────────────────────────────────────────────
    if (fstsw_instr->opcode != kOpcodeName_fstsw)
        return std::nullopt;
    if (fstsw_instr->operands[0].kind != IROperandKind::Register)
        return std::nullopt;

    // ── 3. Classify FLD source ──────────────────────────────────────────────
    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // ── 4. Emit fused code ──────────────────────────────────────────────────
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_cmp = alloc_free_fpr(*a1);

    // ── 4a: Materialise FLD value → Dd_fld ──────────────────────────────────
    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 4b: Load comparand → Dd_cmp ────────────────────────────────────────
    if (fcomp_is_mem) {
        const bool is_f32 = (fcomp_instr->operands[1].mem.size == IROperandSize::S32);
        const int addr_reg =
            compute_operand_address(*a1, /*is_64bit=*/true, &fcomp_instr->operands[1], GPR::XZR);
        emit_fldr_imm(buf, is_f32 ? 2 : 3, Dd_cmp, addr_reg, /*imm12=*/0);
        free_gpr(*a1, addr_reg);
        if (is_f32)
            emit_fcvt_s_to_d(buf, Dd_cmp, Dd_cmp);
    } else {
        emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_cmp, Xst_base);
    }

    // ── 4c: Save NZCV, FCMP, branchless CC mapping, restore NZCV ───────────
    emit_mrs_nzcv(buf, Wd_tmp2);
    emit_fcmp_f64(buf, Dd_fld, Dd_cmp);

    free_fpr(*a1, Dd_cmp);
    free_fpr(*a1, Dd_fld);

    const int Wd_cc = alloc_free_gpr(*a1);
    const int Wd_vs = alloc_free_gpr(*a1);

    emit_cset(buf, 0, /*CC=*/3, Wd_cc);
    emit_cset(buf, 0, /*VS=*/6, Wd_vs);
    emit_cset(buf, 0, /*EQ=*/0, Wd_tmp);

    emit_msr_nzcv(buf, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // C0 = CC | VS, C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_tmp, Wd_tmp);

    // Pack: Wd_tmp = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, 0, 2, 0, 24, 23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 14, Wd_cc, Wd_tmp);

    free_gpr(*a1, Wd_vs);
    free_gpr(*a1, Wd_cc);

    // ── 4d: Build status_word from scratch + BFI into AX ──────────────────
    const int W_ax = fstsw_instr->operands[0].reg.reg.index();
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
        if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
            x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_sw);

        // Build SW from registers: Wd_sw = (Wd_top << 11) | packed_CC
        emit_bitfield(buf, 0, 2, 0, /*immr=*/21, /*imms=*/20, Wd_top, Wd_sw);  // LSL #11
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);    // ORR CC bits

        // OPT-F6: BFI directly into W_AX
        emit_bitfield(buf, 0, 1, 0, /*immr=*/0, /*imms=*/15, Wd_sw, W_ax);

        // STRH Wd_sw → status_word
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // ── 4e: No push/pop — they cancel ───────────────────────────────────────
    // But we still need the TOP bits in AX to reflect the post-pop state,
    // even though net TOP is unchanged.  Since FCOMP pops after FLD push,
    // the net TOP is the same as before.  The status_word already has the
    // correct TOP (we flushed above), so AX is correct.

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/3);
    free_gpr(*a1, Wd_tmp);

    return 3;
}

// =============================================================================
// Peephole: FLD + FCOMP/FUCOMP fusion (no FSTSW)
//
// The pattern  FLD src / FCOMP ST(1)  appears ~1649 times in a real-world MMO binary.
// After FLD push, ST(0)=loaded value and ST(1)=old_ST(0).
// FCOMP compares ST(0) vs ST(1) and pops.
// Net stack change: push + pop = zero.
//
// Fused: materialise FLD value + load old_ST(0), FCMP, map NZCV → x87 CC,
// write CC bits to status_word.  No push/pop emitted.
// Identical to fld_fcomp_fstsw but without the FSTSW BFI-into-AX step.
//
// Returns 2 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_fcomp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* fcomp_instr)
    -> std::optional<int> {
    // ── 1. Validate FCOMP/FUCOMP ────────────────────────────────────────────
    const auto fcomp_op = fcomp_instr->opcode;
    if (fcomp_op != kOpcodeName_fcomp && fcomp_op != kOpcodeName_fucomp)
        return std::nullopt;

    // After FLD push, FCOMP must compare ST(0) vs ST(1) (register form).
    if (fcomp_instr->operands[0].kind != IROperandKind::Register)
        return std::nullopt;
    if (fcomp_instr->operands[1].reg.reg.index() != 1)
        return std::nullopt;

    // ── 2. Classify FLD source ──────────────────────────────────────────────
    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // ── 3. Emit fused code ──────────────────────────────────────────────────
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_st0 = alloc_free_fpr(*a1);

    // ── 3a: Materialise FLD value → Dd_fld ──────────────────────────────────
    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 3b: Load old ST(0) → Dd_st0 ────────────────────────────────────────
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── 3c: Save NZCV, FCMP, branchless CC mapping, restore NZCV ───────────
    emit_mrs_nzcv(buf, Wd_tmp2);
    emit_fcmp_f64(buf, Dd_fld, Dd_st0);

    free_fpr(*a1, Dd_st0);
    free_fpr(*a1, Dd_fld);

    const int Wd_cc = alloc_free_gpr(*a1);
    const int Wd_vs = alloc_free_gpr(*a1);

    emit_cset(buf, 0, /*CC=*/3, Wd_cc);
    emit_cset(buf, 0, /*VS=*/6, Wd_vs);
    emit_cset(buf, 0, /*EQ=*/0, Wd_tmp);

    emit_msr_nzcv(buf, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // C0 = CC | VS, C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_tmp, Wd_tmp);

    // Pack: Wd_tmp = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, 0, 2, 0, 24, 23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 14, Wd_cc, Wd_tmp);

    free_gpr(*a1, Wd_vs);
    free_gpr(*a1, Wd_cc);

    // ── 3d: RMW status_word with new CC bits ────────────────────────────────
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
        if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
            x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_sw);

        // LDRH Wd_sw, [Xbase, #status_word]
        emit_ldr_str_imm(buf, 1, 0, 1, kX87StatusWordImm12, Xbase, Wd_sw);

        // Clear CC bits [10:8] and bit 14
        emit_bitfield(buf, 0, 1, 0, 24, 2, GPR::XZR, Wd_sw);
        emit_bitfield(buf, 0, 1, 0, 18, 0, GPR::XZR, Wd_sw);

        // ORR in new CC bits
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);

        // STRH Wd_sw → status_word
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // ── 3e: No push/pop — they cancel ───────────────────────────────────────
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/2);
    free_gpr(*a1, Wd_tmp);

    return 2;
}

// =============================================================================
// Peephole: FLD + FCOMPP/FUCOMPP + FNSTSW AX fusion (OPT-F9)
//
// The pattern  FLD src / FCOMPP ST(1) / FNSTSW AX  appears ~607 times in
// CoD2.  After FLD pushes, ST(0)=loaded value and ST(1)=old_ST(0).
// FUCOMPP compares ST(0) vs ST(1) and double-pops.
// Net stack change: push + 2 pops = one logical pop (TOP+1).
//
// Fused: materialise FLD value + load old_ST(0), FCMP, map NZCV → x87 CC,
// BFI into AX (OPT-F6 trick), one net pop.  Saves push/pop overhead +
// redundant status_word LDRH.
//
// Returns 3 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_fcompp_fstsw(TranslationResult* a1, IRInstr* fld_instr,
                                       IRInstr* fcompp_instr, IRInstr* fstsw_instr)
    -> std::optional<int> {
    // ── 1. Validate FCOMPP/FUCOMPP ──────────────────────────────────────────
    const auto fcompp_op = fcompp_instr->opcode;
    if (fcompp_op != kOpcodeName_fcompp && fcompp_op != kOpcodeName_fucompp)
        return std::nullopt;
    // FCOMPP/FUCOMPP always compare ST(0) vs ST(1) — no explicit operands.

    // ── 2. Validate FNSTSW AX ───────────────────────────────────────────────
    if (fstsw_instr->opcode != kOpcodeName_fstsw)
        return std::nullopt;
    if (fstsw_instr->operands[0].kind != IROperandKind::Register)
        return std::nullopt;

    // ── 3. Classify FLD source ──────────────────────────────────────────────
    auto cls = classify_fld_source(fld_instr);
    if (cls.source == kFldInvalid)
        return std::nullopt;

    // ── 4. Emit fused code ──────────────────────────────────────────────────
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_fld = alloc_free_fpr(*a1);
    const int Dd_st0 = alloc_free_fpr(*a1);

    // ── 4a: Materialise FLD value → Dd_fld ──────────────────────────────────
    emit_fld_value(buf, *a1, cls, fld_instr, Xbase, Wd_top, Wd_tmp, Dd_fld, Xst_base);

    // ── 4b: Load old ST(0) → Dd_st0 ─────────────────────────────────────────
    // After FLD push: old_ST(0) is at depth=0 from current TOP (pre-push TOP).
    emit_load_st(buf, Xbase, Wd_top, /*stack_depth=*/0, Wd_tmp, Dd_st0, Xst_base);

    // ── 4c: Save NZCV, FCMP(fld_value vs old_ST(0)), map CC, restore NZCV ──
    emit_mrs_nzcv(buf, Wd_tmp2);
    emit_fcmp_f64(buf, Dd_fld, Dd_st0);

    free_fpr(*a1, Dd_st0);
    free_fpr(*a1, Dd_fld);

    const int Wd_cc = alloc_free_gpr(*a1);
    const int Wd_vs = alloc_free_gpr(*a1);

    emit_cset(buf, 0, /*CC=*/3, Wd_cc);
    emit_cset(buf, 0, /*VS=*/6, Wd_vs);
    emit_cset(buf, 0, /*EQ=*/0, Wd_tmp);

    emit_msr_nzcv(buf, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // C0 = CC | VS, C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_tmp, Wd_tmp);

    // Pack: Wd_tmp = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, 0, 2, 0, 24, 23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 14, Wd_cc, Wd_tmp);

    free_gpr(*a1, Wd_vs);
    free_gpr(*a1, Wd_cc);

    // ── 4d: RMW status_word + BFI into AX (OPT-F6 trick) ───────────────────
    const int W_ax = fstsw_instr->operands[0].reg.reg.index();
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // OPT-C: flush deferred TOP before reading status_word.
        x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_sw);

        // LDRH Wd_sw, [Xbase, #status_word]
        emit_ldr_str_imm(buf, 1, 0, 1, kX87StatusWordImm12, Xbase, Wd_sw);

        // Clear CC bits [10:8] and bit 14
        emit_bitfield(buf, 0, 1, 0, 24, 2, GPR::XZR, Wd_sw);
        emit_bitfield(buf, 0, 1, 0, 18, 0, GPR::XZR, Wd_sw);

        // ORR in new CC bits
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);

        // OPT-F6: BFI directly into W_AX
        emit_bitfield(buf, 0, 1, 0, /*immr=*/0, /*imms=*/15, Wd_sw, W_ax);

        // STRH Wd_sw → status_word
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // ── 4e: Net one pop (FLD push + FCOMPP double-pop = +1 net pop) ─────────
    x87_pop(buf, *a1, Xbase, Wd_top, Wd_tmp);
    // AX was BFI'd before the pop — patch in post-pop TOP value.
    // BFI W_ax, Wd_top, #11, #3  →  BFM immr=21, imms=2
    emit_bitfield(buf, 0, 1, 0, /*immr=*/21, /*imms=*/2, Wd_top, W_ax);

    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, /*consumed=*/3);
    free_gpr(*a1, Wd_tmp);

    return 3;
}

// =============================================================================
// Peephole: FLD + FLD + FCOMPP/FUCOMPP [+ FNSTSW AX] fusion (OPT-F10)
//
// The patterns:
//   FLD val1 / FLD val2 / FCOMPP [/ FNSTSW AX]
// appear ~501 (3-instr) and ~495 (4-instr) times in CoD2.
//
// After two FLDs: ST(0)=val2, ST(1)=val1, ST(2)=old_ST(0).
// FUCOMPP compares ST(0) vs ST(1) = val2 vs val1, then double-pops.
// Net stack change: 2 pushes + 2 pops = zero.
//
// Fused: materialise both FLD values, FCMP, map NZCV → x87 CC, optionally
// BFI into AX.  No push or pop needed (net zero).  Saves ~26 AArch64
// instructions (two pushes + two pops eliminated).
//
// Returns 3 or 4 (instructions consumed) if fused, std::nullopt otherwise.
// =============================================================================

static auto try_fuse_fld_fld_fucompp(TranslationResult* a1,
                                      IRInstr* fld1_instr, IRInstr* fld2_instr,
                                      IRInstr* fucompp_instr, IRInstr* fstsw_instr)
    -> std::optional<int> {
    // ── 1. Validate second FLD ───────────────────────────────────────────────
    // (First FLD is already validated by the caller via classify_fld_source.)
    auto cls1 = classify_fld_source(fld1_instr);
    if (cls1.source == kFldInvalid)
        return std::nullopt;

    auto cls2 = classify_fld_source(fld2_instr);
    if (cls2.source == kFldInvalid)
        return std::nullopt;

    // ── 2. Validate FCOMPP/FUCOMPP ──────────────────────────────────────────
    const auto fucompp_op = fucompp_instr->opcode;
    if (fucompp_op != kOpcodeName_fcompp && fucompp_op != kOpcodeName_fucompp)
        return std::nullopt;

    // ── 3. Optionally validate FSTSW AX (4-instruction form) ────────────────
    const bool has_fstsw = (fstsw_instr != nullptr
                            && fstsw_instr->opcode == kOpcodeName_fstsw
                            && fstsw_instr->operands[0].kind == IROperandKind::Register);

    // ── 4. Emit fused code ──────────────────────────────────────────────────
    AssemblerBuffer& buf = a1->insn_buf;
    auto [Xbase, Wd_top] = x87_begin(*a1, buf);
    const int Xst_base = x87_get_st_base(*a1);

    static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;

    const int Wd_tmp = alloc_gpr(*a1, 2);
    const int Wd_tmp2 = alloc_gpr(*a1, 3);
    const int Dd_val1 = alloc_free_fpr(*a1);
    const int Dd_val2 = alloc_free_fpr(*a1);

    // ── 4a: Materialise both FLD values ─────────────────────────────────────
    // val1 is the first FLD (becomes ST(1) after both pushes).
    // val2 is the second FLD (becomes ST(0) after both pushes).
    // cls1 always uses pre-fusion TOP (correct).
    // cls2 of kFldReg needs depth adjustment: fld2 executes after fld1 has
    // decremented TOP by 1, so `fld ST(k)` as fld2 loads physical reg
    // (TOP-1+k)&7 = pre-fusion ST(k-1).  Special case k==0: fld ST(0) after
    // fld1's push = val1, so just copy Dd_val1.
    emit_fld_value(buf, *a1, cls1, fld1_instr, Xbase, Wd_top, Wd_tmp, Dd_val1, Xst_base);
    if (cls2.source == kFldReg) {
        if (cls2.reg_depth == 0) {
            // fld ST(0) as second FLD → same value as val1; copy it.
            emit_fmov_f64_reg(buf, Dd_val2, Dd_val1);
        } else {
            FldClassification cls2_adj = cls2;
            cls2_adj.reg_depth -= 1;
            emit_fld_value(buf, *a1, cls2_adj, fld2_instr, Xbase, Wd_top, Wd_tmp, Dd_val2, Xst_base);
        }
    } else {
        emit_fld_value(buf, *a1, cls2, fld2_instr, Xbase, Wd_top, Wd_tmp, Dd_val2, Xst_base);
    }

    // ── 4b: Save NZCV, FCMP(val2 vs val1), map CC, restore NZCV ────────────
    // FUCOMPP semantics: compare ST(0) vs ST(1) = val2 vs val1.
    emit_mrs_nzcv(buf, Wd_tmp2);
    emit_fcmp_f64(buf, Dd_val2, Dd_val1);

    free_fpr(*a1, Dd_val1);
    free_fpr(*a1, Dd_val2);

    const int Wd_cc = alloc_free_gpr(*a1);
    const int Wd_vs = alloc_free_gpr(*a1);

    emit_cset(buf, 0, /*CC=*/3, Wd_cc);
    emit_cset(buf, 0, /*VS=*/6, Wd_vs);
    emit_cset(buf, 0, /*EQ=*/0, Wd_tmp);

    emit_msr_nzcv(buf, Wd_tmp2);
    free_gpr(*a1, Wd_tmp2);

    // C0 = CC | VS, C3 = EQ | VS
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 0, Wd_tmp, Wd_tmp);

    // Pack: Wd_tmp = (C0 << 8) | (C2 << 10) | (C3 << 14)
    emit_bitfield(buf, 0, 2, 0, 24, 23, Wd_cc, Wd_cc);  // LSL #8
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_vs, 10, Wd_cc, Wd_cc);
    emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 14, Wd_cc, Wd_tmp);

    free_gpr(*a1, Wd_vs);
    free_gpr(*a1, Wd_cc);

    // ── 4c: Build status_word from scratch (+ optional copy into AX) ────────
    // Construct SW = (TOP << 11) | CC_bits.  Avoids reading stale status word
    // from memory, which caused first-call CC corruption.
    {
        const int Wd_sw = alloc_free_gpr(*a1);

        // OPT-D: net-zero-stack fusion — skip flush to preserve full cancellation.
        if (!(a1->x87_cache.tag_push_pending && a1->x87_cache.top_dirty))
            x87_flush_top(buf, *a1, Xbase, Wd_top, Wd_sw);

        // Build SW from registers: Wd_sw = (Wd_top << 11) | packed_CC
        emit_bitfield(buf, 0, 2, 0, /*immr=*/21, /*imms=*/20, Wd_top, Wd_sw);  // LSL #11
        emit_logical_shifted_reg(buf, 0, 1, 0, 0, Wd_tmp, 0, Wd_sw, Wd_sw);    // ORR CC bits

        if (has_fstsw) {
            const int W_ax = fstsw_instr->operands[0].reg.reg.index();
            // MOV W_ax, Wd_sw
            buf.emit(0x2A0003E0u | (uint32_t(Wd_sw) << 16) | uint32_t(W_ax));
        }

        // STRH Wd_sw → status_word
        emit_ldr_str_imm(buf, 1, 0, 0, kX87StatusWordImm12, Xbase, Wd_sw);

        free_gpr(*a1, Wd_sw);
    }

    // ── 4d: No push or pop (2 pushes + 2 pops = net zero) ───────────────────
    // TOP is unchanged; memory already has correct TOP (OPT-D or flushed above).

    const int consumed = has_fstsw ? 4 : 3;
    x87_end(*a1, buf, Xbase, Wd_top, Wd_tmp, consumed);
    free_gpr(*a1, Wd_tmp);

    return consumed;
}

// =============================================================================
// Per-opcode-group fusion dispatchers (longest patterns first)
// =============================================================================

static auto try_fuse_fld_group(TranslationResult* tr, IRInstr* instrs, int64_t num, int64_t idx,
                               uint64_t disabled_mask) -> std::optional<int> {
    IRInstr* cur = &instrs[idx];
    IRInstr* next = &instrs[idx + 1];  // caller guarantees idx+1 < num

    // Reject fusions when the FLD reads from a memory address that a preceding
    // non-x87 store in the same block also writes to.  Rosetta may forward the
    // store value in a register and elide the ARM STR, so our fused LDR would
    // read stale data.  Only memory-sourced FLDs with an actual conflict are
    // rejected; register/constant FLDs and loads with no conflicting store are
    // allowed through.
    const bool fld0_conflict = is_memory_fld_with_store_conflict(instrs, idx);

    // 4-instruction fusions (longest first) — both FLDs must be conflict-free
    if (idx + 3 < num && !fld0_conflict) {
        if (!fusion_disabled(disabled_mask, FusionId::fld_fld_fucompp))
            if (!is_memory_fld_with_store_conflict(instrs, idx + 1))
                if (auto r = try_fuse_fld_fld_fucompp(tr, cur, next, &instrs[idx + 2], &instrs[idx + 3]))
                    return r;
    }

    if (fld0_conflict)
        return std::nullopt;

    // 3-instruction fusions
    if (idx + 2 < num) {
        if (!fusion_disabled(disabled_mask, FusionId::fld_arith_fstp))
            if (auto r = try_fuse_fld_arith_fstp(tr, cur, next, &instrs[idx + 2]))
                return r;
        if (!fusion_disabled(disabled_mask, FusionId::fld_arith_arithp))
            if (auto r = try_fuse_fld_arith_arithp(tr, cur, next, &instrs[idx + 2]))
                return r;
        if (!fusion_disabled(disabled_mask, FusionId::fld_fcomp_fstsw))
            if (auto r = try_fuse_fld_fcomp_fstsw(tr, cur, next, &instrs[idx + 2]))
                return r;
        if (!fusion_disabled(disabled_mask, FusionId::fld_fcompp_fstsw))
            if (auto r = try_fuse_fld_fcompp_fstsw(tr, cur, next, &instrs[idx + 2]))
                return r;
        if (!fusion_disabled(disabled_mask, FusionId::fld_fld_fucompp))
            if (!is_memory_fld_with_store_conflict(instrs, idx + 1))
                if (auto r = try_fuse_fld_fld_fucompp(tr, cur, next, &instrs[idx + 2], nullptr))
                    return r;
    }

    // 2-instruction fusions
    if (!fusion_disabled(disabled_mask, FusionId::fld_arithp))
        if (auto r = try_fuse_fld_arithp(tr, cur, next))
            return r;
    if (!fusion_disabled(disabled_mask, FusionId::fld_fstp))
        if (auto r = try_fuse_fld_fstp(tr, cur, next))
            return r;
    if (!fusion_disabled(disabled_mask, FusionId::fld_fcomp))
        if (auto r = try_fuse_fld_fcomp(tr, cur, next))
            return r;

    return std::nullopt;
}

static auto try_fuse_fxch_group(TranslationResult* tr, IRInstr* instrs, int64_t num, int64_t idx,
                                uint64_t disabled_mask) -> std::optional<int> {
    IRInstr* cur = &instrs[idx];
    IRInstr* next = &instrs[idx + 1];

    if (!fusion_disabled(disabled_mask, FusionId::fxch_arithp))
        if (auto r = try_fuse_fxch_arithp(tr, cur, next))
            return r;
    if (!fusion_disabled(disabled_mask, FusionId::fxch_fstp))
        if (auto r = try_fuse_fxch_fstp(tr, cur, next))
            return r;

    return std::nullopt;
}

static auto try_fuse_fcom_group(TranslationResult* tr, IRInstr* instrs, int64_t num, int64_t idx,
                                uint64_t disabled_mask) -> std::optional<int> {
    IRInstr* cur = &instrs[idx];
    IRInstr* next = &instrs[idx + 1];

    if (!fusion_disabled(disabled_mask, FusionId::fcom_fstsw))
        if (auto r = try_fuse_fcom_fstsw(tr, cur, next))
            return r;

    return std::nullopt;
}

// =============================================================================
// try_peephole — single entry point for all peephole fusion patterns
// =============================================================================

auto try_peephole(TranslationResult* tr, IRInstr* instrs, int64_t num, int64_t idx,
                  uint64_t disabled_mask) -> std::optional<int> {
    if (idx + 1 >= num)
        return std::nullopt;

    switch (instrs[idx].opcode) {
        case kOpcodeName_fld:
        case kOpcodeName_fild:
        case kOpcodeName_fldz:
        case kOpcodeName_fld1:
        case kOpcodeName_fldl2e:
        case kOpcodeName_fldl2t:
        case kOpcodeName_fldlg2:
        case kOpcodeName_fldln2:
        case kOpcodeName_fldpi:
            return try_fuse_fld_group(tr, instrs, num, idx, disabled_mask);

        case kOpcodeName_fxch:
            return try_fuse_fxch_group(tr, instrs, num, idx, disabled_mask);

        case kOpcodeName_fcom:
        case kOpcodeName_fcomp:
        case kOpcodeName_fucom:
        case kOpcodeName_fucomp:
        case kOpcodeName_fcompp:
        case kOpcodeName_fucompp:
            return try_fuse_fcom_group(tr, instrs, num, idx, disabled_mask);

        default:
            return std::nullopt;
    }
}

};  // namespace TranslatorX87
