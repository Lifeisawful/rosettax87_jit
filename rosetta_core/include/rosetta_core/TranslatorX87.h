#pragma once

#include <cstdint>

struct TranslationResult;
struct IRInstr;

namespace TranslatorX87 {
// ── OPT-1: Cross-instruction x87 base/TOP register cache ─────────────────
bool x87_cache_active(TranslationResult* tr);
void x87_cache_invalidate(TranslationResult* tr);
void x87_cache_set_run(TranslationResult* tr, int run_length);
void x87_cache_tick(TranslationResult* tr);
uint32_t x87_cache_pinned_mask(TranslationResult* tr);
int x87_cache_lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx);

// ── Peephole fusion: FLD + popping arithmetic ────────────────────────────
// Returns 1 if the pair was fused (2 instructions consumed), 0 otherwise.
int try_fuse_fld_arithp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* arithp_instr);

// ── Peephole fusion: FXCH ST(1) + popping arithmetic ─────────────────────
// Eliminates the FXCH; for non-commutative ops, swaps the operation.
int try_fuse_fxch_arithp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* next_instr);

// ── Peephole fusion: FLD + FSTP (copy elimination) ───────────────────────
// Eliminates push/pop when FLD is immediately followed by FSTP.
int try_fuse_fld_fstp(TranslationResult* a1, IRInstr* fld_instr, IRInstr* fstp_instr);

// ── Peephole fusion: FXCH ST(1) + FSTP ───────────────────────────────────
// Eliminates FXCH when followed by FSTP (pop destroys the swap's trace).
int try_fuse_fxch_fstp(TranslationResult* a1, IRInstr* fxch_instr, IRInstr* fstp_instr);

auto translate_fldz(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fld1(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fldl2e(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fldl2t(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fldlg2(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fldln2(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fldpi(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fld(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fild(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fadd(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_faddp(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fsub(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fsubp(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fdiv(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fdivp(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fmul(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fiadd(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fst(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fstsw(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fcom(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fxch(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fchs(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fabs(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fsqrt(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fistp(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fidiv(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fimul(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fisub(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fidivr(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_frndint(TranslationResult* a1, IRInstr* /*a2*/) -> void;
};  // namespace TranslatorX87