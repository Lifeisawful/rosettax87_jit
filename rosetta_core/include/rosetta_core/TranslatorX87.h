#pragma once

#include <cstdint>

struct TranslationResult;
struct IRInstr;

namespace TranslatorX87 {

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

auto translate_fcomi(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_ftst(TranslationResult* a1, IRInstr* /*a2*/) -> void;

auto translate_fist(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fisubr(TranslationResult* a1, IRInstr* a2) -> void;

auto translate_fcmov(TranslationResult* a1, IRInstr* a2) -> void;

};  // namespace TranslatorX87