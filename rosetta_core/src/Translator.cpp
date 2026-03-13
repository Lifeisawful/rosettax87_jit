#include "rosetta_core/Translator.h"

#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorX87.h"

auto Translator::translate_instruction(TranslationResult* translation_result, IRBlock* block,
                                       IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx)
    -> std::optional<int64_t> {
    const auto cur_instr = &instr_array[insn_idx];
    const auto opcode = cur_instr->opcode;
    const auto absolute_addr =
        translation_result->ir_module_data->text_vmaddr_range + cur_instr->pc;

    // ── OPT-1: x87 cross-instruction cache management ───────────────────────
    // Invalidate the cache if we've moved to a different block (between blocks,
    // branches may have executed non-x87 code that clobbers scratch GPRs).
    // Then, if no cache is active, scan ahead to find the length of the current
    // consecutive x87 run.  x87_cache_set_run only activates if run >= 2.
    {
        if (block != translation_result->x87_cache_prev_block) {
            TranslatorX87::x87_cache_flush_and_invalidate(translation_result);
            translation_result->free_gpr_mask = kGprScratchMask;
            translation_result->x87_cache_prev_block = block;
        }
        if (!TranslatorX87::x87_cache_active(translation_result)) {
            const int run = TranslatorX87::x87_cache_lookahead(instr_array, num_instrs, insn_idx);
            TranslatorX87::x87_cache_set_run(translation_result, run);
        }
    }

    // CORE_LOG("Translating instruction at %llx opcode=0x%04x (%s)", absolute_addr, opcode,
    // kOpcodeNames[opcode]);

    // ── Peephole: try 3-instruction fusion patterns ─────────────────────────
    // Each pattern consumes 3 IR instructions when successful.
    bool fused = false;
    int consumed = 1;
    if (insn_idx + 2 < num_instrs) {
        IRInstr* next1 = &instr_array[insn_idx + 1];
        IRInstr* next2 = &instr_array[insn_idx + 2];
        switch (opcode) {
            case Opcode::kOpcodeName_fld:
            case Opcode::kOpcodeName_fild:
            case Opcode::kOpcodeName_fldz:
            case Opcode::kOpcodeName_fld1:
            case Opcode::kOpcodeName_fldl2e:
            case Opcode::kOpcodeName_fldl2t:
            case Opcode::kOpcodeName_fldlg2:
            case Opcode::kOpcodeName_fldln2:
            case Opcode::kOpcodeName_fldpi:
                fused = TranslatorX87::try_fuse_fld_arith_fstp(
                             translation_result, cur_instr, next1, next2) != 0;
                if (!fused)
                    fused = TranslatorX87::try_fuse_fld_arith_arithp(
                                 translation_result, cur_instr, next1, next2) != 0;
                if (!fused)
                    fused = TranslatorX87::try_fuse_fld_fcomp_fstsw(
                                 translation_result, cur_instr, next1, next2) != 0;
                if (fused)
                    consumed = 3;
                break;
            default:
                break;
        }
    }

    // ── Peephole: try 2-instruction fusion patterns ─────────────────────────
    // Each pattern consumes 2 IR instructions when successful.
    if (!fused && insn_idx + 1 < num_instrs) {
        IRInstr* next = &instr_array[insn_idx + 1];
        switch (opcode) {
            // Pattern 1: FLD variant + popping arithmetic (FADDP, FSUBP, etc.)
            // Pattern 2: FLD variant + FSTP (copy elimination)
            case Opcode::kOpcodeName_fld:
            case Opcode::kOpcodeName_fild:
            case Opcode::kOpcodeName_fldz:
            case Opcode::kOpcodeName_fld1:
            case Opcode::kOpcodeName_fldl2e:
            case Opcode::kOpcodeName_fldl2t:
            case Opcode::kOpcodeName_fldlg2:
            case Opcode::kOpcodeName_fldln2:
            case Opcode::kOpcodeName_fldpi:
                fused =
                    TranslatorX87::try_fuse_fld_arithp(translation_result, cur_instr, next) != 0;
                if (!fused)
                    fused =
                        TranslatorX87::try_fuse_fld_fstp(translation_result, cur_instr, next) != 0;
                break;

            // Pattern 3: FCOMP/FUCOMP/FCOMPP/FUCOMPP + FNSTSW AX
            case Opcode::kOpcodeName_fcomp:
            case Opcode::kOpcodeName_fcompp:
            case Opcode::kOpcodeName_fucomp:
            case Opcode::kOpcodeName_fucompp:
                fused = TranslatorX87::try_fuse_fcomp_fstsw(
                             translation_result, cur_instr, next) != 0;
                break;

            // Pattern 4: FXCH ST(1) + popping arithmetic
            // Pattern 5: FXCH ST(1) + FSTP
            case Opcode::kOpcodeName_fxch:
                fused =
                    TranslatorX87::try_fuse_fxch_arithp(translation_result, cur_instr, next) != 0;
                if (!fused)
                    fused =
                        TranslatorX87::try_fuse_fxch_fstp(translation_result, cur_instr, next) != 0;
                break;

            default:
                break;
        }
    }

    if (!fused) {
        // CORE_LOG("translating at 0x%08x opcode=0x%x (%s)", cur_instr->pc, cur_instr->opcode,
        // kOpcodeNames[cur_instr->opcode]);
        switch (opcode) {
            case Opcode::kOpcodeName_fldz:
                TranslatorX87::translate_fldz(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fld1:
                TranslatorX87::translate_fld1(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fldl2e:
                TranslatorX87::translate_fldl2e(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fldl2t:
                TranslatorX87::translate_fldl2t(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fldlg2:
                TranslatorX87::translate_fldlg2(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fldln2:
                TranslatorX87::translate_fldln2(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fldpi:
                TranslatorX87::translate_fldpi(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fld:
                TranslatorX87::translate_fld(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fild:
                TranslatorX87::translate_fild(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fadd:
                TranslatorX87::translate_fadd(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_faddp:
                TranslatorX87::translate_faddp(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fiadd:
                TranslatorX87::translate_fiadd(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fsub:
            case Opcode::kOpcodeName_fsubr:
                TranslatorX87::translate_fsub(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fsubp:
            case Opcode::kOpcodeName_fsubrp:
                TranslatorX87::translate_fsubp(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fdiv:
            case Opcode::kOpcodeName_fdivr:
                TranslatorX87::translate_fdiv(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fdivp:
            case Opcode::kOpcodeName_fdivrp:
                TranslatorX87::translate_fdivp(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fmul:
            case Opcode::kOpcodeName_fmulp:
                TranslatorX87::translate_fmul(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fst:
            case Opcode::kOpcodeName_fst_stack:
            case Opcode::kOpcodeName_fstp:
            case Opcode::kOpcodeName_fstp_stack:
                TranslatorX87::translate_fst(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fstsw:
                TranslatorX87::translate_fstsw(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fcom:
            case Opcode::kOpcodeName_fcomp:
            case Opcode::kOpcodeName_fcompp:
            case Opcode::kOpcodeName_fucom:
            case Opcode::kOpcodeName_fucomp:
            case Opcode::kOpcodeName_fucompp:
                TranslatorX87::translate_fcom(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fxch:
                TranslatorX87::translate_fxch(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fchs:
                TranslatorX87::translate_fchs(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fabs:
                TranslatorX87::translate_fabs(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fsqrt:
                TranslatorX87::translate_fsqrt(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fistp:
                TranslatorX87::translate_fistp(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fidiv:
                TranslatorX87::translate_fidiv(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fimul:
                TranslatorX87::translate_fimul(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fisub:
                TranslatorX87::translate_fisub(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fidivr:
                TranslatorX87::translate_fidivr(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_frndint:
                TranslatorX87::translate_frndint(translation_result, cur_instr);
                break;
            default: {
                TranslatorX87::x87_cache_invalidate(translation_result);
                translation_result->free_gpr_mask = kGprScratchMask;
                if (opcode >= kOpcodeName_f2xm1 && opcode <= kOpcodeName_fyl2xp1) {
                    // CORE_LOG("Did not translate instruction at PC=0x%08x: (AARCH64PC=0x%08llx)
                    // opcode=0x%04x (%s)", cur_instr->pc, translation_result->insn_buf.end,
                    //         opcode, kOpcodeNames[opcode]);
                }
            }
                return std::nullopt;
        }
    }  // if (!fused)

    // CORE_LOG("Translated 0x%llx opcode=0x%04x (%s)", absolute_addr, opcode,
    // kOpcodeNames[opcode]);

    // OPT-1: Tick the cache (decrements run counter; releases on expiry).
    // Then reset the mask, excluding any GPRs still pinned by the cache.
    // Fused patterns consumed 2 or 3 instructions — tick accordingly.
    if (!fused)
        consumed = 1;
    else if (consumed == 1)
        consumed = 2;  // 2-instruction fusion
    for (int i = 0; i < consumed; i++)
        TranslatorX87::x87_cache_tick(translation_result);

    if (TranslatorX87::x87_cache_active(translation_result)) {
        translation_result->free_gpr_mask =
            kGprScratchMask & ~TranslatorX87::x87_cache_pinned_mask(translation_result);
    } else {
        translation_result->free_gpr_mask = kGprScratchMask;
    }
    translation_result->free_fpr_mask =
        translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
    translation_result->_pinned_temporary_scalars = 0;

    return insn_idx + consumed;
}