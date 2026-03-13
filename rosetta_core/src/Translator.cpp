#include "rosetta_core/Translator.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorX87.h"
#include "rosetta_core/TranslatorX87Fusion.h"
#include "rosetta_core/X87Cache.h"
#include "rosetta_config/Config.h"

static OpcodeId opcode_to_id(uint16_t op) {
    using O = Opcode;
    using I = OpcodeId;
    switch (op) {
        case O::kOpcodeName_fldz:                                return I::fldz;
        case O::kOpcodeName_fld1:                                return I::fld1;
        case O::kOpcodeName_fldl2e:                              return I::fldl2e;
        case O::kOpcodeName_fldl2t:                              return I::fldl2t;
        case O::kOpcodeName_fldlg2:                              return I::fldlg2;
        case O::kOpcodeName_fldln2:                              return I::fldln2;
        case O::kOpcodeName_fldpi:                               return I::fldpi;
        case O::kOpcodeName_fld:                                 return I::fld;
        case O::kOpcodeName_fild:                                return I::fild;
        case O::kOpcodeName_fadd:     return I::fadd;
        case O::kOpcodeName_faddp:    return I::faddp;
        case O::kOpcodeName_fiadd:    return I::fiadd;
        case O::kOpcodeName_fsub:     return I::fsub;
        case O::kOpcodeName_fsubr:    return I::fsubr;
        case O::kOpcodeName_fsubp:    return I::fsubp;
        case O::kOpcodeName_fsubrp:   return I::fsubrp;
        case O::kOpcodeName_fdiv:     return I::fdiv;
        case O::kOpcodeName_fdivr:    return I::fdivr;
        case O::kOpcodeName_fdivp:    return I::fdivp;
        case O::kOpcodeName_fdivrp:   return I::fdivrp;
        case O::kOpcodeName_fmul:     return I::fmul;
        case O::kOpcodeName_fmulp:    return I::fmulp;
        case O::kOpcodeName_fst:          return I::fst;
        case O::kOpcodeName_fst_stack:    return I::fst_stack;
        case O::kOpcodeName_fstp:         return I::fstp;
        case O::kOpcodeName_fstp_stack:   return I::fstp_stack;
        case O::kOpcodeName_fstsw:    return I::fstsw;
        case O::kOpcodeName_fcom:     return I::fcom;
        case O::kOpcodeName_fcomp:    return I::fcomp;
        case O::kOpcodeName_fcompp:   return I::fcompp;
        case O::kOpcodeName_fucom:    return I::fucom;
        case O::kOpcodeName_fucomp:   return I::fucomp;
        case O::kOpcodeName_fucompp:  return I::fucompp;
        case O::kOpcodeName_fxch:     return I::fxch;
        case O::kOpcodeName_fchs:     return I::fchs;
        case O::kOpcodeName_fabs:     return I::fabs;
        case O::kOpcodeName_fsqrt:    return I::fsqrt;
        case O::kOpcodeName_fistp:    return I::fistp;
        case O::kOpcodeName_fidiv:    return I::fidiv;
        case O::kOpcodeName_fimul:    return I::fimul;
        case O::kOpcodeName_fisub:    return I::fisub;
        case O::kOpcodeName_fidivr:   return I::fidivr;
        case O::kOpcodeName_frndint:  return I::frndint;
        case O::kOpcodeName_fcomi:    return I::fcomi;
        case O::kOpcodeName_fcomip:   return I::fcomip;
        case O::kOpcodeName_fucomi:   return I::fucomi;
        case O::kOpcodeName_fucomip:  return I::fucomip;
        case O::kOpcodeName_ftst:     return I::ftst;
        case O::kOpcodeName_fist:     return I::fist;
        case O::kOpcodeName_fisubr:   return I::fisubr;
        case O::kOpcodeName_fcmovb:   return I::fcmovb;
        case O::kOpcodeName_fcmovbe:  return I::fcmovbe;
        case O::kOpcodeName_fcmove:   return I::fcmove;
        case O::kOpcodeName_fcmovnb:  return I::fcmovnb;
        case O::kOpcodeName_fcmovnbe: return I::fcmovnbe;
        case O::kOpcodeName_fcmovne:  return I::fcmovne;
        case O::kOpcodeName_fcmovu:   return I::fcmovu;
        case O::kOpcodeName_fcmovnu:  return I::fcmovnu;
        default:                      return I::kCount;
    }
}

auto Translator::translate_instruction(TranslationResult* translation_result, IRBlock* block,
                                       IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx)
    -> std::optional<int64_t> {
    const auto cur_instr = &instr_array[insn_idx];
    const auto opcode = cur_instr->opcode;
    auto& cache = translation_result->x87_cache;

    // ── OPT-1: x87 cross-instruction cache management ───────────────────────
    // Invalidate the cache if we've moved to a different block (between blocks,
    // branches may have executed non-x87 code that clobbers scratch GPRs).
    // Then, if no cache is active, scan ahead to find the length of the current
    // consecutive x87 run.  x87_cache_set_run only activates if run >= 2.
    {
        if (block != cache.prev_block) {
            cache.invalidate(translation_result->free_gpr_mask, kGprScratchMask);
            cache.prev_block = block;
        }
        if (!cache.active()) {
            const bool cache_disabled = g_rosetta_config && g_rosetta_config->disable_x87_cache;
            if (!cache_disabled) {
                const uint64_t ops_mask = g_rosetta_config ? g_rosetta_config->disabled_ops_mask : 0;
                const int run = X87Cache::lookahead(instr_array, num_instrs, insn_idx, ops_mask);
                cache.set_run(run);
            }
        }
    }

    // ── Peephole: try 2-instruction fusion patterns ─────────────────────────
    const uint64_t fusions_mask = g_rosetta_config ? g_rosetta_config->disabled_fusions_mask : 0;
    const auto fused =
        TranslatorX87::try_peephole(translation_result, instr_array, num_instrs, insn_idx,
                                    fusions_mask);

    if (!fused) {
        if (g_rosetta_config) {
            const auto id = opcode_to_id(opcode);
            if (id != OpcodeId::kCount && op_is_disabled(*g_rosetta_config, id)) {
                cache.invalidate(translation_result->free_gpr_mask, kGprScratchMask);
                return std::nullopt;
            }
        }

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

            case Opcode::kOpcodeName_fcomi:
            case Opcode::kOpcodeName_fcomip:
            case Opcode::kOpcodeName_fucomi:
            case Opcode::kOpcodeName_fucomip:
                TranslatorX87::translate_fcomi(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_ftst:
                TranslatorX87::translate_ftst(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fist:
                TranslatorX87::translate_fist(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fisubr:
                TranslatorX87::translate_fisubr(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fcmovb:
            case Opcode::kOpcodeName_fcmovbe:
            case Opcode::kOpcodeName_fcmove:
            case Opcode::kOpcodeName_fcmovnb:
            case Opcode::kOpcodeName_fcmovnbe:
            case Opcode::kOpcodeName_fcmovne:
            case Opcode::kOpcodeName_fcmovu:
            case Opcode::kOpcodeName_fcmovnu:
                TranslatorX87::translate_fcmov(translation_result, cur_instr);
                break;

            default:
                // Hand translation back to rosetta, we don't support this instruction - invalidate
                // cache.
                cache.invalidate(translation_result->free_gpr_mask, kGprScratchMask);
                return std::nullopt;
        }
    }

    // OPT-1: Tick the cache (decrements run counter; releases on expiry).
    // Then reset the mask, excluding any GPRs still pinned by the cache.
    // Fused pairs consumed 2 instructions — tick twice.
    const int consumed = fused.value_or(1);
    for (int i = 0; i < consumed; i++) {
        cache.tick();
    }

    if (cache.active()) {
        translation_result->free_gpr_mask = kGprScratchMask & ~cache.pinned_mask();
    } else {
        translation_result->free_gpr_mask = kGprScratchMask;
    }
    translation_result->free_fpr_mask =
        translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
    translation_result->_pinned_temporary_scalars = 0;

    return insn_idx + consumed;
}
