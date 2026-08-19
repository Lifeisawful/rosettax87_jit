#include "rosetta_core/Translator.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorCustom.h"
#include "rosetta_core/TranslatorX87.h"
#include "rosetta_core/TranslatorX87Fusion.h"
#include "rosetta_core/X87Cache.h"
#include "rosetta_core/X87IR.h"
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
        case O::kOpcodeName_fisttp:   return I::fisttp;
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
        case O::kOpcodeName_ficom:    return I::ficom;
        case O::kOpcodeName_ficomp:   return I::ficomp;
        default:                      return I::kCount;
    }
}

// ── Phase-0 run-break telemetry (ROSETTA_X87_LOG_RUN_BREAKS) ─────────────────
// One line per x87 run at translation time: run length, the guest opcode that
// ended it, the gap until the next x87 instruction (within 16), and the
// breaker's address. Drives the transparent-set choice for OPT-RB bridging.
//
// Operand-form suffix (drives the TRANSPARENT_INT inline-set choice): for the
// mov/movzx/movsx/movsxd/lea family, classify dst<-src as r/m/i with the dst
// width, e.g. "r32<-i", "r64<-m", "m<-r". Inline v1 handles only the
// register-destination, non-memory-source forms.
static const char* operand_form_kind(const IROperand& op) {
    switch (op.kind) {
        case IROperandKind::Register: return "r";
        case IROperandKind::MemRef:
        case IROperandKind::AbsMem:   return "m";
        // Immediates arrive in more than one immediate-like kind; the payload
        // sits at the same offset in all of them (verified against Rosetta's IR).
        default: return "i";
    }
}

static const char* operand_width(const IROperand& op) {
    if (op.kind != IROperandKind::Register) return "";
    switch (op.reg.size) {
        case IROperandSize::S8:  return "8";
        case IROperandSize::S16: return "16";
        case IROperandSize::S32: return "32";
        case IROperandSize::S64: return "64";
        default: return "?";
    }
}

// Writes "form=r32<-i " (or "" for non-mov-family / operand-less ops) into buf.
static void mov_family_form(const IRInstr* in, char* buf, int buf_len) {
    buf[0] = '\0';
    switch (in->opcode()) {
        case kOpcodeName_mov:
        case kOpcodeName_movzx:
        case kOpcodeName_movsx:
        case kOpcodeName_movsxd:
        case kOpcodeName_lea:
            break;
        default:
            return;
    }
    if (in->num_operands < 2) return;
    const auto& dst = in->operands[0];
    const auto& src = in->operands[1];
    snprintf(buf, static_cast<size_t>(buf_len), "form=%s%s<-%s(k%u) ",
             operand_form_kind(dst), operand_width(dst), operand_form_kind(src),
             static_cast<unsigned>(src.kind));
}

static void log_run_break(TranslationResult* translation_result, IRInstr* instr_array,
                          int64_t num_instrs, int64_t insn_idx, int run) {
    // Bridged runs contain non-x87 gap instructions inside [insn_idx, run):
    // log each one so the inline-set histogram covers in-run gaps, not just
    // run-ending breakers.
    for (int64_t g = insn_idx; g < insn_idx + run && g < num_instrs; g++) {
        const uint16_t gop = instr_array[g].opcode();
        if (X87Cache::is_handled(gop)) continue;
        char form[24];
        mov_family_form(&instr_array[g], form, sizeof(form));
        const char* gname =
            (gop < kOpcodeNames.size() && kOpcodeNames[gop]) ? kOpcodeNames[gop] : "?";
        CORE_LOG("X87 bridge-gap: op=%s(%u) %sat %lx", gname, gop, form,
                 static_cast<uintptr_t>(
                     translation_result->ir_module_data->text_vmaddr_range +
                     instr_array[g].pc));
    }

    const int64_t brk = insn_idx + run;
    if (brk >= num_instrs) {
        CORE_LOG("X87 run-break: len=%d block-end", run);
        return;
    }
    const uint16_t bop = instr_array[brk].opcode();
    int gap = 0;
    int64_t j = brk;
    while (j < num_instrs && gap < 16 && !X87Cache::is_handled(instr_array[j].opcode())) {
        j++;
        gap++;
    }
    const int resumes = (j < num_instrs && X87Cache::is_handled(instr_array[j].opcode())) ? 1 : 0;
    const char* name =
        (bop < kOpcodeNames.size() && kOpcodeNames[bop]) ? kOpcodeNames[bop] : "?";
    const uintptr_t address =
        translation_result->ir_module_data->text_vmaddr_range + instr_array[brk].pc;
    char form[24];
    mov_family_form(&instr_array[brk], form, sizeof(form));
    CORE_LOG("X87 run-break: len=%d breaker=%s(%u) %sgap=%d resumes=%d at %lx", run, name,
             bop, form, gap, resumes, address);
}

auto Translator::translate_instruction(TranslationResult* translation_result, IRBlock* block,
                                       IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx)
    -> std::optional<int64_t> {
    const auto cur_instr = &instr_array[insn_idx];
    const auto opcode = cur_instr->opcode();
    auto& cache = translation_result->x87_cache;

    // If extended FPR scratch is enabled, upgrade the mask from 8-reg to 16-reg form on first use.
    if (g_rosetta_config && g_rosetta_config->extended_fpr_scratch &&
        translation_result->free_fpr_mask == kFprScratchMask) {
        translation_result->free_fpr_mask = kFprScratchMaskExt;
    }

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
                const bool bridge = g_rosetta_config && g_rosetta_config->run_bridge;
                const bool keepalive = g_rosetta_config && g_rosetta_config->runtime_keepalive;
                const int run =
                    X87Cache::lookahead(instr_array, num_instrs, insn_idx, ops_mask, bridge,
                                        keepalive);
                if (g_rosetta_config && g_rosetta_config->log_run_breaks && run > 0)
                    log_run_break(translation_result, instr_array, num_instrs, insn_idx, run);
                cache.set_run(run);
            }
        }
        // OPT-RB/OPT-KA: after a bridged gap or keepalive transcendental,
        // Rosetta's own translation ran. If it reset the scratch mask,
        // re-exclude the pinned cache GPRs before anything here allocates
        // from it.
        if (g_rosetta_config &&
            (g_rosetta_config->run_bridge || g_rosetta_config->runtime_keepalive) &&
            cache.active())
            translation_result->free_gpr_mask &= ~cache.pinned_mask();
    }

    // ── IR pipeline: try whole-run optimization for runs of 2+ ─────────────
    // It builds an SSA-like IR, runs optimization passes (DSE, FMA, FCOM+FSTSW
    // fusion), and lowers directly to AArch64.
    {
        const bool ir_disabled = g_rosetta_config && g_rosetta_config->disable_x87_ir;
        // Minimum run length for the IR pipeline. Runs of exactly 2 also go
        // through the IR: benchmarks show pairs the peephole fusions don't
        // cover gain up to ~28% (e.g. fld+fistp), while fusion-covered pairs
        // regress ≤2% (the fusions still handle pairs the IR declines).
        constexpr int kX87IRMinRun = 2;
        // Deferred cache state (top_dirty, deferred push/pop tags, FXCH perm)
        // no longer blocks the IR: compile_run folds it into the build and the
        // lowering epilogue, so mid-run entry after a deferred FXCH or partial
        // per-instruction translation still gets IR lowering.
        if (!ir_disabled && cache.active() && cache.run_remaining >= kX87IRMinRun) {
            X87IR::CompileError error;
            const int ir_consumed =
                X87IR::compile_run(translation_result, instr_array, num_instrs, insn_idx,
                                   cache.run_remaining, &error);
            if (ir_consumed > 0) {
                for (int i = 0; i < ir_consumed; i++)
                    cache.tick();
                if (cache.active()) {
                    translation_result->free_gpr_mask = kGprScratchMask & ~cache.pinned_mask();
                } else {
                    translation_result->free_gpr_mask = kGprScratchMask;
                }
                translation_result->free_fpr_mask =
                    translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
                translation_result->_pinned_temporary_scalars = 0;
                return insn_idx + ir_consumed;
            } else if (g_rosetta_config && g_rosetta_config->log_ir_declines) {
                uintptr_t address = translation_result->ir_module_data->text_vmaddr_range + cur_instr->pc;
                CORE_LOG("X87IR::compile_run error=%d at %lx", static_cast<int>(error), address);
            }
        }
    }

    // OPT-BC: an x87 instruction is about to go through the peephole/singular
    // translators. Release any carried addr-cache/RC pins first: those paths
    // can change control_word (fldcw) or AX (fstsw) behind the carried state,
    // and they allocate several transient GPRs (emit_fcom_cc_pack peaks at 4)
    // — the carried pins would shrink the pool below what they were audited
    // against.
    if (cache.carried_any() && X87Cache::is_handled(opcode))
        cache.carried_release(translation_result->free_gpr_mask);

    // ── FILD/FISTP/FISTTP m64: decline to the runtime ───────────────────────
    // An f64 stack slot cannot hold a full 64-bit mantissa, so these must reach
    // x87_fild / x87_fist_i64 / x87_fistt_i64, which carry an exact int64
    // shadow.  Declined before try_peephole so a fusion cannot swallow the
    // encoding and re-introduce the lossy SCVTF path.
    if (x87_is_m64_int_memop(*cur_instr)) {
        cache.invalidate(translation_result->free_gpr_mask, kGprScratchMask);
        translation_result->free_fpr_mask =
            translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
        return std::nullopt;
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
                translation_result->free_fpr_mask =
                    translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
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

            case Opcode::kOpcodeName_fisttp:
                TranslatorX87::translate_fisttp(translation_result, cur_instr);
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

            case Opcode::kOpcodeName_ficom:
            case Opcode::kOpcodeName_ficomp:
                TranslatorX87::translate_ficom(translation_result, cur_instr);
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

            case Opcode::kOpcodeName_fldcw:
                TranslatorX87::translate_fldcw(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fnstcw:
                TranslatorX87::translate_fnstcw(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_fnop:
                TranslatorX87::translate_fnop(translation_result, cur_instr);
                break;

            case Opcode::kOpcodeName_arpl:
                TranslatorCustom::translate_arpl(translation_result, cur_instr);
                break;

            default:
                // OPT-KA (opt-in ROSETTA_X87_RUNTIME_KEEPALIVE): a keepalive
                // transcendental inside an active run. Rosetta translates it as
                // a runtime-routine BL whose round trip preserves every pinned
                // cache GPR (only x27/x29 are clobbered — IDA-verified, see
                // X87Cache::runtime_keepalive_top_delta). Flush deferred state
                // so the helper sees coherent X87State memory, pre-adjust the
                // cached TOP by the op's fixed stack delta, and keep the pins
                // excluded from the scratch pool. Carried pins are released
                // first: one could live in x27, and releasing frees the flush's
                // scratch slots (Rosetta's own translate_* for these ops is a
                // pure fixup+BL with zero scratch-GPR demand, decomp-verified).
                if (cache.active() && g_rosetta_config && g_rosetta_config->runtime_keepalive) {
                    if (auto top_delta = X87Cache::runtime_keepalive_top_delta(opcode)) {
                        if (cache.carried_any())
                            cache.carried_release(translation_result->free_gpr_mask);
                        TranslatorX87::runtime_keepalive_flush(translation_result, *top_delta);
                        cache.tick();
                        if (cache.active()) {
                            translation_result->free_gpr_mask =
                                kGprScratchMask & ~cache.pinned_mask();
                        } else {
                            translation_result->free_gpr_mask = kGprScratchMask;
                        }
                        translation_result->free_fpr_mask =
                            translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
                        return std::nullopt;
                    }
                }
                // OPT-RB (opt-in ROSETTA_X87_RUN_BRIDGE): a run-transparent
                // integer instruction inside an active run. Rosetta translates
                // it itself; we only tick the run counter and keep the pinned
                // cache GPRs excluded from the scratch pool so the cache
                // survives. lookahead guarantees a run never ENDS on a bridged
                // instruction, so pending deferred TOP/tag state is always
                // flushed by a later x87 instruction's x87_end / IR epilogue.
                std::optional<int> bridge_need;
                if (cache.active() && g_rosetta_config && g_rosetta_config->run_bridge)
                    bridge_need = X87Cache::gap_gpr_demand(cur_instr);
                if (bridge_need && *bridge_need <= X87Cache::kMaxBridgeDemand) {
                    // OPT-BC: the gap instruction may redefine a guest GPR a
                    // carried base was derived from. Freed bits return via
                    // the pinned_mask() recompute below.
                    if (cache.carried_any())
                        cache.carried_drop_written(
                            X87Cache::gap_written_gpr_mask(cur_instr));
                    // Rosetta translates this instruction from the reduced
                    // pool. If the pins leave too few free temps for its
                    // translation, release the carried pins — the 3 fixed cache
                    // GPRs alone leave 5 free, which covers every demand
                    // lookahead admits (≤ kMaxBridgeDemand = 4) with a spare.
                    // Release on have <= need (not <): keep ≥1 register of
                    // headroom above the estimate so an admitted demand-4 op
                    // never runs the pool to exactly zero.
                    {
                        const int need = *bridge_need;
                        // GPR-only popcount: __builtin_popcount lowers to NEON
                        // CNT, and this hook runs lazy translation on the
                        // guest thread with guest SIMD state live in the host
                        // vector registers — clobbering one corrupts it.
                        uint32_t v = kGprScratchMask & ~cache.pinned_mask();
                        int have = 0;
                        while (v) { v &= v - 1; have++; }
                        const bool release = have <= need && cache.carried_any();
                        if (release)
                            cache.carried_release(translation_result->free_gpr_mask);
                        if (g_rosetta_config->log_run_breaks)
                            CORE_LOG("X87 bridge-gap alloc: op=%u at %lx need=%d have=%d%s",
                                     opcode,
                                     static_cast<uintptr_t>(
                                         translation_result->ir_module_data
                                             ->text_vmaddr_range + cur_instr->pc),
                                     need, have, release ? " (carried released)" : "");
                    }
                    cache.tick();
                    if (cache.active()) {
                        translation_result->free_gpr_mask =
                            kGprScratchMask & ~cache.pinned_mask();
                    } else {
                        translation_result->free_gpr_mask = kGprScratchMask;
                    }
                    translation_result->free_fpr_mask =
                        translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
                    return std::nullopt;
                }
                // Hand translation back to rosetta, we don't support this instruction - invalidate
                // cache.
                cache.invalidate(translation_result->free_gpr_mask, kGprScratchMask);
                // restore fpr mask
                translation_result->free_fpr_mask =
                    translation_result->_unoccupied_temporary_fprs_for_xmm_scalars;
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
