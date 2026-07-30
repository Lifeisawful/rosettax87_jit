#include "rosetta_core/X87IR.h"

#include <cstring>
#include <utility>

#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/IROperand.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/TranslatorX87Helpers.hpp"
#include "rosetta_config/Config.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/RuntimeRoutine.h"
#include "rosetta_core/X87Cache.h"
#include "rosetta_core/CoreLog.h"

// Internal helpers from TranslatorX87Internal.hpp that we need.
namespace TranslatorX87 {
// The x87-state preamble registers. Any of them may be -1 when the run does
// not read them (see X87IR::StateNeeds); the emitters that take them are only
// reached from nodes that demanded them.
struct X87Regs {
    int base = -1;      // Xbase   — &X87State
    int top = -1;       // Wd_top  — current TOP (extracted from status_word)
    int st_base = -1;   // Xst_base — &X87State.st[0]
};

// Materialize only the requested subset of the preamble. `want_st_base`
// additionally requires the run cache to be live (the ST-base register is the
// cache's, and emit_load_st/emit_store_st fall back to Xbase+Wd_tmp without
// it). Returns already-pinned registers unchanged on mid-run entry.
inline X87Regs x87_begin_sel(TranslationResult& a1, AssemblerBuffer& buf, bool want_base,
                             bool want_top, bool want_st_base) {
    if (a1.x87_cache.run_remaining > 0 && a1.x87_cache.gprs_valid)
        return {a1.x87_cache.base_gpr, a1.x87_cache.top_gpr, a1.x87_cache.st_base_gpr};
    // Everything below is addressed through Xbase (emit_load_top may use it as
    // its LDRH base, and Xst_base is Xbase + kX87RegFileOff).
    if (want_top || want_st_base) want_base = true;
    X87Regs r;
    if (!want_base) return r;
    r.base = alloc_gpr(a1, 0);
    emit_x87_base(buf, a1, r.base);
    if (want_top) {
        r.top = alloc_gpr(a1, 1);
        emit_load_top(buf, a1, r.base, r.top);
    }
    if (want_st_base && a1.x87_cache.run_remaining > 0) {
        r.st_base = alloc_gpr(a1, 6);
        emit_add_imm(buf, 1, 0, 0, 0, kX87RegFileOff, r.base, r.st_base);
    }
    // Publish to the run cache only when all three are live — a later run in
    // the window reads all of them, so a partial set must not be advertised.
    if (a1.x87_cache.run_remaining > 0 && r.top >= 0 && r.st_base >= 0) {
        a1.x87_cache.base_gpr = static_cast<int8_t>(r.base);
        a1.x87_cache.top_gpr = static_cast<int8_t>(r.top);
        a1.x87_cache.st_base_gpr = static_cast<int8_t>(r.st_base);
        a1.x87_cache.gprs_valid = 1;
    }
    return r;
}
}  // namespace TranslatorX87

namespace X87IR {

static constexpr int16_t kX87TagWordImm12 = kX87TagWordOff / 2;      // = 2
static constexpr int16_t kX87StatusWordImm12 = kX87StatusWordOff / 2;  // = 1

// ── FPR assignment ──────────────────────────────────────────────────────────

struct FPRState {
    int8_t node_fpr[kMaxNodes];      // D register for each node, or -1
    int16_t last_use[kMaxNodes];     // last node index that uses each node, or -1
    int8_t prefer_fpr[kMaxNodes];    // OPT-TI plan: pin this node's value to
                                     // 16/17 (trig-call arg/result), or -1
    uint32_t pinned_mask = 0;        // regs handed out by the plan — never
                                     // pool-allocated, never pool-freed

    void compute_last_uses(const Context& ctx) {
        memset(last_use, -1, sizeof(last_use));
        memset(node_fpr, -1, sizeof(node_fpr));
        memset(prefer_fpr, -1, sizeof(prefer_fpr));
        pinned_mask = 0;
        for (int i = 0; i < ctx.num_nodes; i++) {
            auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0) last_use[n.inputs[j]] = static_cast<int16_t>(i);
            }
        }
        // Final stack values are live past all nodes.
        for (int d = 0; d < 8; d++) {
            int16_t val = ctx.slot_val[d];
            if (val >= 0 && val < ctx.num_nodes)
                last_use[val] = static_cast<int16_t>(ctx.num_nodes);
        }
    }

    // Free FPRs whose last use was node `i`.  Plan-pinned regs (v16/v17 in
    // trig runs) were never pool-allocated, so they are released by clearing
    // the node binding only.
    void free_dead_inputs(TranslationResult& result, const Node& n, int i) {
        for (int j = 0; j < 3; j++) {
            int16_t in = n.inputs[j];
            if (in >= 0 && last_use[in] == i && node_fpr[in] >= 0) {
                if (!(pinned_mask >> node_fpr[in] & 1u))
                    free_fpr(result, node_fpr[in]);
                node_fpr[in] = -1;
            }
        }
    }

    int get(int16_t node_id) const {
        if (node_id < 0 || node_id >= kMaxNodes) return -1;
        return node_fpr[node_id];
    }

    // Try to reuse an FPR from a dying input of node `i`.
    // Returns the FPR register number, or -1 if no reuse is possible.
    // On success, sets node_fpr[input] = -1 so free_dead_inputs skips it.
    // Caller MUST capture input FPRs via get() BEFORE calling this.
    // Plan-pinned regs are never reused: a value parked there would cross
    // the trig call that owns the register.
    int try_reuse_input(const Context& ctx, int i) {
        const auto& n = ctx.nodes[i];
        // Prefer inputs[0] (Dn, natural accumulator position)
        for (int pref = 0; pref < 3; pref++) {
            int16_t in = n.inputs[pref];
            if (in >= 0 && last_use[in] == i && node_fpr[in] >= 0 &&
                !(pinned_mask >> node_fpr[in] & 1u)) {
                int fpr = node_fpr[in];
                node_fpr[in] = -1;  // claimed — free_dead_inputs will skip
                return fpr;
            }
        }
        return -1;
    }

    // Allocate the output FPR for node `i`: the plan target if one was
    // pinned, else a dying input's register, else a fresh pool register.
    int alloc_output(const Context& ctx, TranslationResult& result, int i) {
        if (prefer_fpr[i] >= 0) return prefer_fpr[i];
        int Dd = try_reuse_input(ctx, i);
        if (Dd < 0) Dd = alloc_free_fpr(result);
        return Dd;
    }

    // ── OPT-TI: v16/v17 residency plan ──────────────────────────────────────
    // The trig/pow value calls take their argument in d16 (d17 for the
    // two-arg family's ST(1)) and return in d16 (d17 = fsincos cosine).  The
    // lowering already elides its FMOV bridges whenever Dn/Dd happen to BE
    // 16/17 — this pre-pass makes that happen by pinning suitable values to
    // those registers.  v16 (and v17 for sincos-family runs) are excluded
    // from the pool (compile_run), so every 16/17 binding comes from this
    // plan and the free paths above keep them out of the pool for good.
    //
    // Safety rules, per register:
    //  - a pinned live range may never contain a value-call node in its
    //    interior (the call clobbers the register);
    //  - ranges are claimed left-to-right against a watermark, so two plans
    //    never overlap;
    //  - a range may END at a call: the call's own d16/d17 argument moves
    //    read operand registers before writing them (input1's move is
    //    emitted before input0's, and only the two-arg family writes d17
    //    pre-BL), so equality cases are checked position-aware below.
    void plan_trig_targets(const Context& ctx, const int16_t* pair_with) {
        auto is_call = [](Op op) {
            return op == Op::FCosCall || op == Op::FSinCall ||
                   op == Op::FPtanCall || op == Op::FSinCosCall ||
                   op == Op::F2XM1Call || op == Op::FScaleCall ||
                   op == Op::FYl2xCall || op == Op::FYl2xp1Call ||
                   op == Op::FPatanCall;
        };
        auto is_two_arg = [](Op op) {
            return op == Op::FScaleCall || op == Op::FYl2xCall ||
                   op == Op::FYl2xp1Call || op == Op::FPatanCall;
        };

        int16_t calls[kMaxNodes];
        int ncalls = 0;
        bool v17_excluded = false;  // mirrors compile_run's has_sincos_call
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (is_call(n.op)) {
                calls[ncalls++] = static_cast<int16_t>(i);
                if (is_two_arg(n.op) || n.op == Op::FSinCosCall)
                    v17_excluded = true;
            }
        }
        if (ncalls == 0) return;

        // Producers whose output allocation honors prefer_fpr (everything
        // lowered through alloc_output; load-pair members are excluded —
        // their two-register shape has its own allocation path).
        auto producer_ok = [&](int16_t d) -> bool {
            if (d < 0 || pair_with[d] >= 0) return false;
            switch (ctx.nodes[d].op) {
            case Op::ReadSt:
            case Op::LoadF64: case Op::LoadF32Raw:
            case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
            case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
            case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
            case Op::FNMul:
            case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
            case Op::FNeg: case Op::FAbs: case Op::FSqrt: case Op::FRndInt:
            case Op::FCSel:
            case Op::CvtF32ToF64: case Op::CvtF64ToF32:
                return true;
            default:
                return false;
            }
        };

        int v16_free_from = 0;  // v16/v17 available from this node index on
        int v17_free_from = 0;
        for (int k = 0; k < ncalls; k++) {
            const int c = calls[k];
            const int prev = (k > 0) ? calls[k - 1] : -1;
            const int next = (k + 1 < ncalls) ? calls[k + 1] : kMaxNodes + 1;
            const auto& cn = ctx.nodes[c];

            // Argument in d16: pin the producer when the value is born after
            // the previous call, v16 is free, and it dies here.
            const int16_t in0 = cn.inputs[0];
            if (producer_ok(in0) && prefer_fpr[in0] < 0 &&
                last_use[in0] == c && in0 > prev &&
                in0 >= v16_free_from) {
                prefer_fpr[in0] = 16;
                pinned_mask |= 1u << 16;
            }

            // Result in d16: pin when no later call clobbers it first.
            // Dying exactly AT the next call is fine — its argument moves
            // read v16 before anything writes d16.
            int lu = last_use[c];
            if (lu < c) lu = c;  // side-effect-only call: dies immediately
            if (lu <= next) {
                prefer_fpr[c] = 16;
                pinned_mask |= 1u << 16;
                v16_free_from = lu;
            } else {
                v16_free_from = c + 1;  // result copied out; v16 dead after BL
            }

            if (!v17_excluded) continue;  // v17 belongs to the pool
            // ST(1) argument in d17 (two-arg family).
            if (is_two_arg(cn.op)) {
                const int16_t in1 = cn.inputs[1];
                if (producer_ok(in1) && prefer_fpr[in1] < 0 &&
                    last_use[in1] == c && in1 > prev &&
                    in1 >= v17_free_from && cn.inputs[0] != in1) {
                    prefer_fpr[in1] = 17;
                    pinned_mask |= 1u << 17;
                }
            }
            v17_free_from = c + 1;
            // fsincos cosine: pin the adjacent projection's output to d17.
            // A range ending exactly AT the next call is only safe when that
            // call reads it from d17 (its inputs[1]) or never writes d17
            // before the BL (the one-arg family).
            if (cn.op == Op::FSinCosCall) {
                int p = c + 1;
                while (p < ctx.num_nodes && (ctx.nodes[p].flags & kDead)) p++;
                if (p < ctx.num_nodes &&
                    ctx.nodes[p].op == Op::FSinCosProjCos &&
                    ctx.nodes[p].inputs[0] == c) {
                    int lup = last_use[p];
                    if (lup < p) lup = p;
                    const bool end_at_next_ok =
                        lup < next ||
                        (lup == next &&
                         (!is_two_arg(ctx.nodes[next].op) ||
                          ctx.nodes[next].inputs[1] == p));
                    if (end_at_next_ok) {
                        prefer_fpr[p] = 17;
                        pinned_mask |= 1u << 17;
                        v17_free_from = lup;
                    } else {
                        v17_free_from = p + 1;
                    }
                }
            }
        }
    }
};

// ── Guest-flags deadness after the run ──────────────────────────────────────
//
// Host NZCV holds the guest's materialized EFLAGS; each FCmp/FTst wraps its
// FCMP in an MRS/MSR pair (or one hoisted pair per group) to preserve them.
// If the first flag-relevant guest instruction after the run fully redefines
// EFLAGS, the pre-run flags are dead and the save/restore can be skipped
// entirely — the dominant pattern is `fcomp; fnstsw ax; test/and ...; jcc`.
//
// Whitelist walk: only instructions that neither read nor write EFLAGS may
// sit between the run and the redefinition. Anything unknown — including
// reaching block end, since the terminator may be a JCC and Rosetta itself
// treats flags as live across RET/CALL — keeps the conservative pair.
//
// Flag-liveness assist: for a PARTIAL or CONDITIONAL definer the walk can't
// prove deadness by redefinition, but Rosetta's backward flag-liveness
// dataflow can prove the flags that flow THROUGH it dead.
// IRInstr::flag_liveness holds the flags live OUT of that instruction
// (block-fixpoint with predecessor propagation, conservative all-live at
// unknown targets — the same byte TRANSPARENT_FLAGS already gates on), so
//     live-in  =  (flag_liveness & ~defined) | read
// and for an instruction that READS no flags, live-in ⊆ flag_liveness with
// the architecturally-always-defined bits masked off. Only the NZCV-mapped
// guest flags (SF/ZF/CF/OF) matter: eliding the pair leaves host NZCV
// unprotected across the FCMP and nothing else — wherever Rosetta keeps
// guest PF/AF/DF, an unsaved FCMP cannot touch it.
//
// Eligible opcodes (each defines-only, never reads EFLAGS; masks are OUR
// architectural sets, NOT the x86_opcode_flag_effects rows — those encode
// reader/cc semantics Rosetta resolves elsewhere and are not trustworthy
// as plain (used, defined) pairs outside the unconditional definers):
//   inc/dec   — define OF/SF/ZF/AF/PF, preserve CF     → check CF only
//   sahf      — defines SF/ZF/AF/PF/CF from AH, not OF → check OF only
//   shl/shr/sar by CL — flags untouched iff masked count is 0, else
//               defined; either way nothing is read    → check SF/ZF/CF/OF
//   rol/ror   — define at most CF/OF, count-dependent  → check SF/ZF/CF/OF
// The dataflow answers at the FIRST such instruction are final: a live bit
// there means a real reader downstream (modulo the analysis' conservatism),
// so returning its verdict directly loses nothing over walking on.
// ROSETTA_X87_DISABLE_NZCV_LIVENESS=1 drops the assist (bisection lever).

// Shift count when provably a compile-time constant: -1 for CL/memory/unknown
// forms, else the masked count. The 0x1F mask under-approximates the 0x3F
// mask of 64-bit shifts (counts 32–63 report 0 → treated as flag-preserving
// "unknown" by callers), which is the conservative direction.
static int shift_imm_count(const IRInstr* t) {
    if (t->num_operands < 2) return -1;
    const auto& c = t->operands[1];
    if (c.kind == IROperandKind::Register || c.kind == IROperandKind::MemRef ||
        c.kind == IROperandKind::AbsMem)
        return -1;
    return static_cast<int>(c.imm.value & 0x1F);
}

// Guest flags whose materialization lives in host NZCV.
static constexpr uint8_t kNzcvLiveMask = FLAG_SF | FLAG_ZF | FLAG_CF | FLAG_OF;

static bool nzcv_dead_after_run(IRInstr* instr_array, int64_t num_instrs, int64_t end_idx) {
    const bool use_liveness =
        !(g_rosetta_config && g_rosetta_config->disable_nzcv_liveness);
    for (int64_t i = end_idx; i < num_instrs; i++) {
        const uint8_t fl = instr_array[i].flag_liveness;
        const uint16_t op = instr_array[i].opcode();
        // x87 instructions (unconsumed ones end up in the tail: declined
        // forms, runtime-routine ops like fprem) never touch EFLAGS — walk
        // across them. The two exceptions live OUTSIDE this enum cluster:
        // the fcomi family fully redefines EFLAGS (ZF/PF/CF from the
        // compare, OF/SF/AF cleared) and the fcmov family READS cc flags
        // (stays at the conservative default below).
        static_assert(kOpcodeName_f2xm1 < kOpcodeName_fld &&
                          kOpcodeName_fld < kOpcodeName_fyl2xp1 &&
                          kOpcodeName_fcomi < kOpcodeName_f2xm1,
                      "x87 opcode cluster moved — revisit the range walk");
        if (op >= kOpcodeName_f2xm1 && op <= kOpcodeName_fyl2xp1) continue;
        if (op == kOpcodeName_fcomi || op == kOpcodeName_fcomip ||
            op == kOpcodeName_fucomi || op == kOpcodeName_fucomip)
            return true;
        switch (op) {
            // Full EFLAGS definers (write SF/ZF/CF/OF/PF; AF at worst
            // architecturally undefined): pre-run flags die here.
            case kOpcodeName_and:
            case kOpcodeName_or:
            case kOpcodeName_xor:
            case kOpcodeName_test:
            case kOpcodeName_cmp:
            case kOpcodeName_add:
            case kOpcodeName_sub:
            case kOpcodeName_neg:   // CF/OF/SF/ZF/PF all defined
            // MUL/IMUL define CF/OF; SF/ZF/PF are architecturally undefined,
            // so no correct guest reads them — dead either way.
            case kOpcodeName_mul:
            case kOpcodeName_imul:
                return true;
            // Immediate-count shifts: count != 0 defines CF/SF/ZF/PF (OF
            // undefined for count > 1 — within the standard above); count == 0
            // leaves EFLAGS untouched (flag-neutral). CL-count is unknown.
            case kOpcodeName_shl:
            case kOpcodeName_shr:
            case kOpcodeName_sar: {
                const int cnt = shift_imm_count(&instr_array[i]);
                if (cnt > 0) return true;
                if (cnt == 0) continue;
                // CL-count: conditional definer, reads no flags — the pre-run
                // flags are dead iff nothing NZCV-mapped is live out of it.
                return use_liveness && (fl & kNzcvLiveMask) == 0;
            }
            // Partial/conditional definers — deadness of the flags that flow
            // through them comes from the flag-liveness dataflow (header).
            case kOpcodeName_inc:
            case kOpcodeName_dec:
                // OF/SF/ZF/AF/PF defined here; only CF flows through.
                return use_liveness && (fl & FLAG_CF) == 0;
            case kOpcodeName_sahf:
                // SF/ZF/AF/PF/CF defined from AH; only OF flows through.
                return use_liveness && (fl & FLAG_OF) == 0;
            case kOpcodeName_rol:
            case kOpcodeName_ror:
                // Define at most CF/OF (count-dependent), read nothing
                // (unlike rcl/rcr, which read CF and stay conservative).
                return use_liveness && (fl & kNzcvLiveMask) == 0;
            // Flag-neutral instructions (neither read nor write EFLAGS).
            case kOpcodeName_mov:
            case kOpcodeName_movzx:
            case kOpcodeName_movsx:
            case kOpcodeName_movsxd:
            case kOpcodeName_lea:
            case kOpcodeName_push:
            case kOpcodeName_pushd:
            case kOpcodeName_pushw:
            case kOpcodeName_pop:
            case kOpcodeName_popd:
            case kOpcodeName_popw:
            case kOpcodeName_nop:
            case kOpcodeName_not:   // NOT writes no flags
            case kOpcodeName_xchg:
            case kOpcodeName_leave:
            case kOpcodeName_cbw:
            case kOpcodeName_cwde:
            case kOpcodeName_cdqe:
            case kOpcodeName_cwd:
            case kOpcodeName_cdq:
            // Flag-neutral SSE/SSE2 data movement and conversions (mixed
            // x87/SSE game code interleaves these with compare idioms).
            // (u)comiss/sd are NOT here — they write EFLAGS.
            case kOpcodeName_movss:
            case kOpcodeName_movsd:      // SSE movsd (0F 10/11), not movsd-string
            case kOpcodeName_movaps:
            case kOpcodeName_movapd:
            case kOpcodeName_movups:
            case kOpcodeName_movupd:
            case kOpcodeName_movlps:
            case kOpcodeName_movhps:
            case kOpcodeName_movdqa:
            case kOpcodeName_movdqu:
            case kOpcodeName_movd:
            case kOpcodeName_movq:
            case kOpcodeName_cvtsi2ss:
            case kOpcodeName_cvtsi2sd:
            case kOpcodeName_cvtss2sd:
            case kOpcodeName_cvtsd2ss:
            case kOpcodeName_cvttss2si:
            case kOpcodeName_cvttsd2si:
            // fwait checks unmodeled FP exceptions; Rosetta translates it to
            // nothing (same disposition as build_guest_int's consumption).
            case kOpcodeName_wait:
                continue;
            default:
                return false;  // reader / partial definer / unknown
        }
    }
    return false;  // block end reached without a full redefinition
}

// ── Base-address cache ──────────────────────────────────────────────────────
//
// Game-profile data shows runs dominated by f32/f64 memory traffic through a
// shared guest base register ([reg+disp] locals, vectors, matrices).  Instead
// of emitting ADD Waddr, Wbase, #disp + LDR [Xaddr] per access, materialize
// the base once per run and fold each displacement into the LDR/STR immediate.
//
// Correctness: guest GPRs cannot change within a run (only x87 instructions;
// the one exception, FSTSW AX, is handled by excluding RAX-based operands
// when an FStsw is present).  Semantics note for 32-bit addressing: folding
// computes zext32(base) + disp instead of zext32(base + disp) — divergence
// only on 32-bit pointer wraparound, impossible for valid pointers with
// |disp| ≤ 32 KB.

static bool addr_operand_base_cacheable(const IROperand* op) {
    return op->kind == IROperandKind::MemRef && op->mem.seg_override == 0 &&
           (op->mem.mem_flags & 1) != 0;  // has_base
}

// Same address computation modulo displacement.
static bool addr_base_key_equal(const IROperand* a, const IROperand* b) {
    return a->mem.addr_size == b->mem.addr_size &&
           a->mem.mem_flags == b->mem.mem_flags &&
           a->mem.base_reg == b->mem.base_reg &&
           a->mem.index_reg == b->mem.index_reg &&
           a->mem.shift_amount == b->mem.shift_amount;
}

static bool addr_disp_foldable(const IROperand* op, bool is_f64) {
    const int64_t disp = op->mem.disp;
    const int scale = is_f64 ? 8 : 4;
    if (disp >= 0 && disp % scale == 0 && disp / scale <= 4095) return true;
    return disp >= -256 && disp <= 255;  // LDUR/STUR imm9
}

static bool addr_uses_rax(const IROperand* op) {
    if ((op->mem.mem_flags & 1) && (op->mem.base_reg & 0xF) == 0) return true;
    if ((op->mem.mem_flags & 2) && (op->mem.index_reg & 0xF) == 0) return true;
    return false;
}

// True if the operand's base or index register is written by an inlined
// Guest* node anywhere in the run. Such operands cannot go through the
// base-address cache: the base is materialized in the preamble, before the
// guest write, but accesses after the write need the new address.
static bool addr_uses_written_reg(const IROperand* op, uint16_t written_mask) {
    if (!written_mask) return false;
    if ((op->mem.mem_flags & 1) &&
        ((written_mask >> (op->mem.base_reg & 0xF)) & 1))
        return true;
    if ((op->mem.mem_flags & 2) &&
        ((written_mask >> (op->mem.index_reg & 0xF)) & 1))
        return true;
    return false;
}

// Access width of a Guest load/store node's memory operand.
static int guest_mem_size_log2(const IROperand* m) {
    const IROperandSize s =
        m->kind == IROperandKind::AbsMem ? m->abs_mem.size : m->mem.size;
    switch (s) {
        case IROperandSize::S8: return 0;
        case IROperandSize::S16: return 1;
        case IROperandSize::S32: return 2;
        default: return 3;
    }
}

// ── LDP/STP pair planning ───────────────────────────────────────────────────
//
// Pair two f64/f32 accesses through the same guest base into one LDP/STP.
// Load pairs are emitted at the earlier node (the partner load is hoisted);
// store pairs at the later node (the earlier store is sunk), so both values
// exist at emission. The scan may cross a bounded number of intervening live
// nodes that cannot alias or reorder unsafely: pure value nodes always, plus
// other guest loads when the lead is a load (read-read reordering is safe).
// This catches the dominant game patterns where a widen/narrow FCVT or a
// multiply sits between the two halves of a vector access
// (fld a; fmul b; fld a+4; fmul b+4).
//
// pair_with[e] = partner node ID, stored at the emission node e;
// pair_skip[s] = true for the node whose own emission is suppressed.
// `reps`/`nreps`: the planned cached-base representatives — pairs only form
// through a cached base. peak_live_fprs passes reps == nullptr, which admits
// any base-cacheable operand: a superset of what lower() forms, keeping the
// pressure model conservative.

static constexpr int kPairMaxSkip = 4;

static bool pair_class(Op op, bool* is_load, int* scale) {
    switch (op) {
        case Op::LoadF64:     *is_load = true;  *scale = 8; return true;
        case Op::LoadF32Raw:  *is_load = true;  *scale = 4; return true;
        case Op::StoreF64:    *is_load = false; *scale = 8; return true;
        case Op::StoreF32Raw: *is_load = false; *scale = 4; return true;
        default: return false;
    }
}

static bool pair_node_skippable(Op op, bool lead_is_load) {
    switch (op) {
        // Pure value nodes — no guest-memory access.
        case Op::ReadSt:
        case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
        case Op::CvtF32ToF64: case Op::CvtF64ToF32:
        case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
        case Op::FNMul: case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
        case Op::FNeg: case Op::FAbs: case Op::FSqrt:
        case Op::FCSel:
            return true;
        // Guest loads: a load may be hoisted past them, a store may not be
        // sunk past them (the load could read the stored location).
        case Op::LoadF64: case Op::LoadF32Raw:
        case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
        case Op::GuestLoad:
            return lead_is_load;
        // Register-only inlined guest instructions never touch memory.
        // Pairs only form through cached-base operands, and plan_addr_cache
        // excludes every base/index register these nodes write — so a paired
        // access's address and value are unaffected by crossing one.
        // (GuestLoad above writes a register too — same argument — but reads
        // memory; GuestStoreR/GuestStoreI write memory and fall to default,
        // as does GuestRmwR which both reads and writes it.)
        case Op::GuestMovRR: case Op::GuestMovRI:
        case Op::GuestLea: case Op::GuestExt: case Op::GuestAluRI:
            return true;
        default:
            return false;
    }
}

// LDP/STP signed imm7 range, scaled.
static bool pair_disp_ok(int64_t disp, int scale) {
    return disp % scale == 0 && disp >= -64 * scale && disp <= 63 * scale;
}

static void compute_pairs(const Context& ctx, IROperand* const* reps, int nreps,
                          int16_t* pair_with, bool* pair_skip) {
    for (int i = 0; i < ctx.num_nodes; i++) {
        pair_with[i] = -1;
        pair_skip[i] = false;
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (pair_skip[i] || pair_with[i] >= 0) continue;
        bool is_load;
        int scale;
        if (!pair_class(n.op, &is_load, &scale)) continue;
        const IROperand* mo = n.mem_operand;
        if (!addr_operand_base_cacheable(mo)) continue;
        if (reps) {
            int k = 0;
            for (; k < nreps; k++)
                if (addr_base_key_equal(mo, reps[k])) break;
            if (k == nreps) continue;
        }
        const int64_t d1 = mo->mem.disp;
        if (!pair_disp_ok(d1, scale)) continue;

        int skipped = 0;
        for (int j = i + 1; j < ctx.num_nodes; j++) {
            const auto& m = ctx.nodes[j];
            if (m.flags & kDead) continue;
            if (m.op == n.op && !pair_skip[j] && pair_with[j] < 0 &&
                addr_operand_base_cacheable(m.mem_operand) &&
                addr_base_key_equal(mo, m.mem_operand)) {
                const int64_t d2 = m.mem_operand->mem.disp;
                if (pair_disp_ok(d2, scale) &&
                    (d2 == d1 + scale || d2 == d1 - scale)) {
                    if (is_load) {
                        pair_with[i] = static_cast<int16_t>(j);
                        pair_skip[j] = true;
                    } else {
                        pair_with[j] = static_cast<int16_t>(i);
                        pair_skip[i] = true;
                    }
                    break;
                }
                // Same-op access that isn't the partner: fall through to the
                // skippability check (loads may cross loads; stores stop).
            }
            if (!pair_node_skippable(m.op, is_load)) break;
            if (++skipped > kPairMaxSkip) break;
        }
    }
}

// Pick up to 2 base keys with ≥2 foldable f32/f64 accesses each; store the
// representative node IDs in ctx.addr_cache_rep.  Returns the planned count.
// The caller (compile_run) degrades the plan to fit the GPR pool — each
// cached base pins exactly one extra GPR for the whole run.
static int plan_addr_cache(Context& ctx) {
    bool has_fstsw = false;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op == Op::FStsw) has_fstsw = true;
        // Any segment-override memory operand in the run disables the cache:
        // the GS/TLS fallback path fixed-allocates pool slot 7 (x29) mid-run,
        // which would assert if a cached base happens to hold it (and the FS/GS
        // paths also allocate more transient GPRs than the pressure model
        // attributes to a Load/Store node).
        switch (n.op) {
            case Op::LoadF64: case Op::LoadF32Raw:
            case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
            case Op::StoreF64: case Op::StoreF32Raw:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::StoreCW: case Op::LoadCW:
                if (n.mem_operand->kind == IROperandKind::MemRef &&
                    n.mem_operand->mem.seg_override != 0)
                    return 0;
                break;
            default:
                break;
        }
    }

    struct { int16_t node; int count; } keys[6];
    int nkeys = 0;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        bool foldable;
        switch (n.op) {
            case Op::LoadF64: case Op::StoreF64:
                foldable = addr_disp_foldable(n.mem_operand, /*is_f64=*/true);
                break;
            case Op::LoadF32Raw: case Op::StoreF32Raw:
                foldable = addr_disp_foldable(n.mem_operand, /*is_f64=*/false);
                break;
            case Op::GuestLoad: case Op::GuestStoreR: case Op::GuestStoreI:
            case Op::GuestRmwR:
                // Width varies (8/16/32/64) — classify at the exact size so a
                // counted access is one the cached path can actually emit.
                foldable = n.mem_operand->kind == IROperandKind::MemRef &&
                           classify_ldst_disp(n.mem_operand->mem.disp,
                                              guest_mem_size_log2(n.mem_operand)) != 0;
                break;
            // Integer x87 nodes: classify at the access width.
            case Op::LoadI16: case Op::StoreI16:
            case Op::StoreCW: case Op::LoadCW:
                foldable = n.mem_operand->kind == IROperandKind::MemRef &&
                           classify_ldst_disp(n.mem_operand->mem.disp, 1) != 0;
                break;
            case Op::LoadI32: case Op::StoreI32:
                foldable = n.mem_operand->kind == IROperandKind::MemRef &&
                           classify_ldst_disp(n.mem_operand->mem.disp, 2) != 0;
                break;
            case Op::LoadI64: case Op::StoreI64:
                foldable = n.mem_operand->kind == IROperandKind::MemRef &&
                           classify_ldst_disp(n.mem_operand->mem.disp, 3) != 0;
                break;
            default: continue;
        }
        const IROperand* mo = n.mem_operand;
        if (!addr_operand_base_cacheable(mo)) continue;
        if (has_fstsw && addr_uses_rax(mo)) continue;
        if (addr_uses_written_reg(mo, ctx.guest_written_mask)) continue;
        if (!foldable) continue;
        int k = 0;
        for (; k < nkeys; k++) {
            if (addr_base_key_equal(ctx.nodes[keys[k].node].mem_operand, mo)) {
                keys[k].count++;
                break;
            }
        }
        if (k == nkeys && nkeys < 6) {
            keys[nkeys].node = static_cast<int16_t>(i);
            keys[nkeys].count = 1;
            nkeys++;
        }
    }

    int picked = 0;
    for (int round = 0; round < Context::kAddrCacheSlots; round++) {
        int best = -1;
        for (int k = 0; k < nkeys; k++) {
            if (keys[k].count >= 2 && (best < 0 || keys[k].count > keys[best].count))
                best = k;
        }
        if (best < 0) break;
        ctx.addr_cache_rep[picked++] = keys[best].node;
        keys[best].count = 0;
    }
    return picked;
}

// ── Guest* node emission (opt-in TRANSPARENT_INT) ───────────────────────────
//
// Flag-free encodings only: Guest nodes may sit between an FCmp/FComI and its
// NZCV consumer (hoisted saves, FCSel, the TestFused TST), so nothing here
// may write NZCV. They write guest GPRs (x0–x15) directly — disjoint from
// the scratch pool (x22–x29), so pinned cache GPRs and held values (packed
// CC, hoisted NZCV) are never clobbered.

static void emit_guest_node(TranslationResult& result, AssemblerBuffer& buf,
                            const Node& n) {
    const GuestPayload p = guest_unpack(n.imm_bits);
    switch (n.op) {
        case Op::GuestMovRR:
            emit_mov_reg(buf, p.is64 ? 1 : 0, p.dst, p.src);
            break;
        case Op::GuestMovRI:
            // 32-bit dst only (build declines r64,imm): W-write zero-extends.
            emit_load_immediate_no_xzr(result, 0, p.imm, p.dst);
            break;
        case Op::GuestExt: {
            // cls: 0=8lo, 1=8hi, 2=16, 3=32 (movsxd)
            const int lsb = (p.cls == 1) ? 8 : 0;
            const int width = (p.cls >= 2) ? ((p.cls == 3) ? 32 : 16) : 8;
            if (!p.sign) {
                // UBFX Wd — zeroes the upper 32 bits too, covering r64 dsts.
                emit_bitfield(buf, 0, /*UBFM*/2, 0, static_cast<int8_t>(lsb),
                              static_cast<int8_t>(lsb + width - 1), p.src, p.dst);
            } else {
                // SBFX to the dst width (SXTB/SXTH/SXTW forms).
                const int sf = p.is64 ? 1 : 0;
                emit_bitfield(buf, sf, /*SBFM*/0, sf, static_cast<int8_t>(lsb),
                              static_cast<int8_t>(lsb + width - 1), p.src, p.dst);
            }
            break;
        }
        // push/pop (TRANSPARENT_PUSHPOP): Rosetta-parity writeback forms on
        // guest RSP (x4). Build declined RSP as the data register, so the
        // Rt==Rn writeback hazard cannot occur.
        case Op::GuestPushR: {
            const int slot = p.is64 ? 8 : 4;
            emit_ldr_str_imm_ext(buf, p.is64 ? 3 : 2, /*pre=*/1, /*STR*/0,
                                 static_cast<int16_t>(-slot), /*Rn=RSP*/4, p.dst);
            break;
        }
        case Op::GuestPushI: {
            const int slot = p.is64 ? 8 : 4;
            const uint64_t v =
                p.is64 ? static_cast<uint64_t>(
                             static_cast<int64_t>(static_cast<int32_t>(p.imm)))
                       : p.imm;
            // XZR hint: imm 0 comes back as WZR/XZR — STR ZR stores zero.
            const int Rt = emit_load_immediate(result, p.is64 ? 1 : 0, v,
                                               GPR::XZR);
            emit_ldr_str_imm_ext(buf, p.is64 ? 3 : 2, /*pre=*/1, /*STR*/0,
                                 static_cast<int16_t>(-slot), /*Rn=RSP*/4, Rt);
            free_gpr(result, Rt);
            break;
        }
        case Op::GuestPop: {
            const int slot = p.is64 ? 8 : 4;
            emit_ldr_str_imm_ext(buf, p.is64 ? 3 : 2, /*post=*/0, /*LDR*/1,
                                 static_cast<int16_t>(slot), /*Rn=RSP*/4, p.dst);
            break;
        }
        case Op::GuestAluRI: {
            // Flag-free in-place ALU on a guest GPR (TRANSPARENT_FLAGS).
            // Build pre-validated: logical imms are bitmask-encodable, shift
            // counts are masked and nonzero, add/sub imms fit via
            // emit_add_disp (temp GPR on the hard path, as for lea).
            const int is64 = p.is64 ? 1 : 0;
            const int bits = is64 ? 64 : 32;
            switch (static_cast<GuestAlu>(n.aux)) {
                case GuestAlu::Add:
                    emit_add_disp(result, is64, p.dst, p.dst,
                                        static_cast<int32_t>(p.imm));
                    break;
                case GuestAlu::Sub:
                    emit_add_disp(result, is64, p.dst, p.dst,
                                        -static_cast<int64_t>(
                                            static_cast<int32_t>(p.imm)));
                    break;
                case GuestAlu::And:
                case GuestAlu::Or:
                case GuestAlu::Xor: {
                    // r64 forms sign-extend the imm32 (x86 semantics).
                    const uint64_t v =
                        is64 ? static_cast<uint64_t>(static_cast<int64_t>(
                                   static_cast<int32_t>(p.imm)))
                             : p.imm;
                    LogicalImmEncoding enc;
                    is_bitmask_immediate(is64 != 0, v, enc);
                    const auto a = static_cast<GuestAlu>(n.aux);
                    const int opc = (a == GuestAlu::And) ? 0
                                    : (a == GuestAlu::Or) ? 1
                                                          : 2;  // EOR
                    emit_logical_imm(buf, is64, opc, enc.N ? 1 : 0,
                                     static_cast<int8_t>(enc.immr),
                                     static_cast<int8_t>(enc.imms),
                                     p.dst, p.dst);
                    break;
                }
                case GuestAlu::Shl: {
                    // LSL #c == UBFM Rd, Rn, #(bits-c), #(bits-1-c)
                    const int c = static_cast<int>(p.imm);
                    emit_bitfield(buf, is64, /*UBFM*/2, is64,
                                  static_cast<int8_t>((bits - c) & (bits - 1)),
                                  static_cast<int8_t>(bits - 1 - c),
                                  p.dst, p.dst);
                    break;
                }
                case GuestAlu::Shr:
                case GuestAlu::Sar: {
                    // LSR/ASR #c == UBFM/SBFM Rd, Rn, #c, #(bits-1)
                    const int c = static_cast<int>(p.imm);
                    const int opc =
                        (static_cast<GuestAlu>(n.aux) == GuestAlu::Shr) ? 2 : 0;
                    emit_bitfield(buf, is64, opc, is64, static_cast<int8_t>(c),
                                  static_cast<int8_t>(bits - 1), p.dst, p.dst);
                    break;
                }
                case GuestAlu::Neg:
                    // NEG Rd == SUB Rd, ZR, Rd
                    emit_add_sub_shifted_reg(buf, is64, /*is_sub=*/1, 0,
                                             /*LSL*/0, p.dst, 0, GPR::XZR,
                                             p.dst);
                    break;
                case GuestAlu::Not:
                    // MVN Rd == ORN Rd, ZR, Rd
                    emit_logical_shifted_reg(buf, is64, /*ORR*/1, /*n=*/1,
                                             /*LSL*/0, p.dst, 0, GPR::XZR,
                                             p.dst);
                    break;
            }
            break;
        }
        case Op::GuestLea: {
            // Compute in W unless both dst and address size are 64-bit:
            // W-writes zero-extend (lea r64 with addr32) and W arithmetic
            // truncates mod 2^32 (lea r32 with addr64) — both match x86.
            const int is64 = (p.is64 && !p.addr32) ? 1 : 0;
            const int64_t disp = static_cast<int32_t>(p.imm);
            if (p.has_base && p.has_index) {
                emit_add_sub_shifted_reg(buf, is64, 0, 0, /*LSL*/0, p.idx,
                                         static_cast<int8_t>(p.cls), p.src, p.dst);
                emit_add_disp(result, is64, p.dst, p.dst, disp);
            } else if (p.has_base) {
                emit_add_disp(result, is64, p.dst, p.src, disp);
            } else if (p.has_index) {
                // ADD dst, ZR, idx, LSL #s  (reg 31 = ZR in shifted-reg forms)
                emit_add_sub_shifted_reg(buf, is64, 0, 0, /*LSL*/0, p.idx,
                                         static_cast<int8_t>(p.cls), GPR::XZR, p.dst);
                emit_add_disp(result, is64, p.dst, p.dst, disp);
            } else {
                emit_load_immediate_no_xzr(result, is64, static_cast<uint64_t>(disp),
                                           p.dst);
            }
            break;
        }
        default:
            break;
    }
}

// ── OPT-BC: carried-entry key match ─────────────────────────────────────────
// Same identity as addr_base_key_equal, against a CarriedBase snapshot.
static bool carried_key_match(const X87Cache::CarriedBase& c, const IROperand* op) {
    return c.addr_size == static_cast<uint8_t>(op->mem.addr_size) &&
           c.mem_flags == op->mem.mem_flags &&
           c.base_reg == op->mem.base_reg &&
           c.index_reg == op->mem.index_reg &&
           c.shift_amount == op->mem.shift_amount;
}

// ── x87-state preamble demand ───────────────────────────────────────────────
//
// The preamble (ADD Xbase / LDRH+UBFX TOP / ADD Xst_base / Wd_tmp) used to be
// emitted unconditionally, but a run only reads those registers when it
// touches the x87 register file, the status/tag/control words, or leaves the
// stack unbalanced.  The dominant shape in real code — a balanced run ending
// in `fstp m32/m64`, with no compare and no residue — reads none of them, and
// paid 4 dead instructions per run (in `fld m64; fstp m64` loops that was 4 of
// 8 instructions).  This walk decides what to materialize.
//
// Deliberately conservative: over-claiming a register only restores the old
// behavior, while under-claiming would hand a -1 to an emitter.  It mirrors
// the GENERIC body (top_known < 0), which is a superset of the TOP=0
// specialized one, so it stays valid when both bodies are emitted.

struct StateNeeds {
    bool base = false;      // Xbase
    bool top = false;       // Wd_top
    bool st_base = false;   // Xst_base (implies base + top via the ST paths)
    bool tmp = false;       // Wd_tmp
};

static StateNeeds compute_state_needs(const Context& ctx, bool entry_top_dirty,
                                      int entry_push_count, int entry_pop_count,
                                      bool top0_specialize) {
    StateNeeds nd;
    const bool fast_round = g_rosetta_config && g_rosetta_config->fast_round;

    // ── Node loop ───────────────────────────────────────────────────────────
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        switch (n.op) {
            case Op::ReadSt:
                // Generic path: emit_load_st(Xbase, Wd_top, Wd_tmp, Xst_base).
                nd.base = nd.top = nd.st_base = nd.tmp = true;
                break;
            // status_word RMW / AX write.
            case Op::FCmp: case Op::FTst:
                // The CC store merges TOP in from Wd_top.
                nd.base = nd.top = true;
                break;
            case Op::FStsw:
                // TOP is merged into the stored halfword and patched into
                // the returned word; both read Wd_top unless it is a
                // translate-time constant, which only the specialized body has.
                nd.base = nd.top = true;
                break;
            // control_word traffic.
            case Op::StoreCW: case Op::LoadCW:
                nd.base = true;
                break;
            case Op::FRndInt:
                if (!fast_round) nd.base = true;  // RC read from control_word
                break;
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
                if (!(n.flags & kTruncate)) {
                    // RC dispatch: emit_rc_preamble / emit_rcmode_dispatch.
                    nd.base = true;
                    nd.tmp = true;
                }
                break;
            // Value calls clear C1 (|C2) in status_word; F2XM1 touches none.
            case Op::FCosCall: case Op::FSinCall: case Op::FPtanCall:
            case Op::FSinCosCall: case Op::FScaleCall:
            case Op::FYl2xCall: case Op::FYl2xp1Call: case Op::FPatanCall:
                nd.base = true;
                break;
            default:
                break;
        }
    }

    // ── Epilogue ────────────────────────────────────────────────────────────
    // Step 1/3: TOP register update and its status_word writeback.
    if (ctx.top_delta != 0 || entry_top_dirty) {
        nd.base = nd.top = nd.tmp = true;  // emit_store_top(Xbase, Wd_top, Wd_tmp)
    }
    // Step 2: stack-slot writeback (same skip rules as lower()'s epilogue; a
    // dead value is what makes fprs.get() return -1 there).
    for (int d = 0; d < 8; d++) {
        const int16_t val = ctx.slot_val[d];
        if (val < 0 || val >= ctx.num_nodes) continue;
        const auto& vn = ctx.nodes[val];
        if (vn.flags & kDead) continue;
        if (vn.op == Op::ReadSt && vn.initial_depth == d + ctx.top_delta) continue;
        nd.base = nd.top = nd.st_base = nd.tmp = true;
        break;
    }
    // Step 4: tag-word batches (generic form indexes by Wd_top via Wd_tmp).
    {
        const int set_valid = (entry_push_count - ctx.top_delta > 0)
                                  ? entry_push_count - ctx.top_delta : 0;
        const int set_empty = (ctx.top_delta + entry_pop_count - entry_push_count > 0)
                                  ? ctx.top_delta + entry_pop_count - entry_push_count : 0;
        if (set_valid > 0 || set_empty > 0) nd.base = nd.top = nd.tmp = true;
    }
    // The TOP=0 guard branches on Wd_top.
    if (top0_specialize) nd.base = nd.top = true;

    if (nd.st_base || nd.top) nd.base = true;
    return nd;
}

// ── Main lowering ───────────────────────────────────────────────────────────

void lower(Context& ctx, TranslationResult* result) {
    auto& buf = result->insn_buf;

    // Carried-in deferred cache state (mid-run entry). The epilogue folds
    // these into its TOP/tag writeback; step 6 then clears the flags.
    const bool entry_top_dirty = result->x87_cache.top_dirty != 0;
    const int entry_push_count = result->x87_cache.deferred_push_count;
    const int entry_pop_count = result->x87_cache.deferred_pop_count;

    // ── TOP=0 specialization gate ───────────────────────────────────────────
    // In real code TOP is almost always 0 at run entry (balanced stack
    // discipline). When enough stack-slot traffic would become static, the
    // run is emitted twice behind a CBNZ guard: a specialized body where
    // every ST(i) physical index, tag mask and TOP value is a translate-time
    // constant (wrap included), and the generic body as fallback.
    int top0_benefit = 0;
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        // ReadSt at depth > 0: ADD+AND+LDR → LDR imm.
        if (n.op == Op::ReadSt && n.initial_depth > 0) top0_benefit += 2;
    }
    for (int d = 1; d < 8; d++) {
        // Epilogue store at depth > 0: ADD+AND+STR → STR imm.
        int16_t val = ctx.slot_val[d];
        if (val < 0 || val >= ctx.num_nodes) continue;
        if (ctx.nodes[val].op == Op::ReadSt &&
            ctx.nodes[val].initial_depth == d + ctx.top_delta)
            continue;  // epilogue skips this store anyway
        top0_benefit += 2;
    }
    // TOP update becomes MOVZ, tag batch masks become constants.
    if (ctx.top_delta != 0) top0_benefit += 3;
    // A compare's status_word store merges the TOP field. With TOP known at
    // translate time that operand is a constant; otherwise it comes from the
    // preamble's LDRH of status_word — the very halfword the store writes —
    // putting a full memory round-trip on the loop-carried dependency chain
    // (STRH -> LDRH -> UBFX -> ORR -> STRH). Specializing breaks it, and the
    // guard branch is a control dependency the predictor hides. Measured ~46%
    // on the fcom/ftst family, so any compare alone justifies the second body.
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op == Op::FCmp || n.op == Op::FTst) { top0_benefit += 4; break; }
    }
    const bool top0_specialize = top0_benefit >= 4;

    // ── Preamble: acquire only the x87-state registers this run reads ───────
    // Emitted here (not at function entry) because the demand walk needs
    // top0_specialize; nothing above emits instructions, so the preamble still
    // precedes the whole body.
    //
    // When the run cache outlives this run, materialize everything regardless:
    // the following run reads all three through the cache, and paying for them
    // once here is strictly cheaper than a partial set that forces the next run
    // to redo the lot.
    StateNeeds nd = compute_state_needs(ctx, entry_top_dirty, entry_push_count,
                                        entry_pop_count, top0_specialize);
    if (result->x87_cache.run_remaining > ctx.consumed)
        nd.base = nd.top = nd.st_base = nd.tmp = true;

    const auto x87r =
        TranslatorX87::x87_begin_sel(*result, buf, nd.base, nd.top, nd.st_base);
    const int Xbase = x87r.base;
    const int Wd_top = x87r.top;
    const int Xst_base = x87r.st_base;
    const int Wd_tmp = nd.tmp ? alloc_gpr(*result, 2) : -1;

    // ── Base-address cache: materialize planned guest bases ────────────────
    // OPT-BC: a planned base whose key matches a carried entry reuses the
    // carried GPR (already pinned, value still valid) instead of
    // re-materializing.
    auto& xc = result->x87_cache;
    const bool carry_on = g_rosetta_config && g_rosetta_config->bridge_carry;
    const int addr_n = ctx.addr_cache_n;
    IROperand* addr_rep[Context::kAddrCacheSlots] = {};
    int addr_reg[Context::kAddrCacheSlots] = {-1, -1, -1};
    bool addr_owned[Context::kAddrCacheSlots] = {};
    for (int k = 0; k < addr_n; k++) {
        addr_rep[k] = ctx.nodes[ctx.addr_cache_rep[k]].mem_operand;
        if (carry_on) {
            int hit = -1;
            for (int s = 0; s < X87Cache::kMaxCarried; s++) {
                if (xc.carried_base[s].gpr >= 0 &&
                    carried_key_match(xc.carried_base[s], addr_rep[k])) {
                    hit = s;
                    break;
                }
            }
            if (hit >= 0) {
                addr_reg[k] = xc.carried_base[hit].gpr;
                addr_owned[k] = false;  // pinned by the cache, not allocated here
                continue;
            }
        }
        IROperand base_op = *addr_rep[k];
        base_op.mem.disp = 0;
        addr_reg[k] = compute_operand_address(*result, true, &base_op, GPR::XZR);
        // The 64-bit no-disp path returns the guest register itself (nothing
        // allocated); only scratch-pool registers are ours to free.
        addr_owned[k] = ((kGprScratchMask >> addr_reg[k]) & 1u) != 0;
    }

    // Emit a Load*/Store* access through a cached base + immediate offset.
    // Returns false if the operand matches no cached base (or the disp fits
    // neither form) — caller falls back to compute_operand_address.
    auto emit_cached_access = [&](const Node& n, int size, int is_load, int Vt) -> bool {
        for (int k = 0; k < addr_n; k++) {
            if (!addr_base_key_equal(n.mem_operand, addr_rep[k])) continue;
            if (try_emit_fp_ldst_disp(buf, size, is_load, Vt, addr_reg[k],
                                      n.mem_operand->mem.disp))
                return true;
        }
        return false;
    };

    // GPR counterpart for Guest load/store nodes. The kind guard matters:
    // an AbsMem operand's bytes must not be compared as MemRef fields.
    auto emit_cached_gpr_access = [&](const Node& n, int size_log2, int is_load,
                                      int Rt) -> bool {
        if (n.mem_operand->kind != IROperandKind::MemRef) return false;
        for (int k = 0; k < addr_n; k++) {
            if (!addr_base_key_equal(n.mem_operand, addr_rep[k])) continue;
            const int64_t disp = n.mem_operand->mem.disp;
            const int cls = classify_ldst_disp(disp, size_log2);
            if (cls == 1) {
                emit_ldr_str_imm(buf, size_log2, /*is_fp=*/0, /*opc=*/is_load,
                                 static_cast<int16_t>(disp >> size_log2),
                                 addr_reg[k], Rt);
                return true;
            }
            if (cls == 2) {
                emit_ldur_stur(buf, size_log2, is_load,
                               static_cast<int16_t>(disp), addr_reg[k], Rt);
                return true;
            }
        }
        return false;
    };

    // ── LDP/STP pairing ─────────────────────────────────────────────────────
    // Precomputed plan (see compute_pairs): pair_with[e] holds the partner at
    // the emission node, pair_skip[s] suppresses the partner's own emission.
    // With addr_n == 0 no operand matches a rep, so no pairs form.
    int16_t pair_with[kMaxNodes];
    bool pair_skip[kMaxNodes];
    compute_pairs(ctx, addr_rep, addr_n, pair_with, pair_skip);

    // Emit one LDP/STP for nodes a (whose FPR is Va) and b (Vb) — same op,
    // same cached base, displacements one element apart.
    auto emit_pair_access = [&](const Node& a, const Node& b, int size,
                                int is_load, int Va, int Vb) {
        int k = 0;
        for (; k < addr_n; k++)
            if (addr_base_key_equal(a.mem_operand, addr_rep[k])) break;
        const int64_t d1 = a.mem_operand->mem.disp;
        const int64_t d2 = b.mem_operand->mem.disp;
        const int64_t lo = d1 < d2 ? d1 : d2;
        const int Vt1 = d1 < d2 ? Va : Vb;
        const int Vt2 = d1 < d2 ? Vb : Va;
        if (size == 3)
            emit_fldp_fstp_d(buf, is_load, static_cast<int16_t>(lo / 8),
                             addr_reg[k], Vt1, Vt2);
        else
            emit_fldp_fstp_s(buf, is_load, static_cast<int16_t>(lo / 4),
                             addr_reg[k], Vt1, Vt2);
    };

    // ── RC caching: hoist LDRH+UBFX when ≥2 RC consumers in a segment ────
    // OPT-BC: a carried RC GPR is reused regardless of this run's consumer
    // count — its value is already valid (only FLDCW changes control_word,
    // and StoreCW re-caches into the same register).
    int Wd_rc_cached = -1;
    bool rc_entry_valid = false;

    if (!(g_rosetta_config && g_rosetta_config->fast_round)) {
        if (carry_on && xc.carried_rc_gpr >= 0) {
            Wd_rc_cached = xc.carried_rc_gpr;
            rc_entry_valid = true;
        } else {
            int rc_count = 0;
            bool use_rc_cache = false;
            for (int i = 0; i < ctx.num_nodes; i++) {
                auto& n = ctx.nodes[i];
                if (n.flags & kDead) continue;
                if (n.op == Op::StoreCW) { continue; }
                bool is_rc = (n.op == Op::FRndInt) ||
                    ((n.op == Op::StoreI16 || n.op == Op::StoreI32 || n.op == Op::StoreI64)
                     && !(n.flags & kTruncate));
                if (is_rc && ++rc_count >= 2) { use_rc_cache = true; break; }
            }
            if (use_rc_cache)
                // alloc_free_gpr, NOT alloc_gpr(pool 3): the addr cache may
                // already hold x25 (any scratch), and fixed-slot allocation
                // asserts on collision. The RC dispatch works from any register.
                Wd_rc_cached = alloc_free_gpr(*result);
        }
    }

    // ── NZCV hoisting / elision around FCmp/FTst ────────────────────────────
    // Hoisting: instead of saving/restoring guest NZCV per compare, save once
    // before the first compare and restore once after the last.  Safe only
    // when no node legitimately writes/reads NZCV in between (FComI writes it
    // for the guest; FCSel reads it) — nothing else emitted by this pipeline
    // touches flags.
    // Elision (nzcv_skip): when compile_run proved the guest flags dead after
    // the run (ctx.nzcv_dead), drop the MRS/MSR pair entirely.
    int nzcv_first_cmp = -1, nzcv_last_cmp = -1;
    bool nzcv_hoist = false;
    bool nzcv_skip = false;
    // OPT-TS: per-node "this value call's status-word clear is dead" (see below).
    bool sw_clear_dead[kMaxNodes] = {};
    {
        int cmp_count = 0;
        bool has_nzcv_user = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::FComI || n.op == Op::FCSel) { has_nzcv_user = true; break; }
            if (n.op == Op::FCmp || n.op == Op::FTst) {
                if (nzcv_first_cmp < 0) nzcv_first_cmp = i;
                nzcv_last_cmp = i;
                cmp_count++;
            }
        }
        nzcv_skip = ctx.nzcv_dead && !has_nzcv_user && cmp_count >= 1;
        nzcv_hoist = !nzcv_skip && !has_nzcv_user && cmp_count >= 2;
    }

    // ── FSTSW / epilogue status_word merge ──────────────────────────────────
    // `fcomp; fnstsw ax` — the dominant compare idiom — wrote status_word
    // twice: once in the FSTSW (CC bits, stale TOP field) and again in
    // epilogue step 3 (LDRH/BFI/STRH to patch TOP), the LDRH reloading the
    // halfword just stored. When the FSTSW's TOP snapshot already equals the
    // run's final top_delta — true whenever nothing pushes or pops after it,
    // which is the shape of the idiom — the FSTSW can fold the FINAL TOP in
    // and store once, and step 3 drops out entirely.
    //
    // Requires the FSTSW to be the last status_word writer in the run: a later
    // FCmp/FTst (CC RMW), FStsw, or trig/pow value call (C1|C2 clear) would
    // overwrite the halfword after we finalized it.
    // Walks backward: anything reached before the last FStsw sits AFTER it in
    // program order, so a status_word writer there disqualifies the sink. The
    // FCmp/FTst fused into this FStsw is earlier, and is never seen.
    auto writes_status_word = [](Op op) {
        switch (op) {
            case Op::FCmp: case Op::FTst: case Op::FStsw:
            case Op::FCosCall: case Op::FSinCall: case Op::FPtanCall:
            case Op::FSinCosCall: case Op::FScaleCall:
            case Op::FYl2xCall: case Op::FYl2xp1Call: case Op::FPatanCall:
                return true;   // F2XM1Call touches no status bits
            default:
                return false;
        }
    };

    // ── OPT-TS: dead intermediate C1|C2 clears ──────────────────────────────
    // Each trig/pow value call clears C1 (|C2) with an LDRH/AND/STRH RMW at its
    // program position. That RMW is unobservable — and so can be dropped
    // outright — when a later node in the same run overwrites the whole
    // halfword before anything reads it back. Runs are straight-line, so a
    // later node is reached unconditionally; this is a pure dead-store
    // elimination, not a fidelity trade (unlike the FSTSW sink below, nothing
    // architecturally visible changes).
    //
    // Classification of what can follow, all verified against the emitters:
    //   FCmp/FTst, not fused   emit_fcom_cc_store_sw — STRH only, never reads   -> KILLS
    //   FCmp/FTst, fused       defers its store to the paired FStsw             -> transparent
    //   FStsw, fused           stores packed CC from a GPR, never reads         -> KILLS
    //   FStsw, not fused       LDRH — reads the halfword back                   -> OBSERVES
    //   another value call     LDRH/AND/STRH; kills only if its mask is a
    //                          superset (C1|C2 covers C1-only, not vice versa)
    //   epilogue TOP writeback LDRH/BFI/STRH — preserves C0-C3                  -> neither
    // Reaching the end of the run without a killer means the clear must stay:
    // anything at all can read status_word after the run ends.
    auto sw_clear_mask = [](Op op) -> uint16_t {
        switch (op) {
            case Op::FCosCall: case Op::FSinCall: case Op::FPtanCall:
            case Op::FSinCosCall:
                return 0x0600;   // C1 | C2
            case Op::FScaleCall: case Op::FYl2xCall:
            case Op::FYl2xp1Call: case Op::FPatanCall:
                return 0x0200;   // C1
            default:
                return 0;        // F2XM1Call and everything else
        }
    };
    const bool sw_clear_sink_on =
        !(g_rosetta_config && g_rosetta_config->disable_trig_sw_sink);
    for (int i = 0; sw_clear_sink_on && i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        const uint16_t mask = sw_clear_mask(n.op);
        if (mask == 0) continue;
        for (int j = i + 1; j < ctx.num_nodes; j++) {
            const auto& later = ctx.nodes[j];
            if (later.flags & kDead) continue;
            if (later.op == Op::FCmp || later.op == Op::FTst) {
                if (later.flags & kFcomFused) continue;  // stores at its FStsw
                sw_clear_dead[i] = true;
                break;
            }
            if (later.op == Op::FStsw) {
                if (later.flags & kFcomFused) sw_clear_dead[i] = true;
                break;  // non-fused reads it back — observed, keep the clear
            }
            const uint16_t later_mask = sw_clear_mask(later.op);
            if (later_mask == 0) continue;
            if ((later_mask & mask) == mask) {
                sw_clear_dead[i] = true;
                break;
            }
            break;  // clears less than we do (C1-only after C1|C2) — keep
        }
    }

    int sw_sink_node = -1;
    if (ctx.top_delta != 0 || entry_top_dirty) {
        for (int i = ctx.num_nodes - 1; i >= 0; i--) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (!writes_status_word(n.op)) continue;
            if (sw_clear_dead[i]) continue;  // its RMW is gone — not a writer
            if (n.op == Op::FStsw &&
                static_cast<int16_t>(n.aux >> 16) == ctx.top_delta)
                sw_sink_node = i;
            break;  // first writer found from the end decides
        }
    }

    // ── Run body (node loop + x87-state epilogue) ───────────────────────────
    // Emitted once normally, or twice when TOP=0 specialization is active:
    // top_known = 0 makes every stack-slot physical index / tag mask / TOP
    // value a translate-time constant; top_known = -1 is the generic body.
    auto emit_body = [&](int top_known) {
    FPRState fprs;
    fprs.compute_last_uses(ctx);
    // Store pairs: the earlier (sunk) store's value must stay live until the
    // STP at the emission node.
    for (int e = 0; e < ctx.num_nodes; e++) {
        if (pair_with[e] < 0) continue;
        const auto& en = ctx.nodes[e];
        if (en.op != Op::StoreF64 && en.op != Op::StoreF32Raw) continue;
        int16_t in_s = ctx.nodes[pair_with[e]].inputs[0];
        if (in_s >= 0 && fprs.last_use[in_s] < e)
            fprs.last_use[in_s] = static_cast<int16_t>(e);
    }
    // OPT-TI: pin trig-call arguments/results to v16/v17 so the d16/d17
    // FMOV bridges vanish.  Runs on the FINAL last_use values (the pair
    // extension above), so pinned live ranges cover sunk stores too.
    fprs.plan_trig_targets(ctx, pair_with);
    bool rc_cache_valid = rc_entry_valid;  // OPT-BC: carried RC is pre-loaded
    int Wd_nzcv_saved = -1;
    const int final_top_known =
        (top_known >= 0) ? ((top_known + ctx.top_delta) & 7) : -1;

    // ── Emit each IR node ───────────────────────────────────────────────────
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (pair_skip[i]) {
            // Access emitted (or to be emitted) as half of an LDP/STP; only
            // the FPR lifetime bookkeeping remains. A sunk store's input has
            // its last_use extended to the emission node, so it survives.
            fprs.free_dead_inputs(*result, n, i);
            continue;
        }

        switch (n.op) {

        // ── Value nodes ─────────────────────────────────────────────────
        case Op::ReadSt: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            if (top_known >= 0) {
                // Static physical slot: LDR Dd, [Xbase, #st_off].
                const int phys = (top_known + n.initial_depth) & 7;
                emit_fldr_imm(buf, 3, Dd, Xbase,
                              static_cast<int16_t>((kX87RegFileOff >> 3) + phys));
            } else {
                emit_load_st(buf, Xbase, Wd_top, n.initial_depth, Wd_tmp, Dd, Xst_base);
            }
            break;
        }
        case Op::LoadF64:
        case Op::LoadF32Raw: {
            const int size = (n.op == Op::LoadF64) ? 3 : 2;
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            const int j = pair_with[i];
            if (j >= 0) {
                // Load pair: hoist the partner load into one LDP.
                int Dd2 = alloc_free_fpr(*result);
                fprs.node_fpr[j] = static_cast<int8_t>(Dd2);
                emit_pair_access(n, ctx.nodes[j], size, /*is_load=*/1, Dd, Dd2);
                break;
            }
            if (!emit_cached_access(n, size, /*is_load=*/1, Dd)) {
                // Not through a cached base — still fold the displacement into
                // the addressing mode rather than materializing the full EA
                // (emit_fp_mem_access, same helper LoadI64 already uses).
                emit_fp_mem_access(*result, /*is_64bit=*/1, n.mem_operand, size,
                                   /*is_load=*/1, Dd);
            }
            break;
        }
        case Op::LoadI16: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int Wd_val = alloc_free_gpr(*result);
            if (emit_cached_gpr_access(n, /*size_log2=*/1, /*is_load=*/1, Wd_val)) {
                // LDRH through the cached base, then SXTH
                emit_bitfield(buf, 0, 0 /*SBFM*/, 0, 0, 15, Wd_val, Wd_val);
            } else {
                const OperandAccess acc =
                    compute_operand_access(*result, /*is_64bit=*/1, n.mem_operand,
                                           /*size_log2=*/1);
                if (acc.enc == OperandAccess::Enc::Unscaled9) {
                    // LDURH + SXTH (no sign-extending LDUR form in the emitter)
                    emit_ldur_stur(buf, /*size=*/1, /*is_load=*/1,
                                   (int16_t)acc.offset, acc.base, Wd_val);
                    emit_bitfield(buf, 0, 0 /*SBFM*/, 0, 0, 15, Wd_val, Wd_val);
                } else {
                    // LDRSH Wd_val, [base, #disp] — sign-extending load
                    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=LDRSH→W*/3,
                                     (int16_t)(acc.offset >> 1), acc.base, Wd_val);
                }
                free_gpr(*result, acc.base);
            }
            // SCVTF Dd, Wd_val
            emit_scvtf(buf, /*is_64_int=*/0, /*ftype=f64*/1, Dd, Wd_val);
            free_gpr(*result, Wd_val);
            break;
        }
        case Op::LoadI32: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int Wd_val = alloc_free_gpr(*result);
            if (!emit_cached_gpr_access(n, /*size_log2=*/2, /*is_load=*/1, Wd_val))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand,
                                    /*size_log2=*/2, /*is_load=*/1, Wd_val);
            // SCVTF W-form treats the 32-bit source as signed
            emit_scvtf(buf, /*is_64_int=*/0, /*ftype=f64*/1, Dd, Wd_val);
            free_gpr(*result, Wd_val);
            break;
        }
        case Op::LoadI64: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            // Load the int64 straight into the D register and convert in
            // place — no value GPR, no cross-domain GPR→FPR move.
            if (!emit_cached_access(n, /*size=*/3, /*is_load=*/1, Dd)) {
                emit_fp_mem_access(*result, /*is_64bit=*/1, n.mem_operand,
                                   /*size=*/3, /*is_load=*/1, Dd);
            }
            emit_scvtf_d_from_d(buf, Dd, Dd);
            break;
        }
        case Op::ConstZero: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_movi_d_zero(buf, Dd);
            break;
        }
        case Op::ConstOne: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fmov_d_one(buf, Dd);
            break;
        }
        case Op::ConstF64: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            uint8_t imm8;
            if (f64_fmov_imm8(n.imm_bits, &imm8))
                emit_fmov_d_imm8(buf, Dd, imm8);
            else
                emit_ldr_literal_f64(buf, Dd, n.imm_bits);
            break;
        }

        // ── Binary arithmetic ───────────────────────────────────────────
        // kF32 nodes compute in S registers (type=0): inputs and result are
        // raw f32 (see pass_f32_narrow).
        case Op::FAdd:
        case Op::FSub:
        case Op::FMul:
        case Op::FNMul:
        case Op::FDiv: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int opc;
            switch (n.op) {
                case Op::FMul:  opc = 0; break;
                case Op::FDiv:  opc = 1; break;
                case Op::FAdd:  opc = 2; break;
                case Op::FSub:  opc = 3; break;
                default:        opc = 8; break;  // FNMul
            }
            emit_fp_dp2(buf, /*type=*/(n.flags & kF32) ? 0 : 1, opc, Dd, Dn, Dm);
            break;
        }

        // ── FMA ─────────────────────────────────────────────────────────
        // FMAdd:  Da + Dn * Dm    FMSub: Da - Dn * Dm    FNMSub: Dn * Dm - Da
        // inputs[0] = Dn, inputs[1] = Dm, inputs[2] = Da.
        // kF32 nodes (opt-in f32 chains) use the S-form encoding.
        case Op::FMAdd:
        case Op::FMSub:
        case Op::FNMSub: {
            int Dn = fprs.get(n.inputs[0]), Dm = fprs.get(n.inputs[1]);
            int Da = fprs.get(n.inputs[2]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            const int o1 = (n.op == Op::FNMSub) ? 1 : 0;
            const int o0 = (n.op == Op::FMAdd) ? 0 : 1;
            emit_fp_dp3(buf, /*type=*/(n.flags & kF32) ? 0 : 1, o1, o0,
                        Dd, Dn, Dm, Da);
            break;
        }

        // ── Unary ───────────────────────────────────────────────────────
        // kF32: S-form, same as binary arithmetic above.
        case Op::FNeg:
        case Op::FAbs:
        case Op::FSqrt: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            const int opc = (n.op == Op::FAbs) ? 1 : (n.op == Op::FNeg) ? 2 : 3;
            emit_fp_dp1(buf, /*type=*/(n.flags & kF32) ? 0 : 1, opc, Dd, Dn);
            break;
        }
        case Op::FRndInt: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);

            if (g_rosetta_config && g_rosetta_config->fast_round) {
                // Fast path: RC=0 → FRINTN
                emit_fp_dp1(buf, /*type=*/1, /*FRINTN=*/8, Dd, Dn);
            } else if (Wd_rc_cached >= 0) {
                // RC caching: emit preamble on first use, then reuse cached RC.
                if (!rc_cache_valid) {
                    emit_rc_preamble(buf, Xbase, Wd_rc_cached);
                    rc_cache_valid = true;
                }
                emit_x87_rc_dispatch_frint(buf, Wd_rc_cached, Dd, Dn);
            } else {
                // alloc_free_gpr, NOT alloc_gpr(pool 3) — see RC cache above.
                int Wd_rc = alloc_free_gpr(*result);
                emit_rc_preamble(buf, Xbase, Wd_rc);
                emit_x87_rc_dispatch_frint(buf, Wd_rc, Dd, Dn);
                free_gpr(*result, Wd_rc);
            }
            break;
        }

        // ── OPT-TI: trig / pow-trio value calls ─────────────────────────
        case Op::FCosCall:
        case Op::FSinCall:
        case Op::FPtanCall:
        case Op::FSinCosCall:
        case Op::F2XM1Call:
        case Op::FScaleCall:
        case Op::FYl2xCall:
        case Op::FYl2xp1Call:
        case Op::FPatanCall: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            // v16 is excluded from the pool for runs containing these nodes
            // (compile_run); plan_trig_targets pins suitable arguments and
            // results there (and to v17 for the two-arg family / fsincos
            // projection), so the moves below vanish whenever the plan hits.
            if (n.op == Op::FScaleCall || n.op == Op::FYl2xCall ||
                n.op == Op::FYl2xp1Call || n.op == Op::FPatanCall) {
                int Dm = fprs.get(n.inputs[1]);
                if (Dm != 17)
                    emit_fp_dp1(buf, /*type=*/1, /*FMOV=*/0, /*Dd=*/17, Dm);
            }
            if (Dn != 16)
                emit_fp_dp1(buf, /*type=*/1, /*FMOV=*/0, /*Dd=*/16, Dn);
            Fixup fixup;
            fixup.kind = FixupKind::Branch26;
            fixup.insn_offset = static_cast<uint32_t>(buf.end);
            fixup.target = (n.op == Op::FCosCall)       ? kRuntimeRoutine_fcos
                           : (n.op == Op::FSinCall)     ? kRuntimeRoutine_fsin
                           : (n.op == Op::FPtanCall)    ? kRuntimeRoutine_fptan
                           : (n.op == Op::F2XM1Call)    ? kRuntimeRoutine_f2xm1
                           : (n.op == Op::FScaleCall)   ? kRuntimeRoutine_fscale
                           : (n.op == Op::FYl2xCall)    ? kRuntimeRoutine_fyl2x
                           : (n.op == Op::FYl2xp1Call)  ? kRuntimeRoutine_fyl2xp1
                           : (n.op == Op::FPatanCall)   ? kRuntimeRoutine_fpatan
                                                        : kRuntimeRoutine_fsincos;
            result->_fixups.push_back(fixup);       // routed to _stub_*_val
            buf.emit(0x94000000u);
            if (Dd != 16)
                emit_fp_dp1(buf, /*type=*/1, /*FMOV=*/0, Dd, /*Dn=*/16);
            // Status-word effect at the node's program position, so a later
            // FStsw in the same run observes it and an earlier FCmp/FTst's
            // bits are legitimately overwritten (hardware order).  Trig
            // clears C1|C2 (~0x600: immr=21, imms=29); FScale/FYl2x/FYl2xp1
            // clear C1 (~0x200: immr=22, imms=30); F2XM1 clears nothing
            // (classic helper parity).
            if (n.op != Op::F2XM1Call && !sw_clear_dead[i]) {
                const bool c1_only = (n.op == Op::FScaleCall || n.op == Op::FYl2xCall ||
                                      n.op == Op::FYl2xp1Call || n.op == Op::FPatanCall);
                const int immr = c1_only ? 22 : 21;
                const int imms = c1_only ? 30 : 29;
                int Wd = alloc_free_gpr(*result);
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=LDR*/1,
                                 kX87StatusWordImm12, Xbase, Wd);
                emit_and_imm(buf, /*is_64bit=*/0, Wd, /*N=*/0, immr, imms, Wd);
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*opc=STR*/0,
                                 kX87StatusWordImm12, Xbase, Wd);
                free_gpr(*result, Wd);
            }
            break;
        }

        // ── OPT-TI Phase C: the cosine (d17) output of the immediately-
        // preceding FSinCosCall.  Nothing executes between that BL and this
        // FMOV (build() emits the pair adjacently and dead nodes emit
        // nothing); v17 is excluded from the pool for runs containing the
        // call, so no pool value can be resident in it.
        case Op::FSinCosProjCos: {
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            if (Dd != 17)  // pinned by the plan: the value already IS d17
                emit_fp_dp1(buf, /*type=*/1, /*FMOV=*/0, Dd, /*Dn=*/17);
            break;
        }

        // ── Conditional select (FCMOV) ────────────────────────────────
        case Op::FCSel: {
            int Dn = fprs.get(n.inputs[0]);   // ST(0) — false arm
            int Dm = fprs.get(n.inputs[1]);   // ST(i) — true arm
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            int cond = static_cast<int>(n.imm_bits & 0xF);
            // FCSEL Dd, Dn_true, Dm_false, cond → Dd = cond ? Dn : Dm
            emit_fcsel_f64(buf, Dd, Dm, Dn, cond);
            break;
        }

        // ── f32 ↔ f64 conversion ────────────────────────────────────────
        case Op::CvtF32ToF64: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fcvt_s_to_d(buf, Dd, Dn);
            break;
        }
        case Op::CvtF64ToF32: {
            int Dn = fprs.get(n.inputs[0]);
            int Dd = fprs.alloc_output(ctx, *result, i);
            fprs.node_fpr[i] = static_cast<int8_t>(Dd);
            emit_fcvt_d_to_s(buf, Dd, Dn);
            break;
        }

        // ── Memory stores ───────────────────────────────────────────────
        case Op::StoreF64:
        case Op::StoreF32Raw: {
            const int size = (n.op == Op::StoreF64) ? 3 : 2;
            int Dd_val = fprs.get(n.inputs[0]);
            const int s = pair_with[i];
            if (s >= 0) {
                // Store pair: the earlier store (s) was sunk here; both
                // values are computed by now.
                const int16_t in_s = ctx.nodes[s].inputs[0];
                int Dd_val2 = fprs.get(in_s);
                emit_pair_access(n, ctx.nodes[s], size, /*is_load=*/0,
                                 Dd_val, Dd_val2);
                // Free the partner's value if this STP is its (extended)
                // last use — free_dead_inputs only covers this node's input.
                if (in_s != n.inputs[0] && fprs.last_use[in_s] == i &&
                    fprs.node_fpr[in_s] >= 0) {
                    if (!(fprs.pinned_mask >> fprs.node_fpr[in_s] & 1u))
                        free_fpr(*result, fprs.node_fpr[in_s]);
                    fprs.node_fpr[in_s] = -1;
                }
                break;
            }
            if (!emit_cached_access(n, size, /*is_load=*/0, Dd_val)) {
                // See LoadF64/LoadF32Raw: fold the disp instead of building
                // the effective address in a scratch GPR.
                emit_fp_mem_access(*result, /*is_64bit=*/1, n.mem_operand, size,
                                   /*is_load=*/0, Dd_val);
            }
            break;
        }

        // ── Integer stores (FISTP/FIST/FISTTP) ──────────────────────────
        case Op::StoreI16:
        case Op::StoreI32:
        case Op::StoreI64: {
            int Dd_val = fprs.get(n.inputs[0]);
            int Wd_int = alloc_free_gpr(*result);
            int is_64bit_int = (n.op == Op::StoreI64) ? 1 : 0;
            int store_size = (n.op == Op::StoreI16) ? 1
                           : (n.op == Op::StoreI32) ? 2
                                                    : 3;

            if (n.flags & kTruncate) {
                // FISTTP: always truncate, single FCVTZS.
                emit_fcvt_fp_to_int(buf, is_64bit_int, /*ftype=double*/ 1,
                                    /*rmode=FCVTZS*/ 3, Wd_int, Dd_val);
            } else if (Wd_rc_cached >= 0) {
                // RC caching: emit preamble on first use, then reuse cached RC.
                if (!rc_cache_valid) {
                    emit_rc_preamble(buf, Xbase, Wd_rc_cached);
                    rc_cache_valid = true;
                }
                emit_x87_rc_dispatch_fcvt(buf, Wd_rc_cached, Wd_int, Dd_val,
                                           is_64bit_int);
            } else {
                // FISTP/FIST: respect rounding mode from control_word.
                emit_rcmode_dispatch(buf, Wd_int, Dd_val, is_64bit_int, Xbase, Wd_tmp);
            }

            if (!emit_cached_gpr_access(n, store_size, /*is_load=*/0, Wd_int))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand,
                                    store_size, /*is_load=*/0, Wd_int);
            free_gpr(*result, Wd_int);
            break;
        }

        // ── Compare ─────────────────────────────────────────────────────
        case Op::FCmp: {
            int Wd_packed;
            if (nzcv_skip || nzcv_hoist) {
                if (nzcv_hoist && Wd_nzcv_saved < 0) {
                    Wd_nzcv_saved = alloc_free_gpr(*result);
                    emit_mrs_nzcv(buf, Wd_nzcv_saved);
                }
                emit_fcmp_f64(buf, fprs.get(n.inputs[0]), fprs.get(n.inputs[1]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack_hoisted(buf, *result, Wd_packed);
                if (nzcv_hoist && i == nzcv_last_cmp) {
                    emit_msr_nzcv(buf, Wd_nzcv_saved);
                    free_gpr(*result, Wd_nzcv_saved);
                    Wd_nzcv_saved = -1;
                }
            } else {
                int Wd_save = alloc_free_gpr(*result);
                emit_mrs_nzcv(buf, Wd_save);
                emit_fcmp_f64(buf, fprs.get(n.inputs[0]), fprs.get(n.inputs[1]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack(buf, *result, Wd_packed, Wd_save);
                // emit_fcom_cc_pack restores NZCV and frees Wd_save internally.
            }

            if (n.flags & kFcomFused) {
                // Fused: keep packed CC alive for FStsw to consume.
                // Store the GPR number in node_fpr[] (repurposed for GPR tracking).
                fprs.node_fpr[i] = static_cast<int8_t>(Wd_packed);
            } else {
                // Non-fused: write CC to status_word now, with no LDRH. TOP
                // is the value memory holds at this point — a constant in the
                // specialized body, which is what keeps the store off the
                // loop-carried chain.
                emit_fcom_cc_store_sw(buf, Xbase, Wd_packed,
                                      (top_known == 0) ? GPR::XZR : Wd_top);
                free_gpr(*result, Wd_packed);
            }
            break;
        }
        case Op::FTst: {
            int Wd_packed;
            if (nzcv_skip || nzcv_hoist) {
                if (nzcv_hoist && Wd_nzcv_saved < 0) {
                    Wd_nzcv_saved = alloc_free_gpr(*result);
                    emit_mrs_nzcv(buf, Wd_nzcv_saved);
                }
                emit_fcmp_zero_f64(buf, fprs.get(n.inputs[0]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack_hoisted(buf, *result, Wd_packed);
                if (nzcv_hoist && i == nzcv_last_cmp) {
                    emit_msr_nzcv(buf, Wd_nzcv_saved);
                    free_gpr(*result, Wd_nzcv_saved);
                    Wd_nzcv_saved = -1;
                }
            } else {
                int Wd_save = alloc_free_gpr(*result);
                emit_mrs_nzcv(buf, Wd_save);
                emit_fcmp_zero_f64(buf, fprs.get(n.inputs[0]));

                Wd_packed = alloc_free_gpr(*result);
                emit_fcom_cc_pack(buf, *result, Wd_packed, Wd_save);
            }

            if (n.flags & kFcomFused) {
                fprs.node_fpr[i] = static_cast<int8_t>(Wd_packed);
            } else {
                emit_fcom_cc_store_sw(buf, Xbase, Wd_packed,
                                      (top_known == 0) ? GPR::XZR : Wd_top);
                free_gpr(*result, Wd_packed);
            }
            break;
        }

        // ── FCOMI / FCOMIP / FUCOMI / FUCOMIP ───────────────────────────
        case Op::FComI: {
            // Direct port of translate_fcomi: FCMP two FPRs, then pack and
            // write x86-compatible flags into NZCV. Does NOT touch status_word.
            int Dd_st0 = fprs.get(n.inputs[0]);
            int Dd_src = fprs.get(n.inputs[1]);

            emit_fcmp_f64(buf, Dd_st0, Dd_src);

            // Extract condition bits before any MSR clobbers NZCV.
            int Wd_z = alloc_free_gpr(*result);
            int Wd_v = alloc_free_gpr(*result);
            int Wd_c = alloc_free_gpr(*result);

            emit_cset(buf, /*is_64bit=*/0, /*EQ=*/0, Wd_z);   // 1 if equal
            emit_cset(buf, /*is_64bit=*/0, /*VS=*/6, Wd_v);   // 1 if unordered
            emit_cset(buf, /*is_64bit=*/0, /*CS=*/2, Wd_c);   // 1 if carry set

            // Z_new = Z | V  (equal or unordered → ZF)
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 0, Wd_z, Wd_z);
            // C_new = C & !V  (carry clear for unordered → CF)
            emit_logical_shifted_reg(buf, 0, /*AND*/0, /*N=invert rhs*/1, /*LSL*/0, Wd_v, 0, Wd_c, Wd_c);

            // Pack NZCV: bit30=ZF, bit29=CF, bit28=V(PF for FCMOV), bit26=PF
            emit_bitfield(buf, /*is_64=*/0, /*UBFM=*/2, /*N=*/0,
                          /*immr=*/2, /*imms=*/1, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_c, 29, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 28, Wd_z, Wd_z);
            emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, /*LSL*/0, Wd_v, 26, Wd_z, Wd_z);

            emit_msr_nzcv(buf, Wd_z);

            free_gpr(*result, Wd_c);
            free_gpr(*result, Wd_v);
            free_gpr(*result, Wd_z);
            // Pop (for FCOMIP/FUCOMIP) is handled by the IR epilogue via top_delta.
            break;
        }

        // ── Control word ────────────────────────────────────────────────
        case Op::StoreCW: {
            // FLDCW: load u16 from memory, write to X87State.control_word.
            int Wd_cw = alloc_free_gpr(*result);
            if (!emit_cached_gpr_access(n, /*size_log2=*/1, /*is_load=*/1, Wd_cw))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand,
                                    /*size_log2=*/1, /*is_load=*/1, Wd_cw);
            // STRH Wd_cw, [Xbase, #0]  — control_word is at offset 0x00 → imm12=0
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0, /*imm12=*/0, Xbase, Wd_cw);
            // Re-cache RC from the just-written control word.
            if (Wd_rc_cached >= 0) {
                // UBFX Wd_rc_cached, Wd_cw, #10, #2
                emit_bitfield(buf, 0, 2, 0, 10, 11, Wd_cw, Wd_rc_cached);
                rc_cache_valid = true;
            } else {
                rc_cache_valid = false;
            }
            free_gpr(*result, Wd_cw);
            break;
        }
        case Op::LoadCW: {
            // FNSTCW: read X87State.control_word, store u16 to memory.
            int Wd_cw = alloc_free_gpr(*result);
            // LDRH Wd_cw, [Xbase, #0]  — control_word is at offset 0x00 → imm12=0
            emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1, /*imm12=*/0, Xbase, Wd_cw);
            if (!emit_cached_gpr_access(n, /*size_log2=*/1, /*is_load=*/0, Wd_cw))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand,
                                    /*size_log2=*/1, /*is_load=*/0, Wd_cw);
            free_gpr(*result, Wd_cw);
            break;
        }

        // ── Inlined guest integer instructions ─────────────────────────
        case Op::GuestMovRR:
        case Op::GuestMovRI:
        case Op::GuestLea:
        case Op::GuestExt:
        case Op::GuestAluRI:
        case Op::GuestPushR:
        case Op::GuestPushI:
        case Op::GuestPop:
            emit_guest_node(*result, buf, n);
            break;

        // ── Guest memory RMW (TRANSPARENT_FLAGS): {add,sub,and,or,xor} [m],r ─
        case Op::GuestRmwR: {
            const int Rs = static_cast<int>(n.aux & 0xF);
            const auto alu = static_cast<GuestAlu>((n.aux >> 4) & 0x7);
            const int sz = guest_mem_size_log2(n.mem_operand);  // 2 or 3
            const int is64 = (sz == 3) ? 1 : 0;
            int Wt = alloc_free_gpr(*result);
            if (!emit_cached_gpr_access(n, sz, /*is_load=*/1, Wt))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand, sz,
                                    /*is_load=*/1, Wt);
            switch (alu) {
                case GuestAlu::Add:
                case GuestAlu::Sub:
                    emit_add_sub_shifted_reg(buf, is64,
                                             alu == GuestAlu::Sub ? 1 : 0, 0,
                                             /*LSL*/0, Rs, 0, Wt, Wt);
                    break;
                default:
                    // AND=0 / ORR=1 / EOR=2 share the logical encoding.
                    emit_logical_shifted_reg(
                        buf, is64,
                        alu == GuestAlu::And ? 0 : alu == GuestAlu::Or ? 1 : 2,
                        0, /*LSL*/0, Rs, 0, Wt, Wt);
                    break;
            }
            if (!emit_cached_gpr_access(n, sz, /*is_load=*/0, Wt))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand, sz,
                                    /*is_load=*/0, Wt);
            free_gpr(*result, Wt);
            break;
        }

        // ── Inlined guest memory movs (Phase 3) ────────────────────────
        case Op::GuestLoad: {
            const int Rt = static_cast<int>(n.aux & 0xF);
            const bool sign = (n.aux >> 4) & 1;
            const int sz = guest_mem_size_log2(n.mem_operand);
            // LDR W/B/H zero-extends into the full register — exactly the
            // x86 mov r32 / movzx write. Rt as base (mov eax,[eax+8]) is
            // fine: the base is read before the destination is written.
            if (!emit_cached_gpr_access(n, sz, /*is_load=*/1, Rt))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand, sz,
                                    /*is_load=*/1, Rt);
            if (sign) {
                // movsx m8/m16 → r32: SXTB/SXTH the loaded value in place
                // (W-form keeps the upper 32 bits zero, matching x86).
                emit_bitfield(buf, /*is_64=*/0, /*SBFM*/0, /*N=*/0, /*immr=*/0,
                              /*imms=*/static_cast<int8_t>(sz == 0 ? 7 : 15),
                              Rt, Rt);
            }
            break;
        }
        case Op::GuestStoreR: {
            const int Rt = static_cast<int>(n.aux & 0xF);
            const int sz = guest_mem_size_log2(n.mem_operand);
            if (!emit_cached_gpr_access(n, sz, /*is_load=*/0, Rt))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand, sz,
                                    /*is_load=*/0, Rt);
            break;
        }
        case Op::GuestStoreI: {
            const int sz = guest_mem_size_log2(n.mem_operand);
            // XZR return for imm==0 encodes as STR WZR — stores zero.
            const int Rt = emit_load_immediate(*result, /*is_64bit=*/0,
                                               static_cast<uint32_t>(n.aux),
                                               GPR::XZR);
            if (!emit_cached_gpr_access(n, sz, /*is_load=*/0, Rt))
                emit_gpr_mem_access(*result, /*is_64bit=*/1, n.mem_operand, sz,
                                    /*is_load=*/0, Rt);
            free_gpr(*result, Rt);
            break;
        }

        // ── FSTSW AX ───────────────────────────────────────────────────
        case Op::FStsw: {
            static constexpr int16_t kSwImm12 = kX87StatusWordOff / 2;  // = 1
            const int16_t td = static_cast<int16_t>(n.aux >> 16);  // top_delta snapshot
            const int W_ax = static_cast<int>(n.aux & 0xF);  // dest reg (usually W0)

            // Absorb the epilogue's TOP writeback into this FSTSW's own
            // status_word store (see sw_sink_node): the halfword is written
            // once, with the final TOP already folded in.
            const bool sink = (i == sw_sink_node);

            // TOP as of this FSTSW: a translate-time constant in the
            // specialized body (no register needed — merges fold to
            // ORR-immediates below), else computed from Wd_top where a
            // register consumer needs it. Computed values are NOT masked
            // mod 8: every consumer merges via a 3-bit BFI (or the BFI
            // inside emit_fcom_cc_store_sw), which masks for free.
            const int topval_const =
                (top_known >= 0) ? ((top_known + td) & 7) : -1;

            // ORR-immediate of (top << 11) into a register whose TOP field
            // is known-zero. Every top in 1..7 except 5 (0x2800, two
            // separated runs) encodes as a logical immediate; the fallback
            // materializes and BFIs.
            auto emit_top_orr_imm = [&](int top, int Wd) {
                LogicalImmEncoding enc;
                if (is_bitmask_immediate(false,
                                         static_cast<uint64_t>(top) << 11,
                                         enc)) {
                    emit_logical_imm(buf, 0, /*ORR*/1, enc.N ? 1 : 0,
                                     static_cast<int8_t>(enc.immr),
                                     static_cast<int8_t>(enc.imms), Wd, Wd);
                } else {
                    const int Wd_t = alloc_free_gpr(*result);
                    emit_movn(buf, 0, /*MOVZ*/2, 0,
                              static_cast<uint16_t>(top), Wd_t);
                    emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21,
                                  /*imms=*/2, Wd_t, Wd);
                    free_gpr(*result, Wd_t);
                }
            };

            if (n.flags & kFcomFused) {
                // Fused: the CC bits are still in the register the FCmp left
                // them in, so status_word is never read back.
                const int16_t fcmp_id = n.inputs[0];
                const int Wd_sw = fprs.get(fcmp_id);  // packed CC, sw positions
                fprs.node_fpr[fcmp_id] = -1;

                // MEMORY gets the TOP the run leaves behind, which is NOT
                // this FSTSW's snapshot: with the snapshot stored and the
                // epilogue's writeback suppressed (top_delta == 0), a
                // mid-run pop would be baked into status_word permanently.
                // Sinking means snapshot == final, so it is stored directly;
                // otherwise store the entry TOP the epilogue expects to find
                // (exactly what the old read-modify-write preserved).
                if (topval_const >= 0) {
                    // Specialized body: entry TOP is the guard constant 0 and
                    // the packed CC's TOP field is structurally zero, so the
                    // merges are ORR-immediates (or nothing for TOP 0).
                    const int store_top = sink ? topval_const : 0;
                    if (store_top != 0) emit_top_orr_imm(store_top, Wd_sw);
                    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0,
                                     kSwImm12, Xbase, Wd_sw);
                    // AX gets the snapshot TOP; the stored merge above was 0
                    // (or identical when sinking), so ORR still applies.
                    if (!sink && topval_const != 0)
                        emit_top_orr_imm(topval_const, Wd_sw);
                } else {
                    int Wd_topval = Wd_top;
                    bool own_topval = false;
                    if (td != 0) {
                        Wd_topval = alloc_free_gpr(*result);
                        own_topval = true;
                        emit_add_imm(buf, 0, /*is_sub=*/td < 0 ? 1 : 0, 0, 0,
                                     td < 0 ? -td : td, Wd_top, Wd_topval);
                    }
                    emit_fcom_cc_store_sw(buf, Xbase, Wd_sw,
                                          sink ? Wd_topval : Wd_top);
                    // AX gets the snapshot TOP. Identical to the stored value
                    // whenever the two TOPs agree, so patch only on mismatch.
                    if (!sink && td != 0)
                        emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21,
                                      /*imms=*/2, Wd_topval, Wd_sw);
                    if (own_topval) free_gpr(*result, Wd_topval);
                }
                // BFI W_ax, Wd_sw, #0, #16
                emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/0, /*imms=*/15,
                              Wd_sw, W_ax);
                free_gpr(*result, Wd_sw);
            } else {
                // Non-fused: the CC bits already reached memory via an earlier
                // compare's store, so the halfword must be read back and its
                // TOP field patched with a register BFI (XZR when the
                // snapshot TOP is the constant 0).
                int Wd_topval;
                bool own_topval = false;
                if (topval_const >= 0) {
                    if (topval_const == 0) {
                        Wd_topval = GPR::XZR;
                    } else {
                        Wd_topval = alloc_free_gpr(*result);
                        own_topval = true;
                        emit_movn(buf, 0, /*MOVZ*/2, 0,
                                  (uint16_t)topval_const, Wd_topval);
                    }
                } else if (td != 0) {
                    Wd_topval = alloc_free_gpr(*result);
                    own_topval = true;
                    emit_add_imm(buf, 0, /*is_sub=*/td < 0 ? 1 : 0, 0, 0,
                                 td < 0 ? -td : td, Wd_top, Wd_topval);
                } else {
                    Wd_topval = Wd_top;
                }
                const int Wd_sw = alloc_free_gpr(*result);
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1,
                                 kSwImm12, Xbase, Wd_sw);
                // BFI Wd_sw, Wd_topval, #11, #3 — patch the TOP field
                emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/21, /*imms=*/2,
                              Wd_topval, Wd_sw);
                if (sink)
                    emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0,
                                     kSwImm12, Xbase, Wd_sw);
                emit_bitfield(buf, 0, /*BFM*/1, 0, /*immr=*/0, /*imms=*/15,
                              Wd_sw, W_ax);
                free_gpr(*result, Wd_sw);
                if (own_topval) free_gpr(*result, Wd_topval);
            }
            break;
        }

        }  // switch

        // Free FPRs whose last use was this node.
        fprs.free_dead_inputs(*result, n, i);
    }

    // ── Epilogue: update x87 state ──────────────────────────────────────────

    // 1. Update TOP register.
    if (ctx.top_delta != 0) {
        if (top_known >= 0) {
            // Final TOP is a translate-time constant.
            emit_movn(buf, 0, /*MOVZ*/2, 0, (uint16_t)final_top_known, Wd_top);
        } else {
            if (ctx.top_delta < 0) {
                emit_add_imm(buf, 0, /*is_sub=*/1, 0, 0, -ctx.top_delta, Wd_top, Wd_top);
            } else {
                emit_add_imm(buf, 0, /*is_sub=*/0, 0, 0, ctx.top_delta, Wd_top, Wd_top);
            }
            emit_and_imm(buf, 0, Wd_top, 0, 0, 2, Wd_top);
        }
    }

    // 2. Store modified stack values.
    // At this point, Wd_top holds the FINAL top. slot_val[d] tells us what value
    // should be at logical depth d relative to the final TOP.
    // In the specialized body every slot address is a static [Xbase, #imm];
    // gather the dirty slots and pair consecutive physical indices into STPs.
    int stp_phys[8], stp_fpr[8], stp_cnt = 0;
    for (int d = 0; d < 8; d++) {
        int16_t val = ctx.slot_val[d];
        if (val < 0) continue;  // initial slot, unchanged (no store needed)
        // Skip redundant write-back: if the value is a ReadSt loaded from the
        // same physical slot it would be stored to, the store is a no-op.
        if (ctx.nodes[val].op == Op::ReadSt &&
            ctx.nodes[val].initial_depth == d + ctx.top_delta)
            continue;
        int Dd = fprs.get(val);
        if (Dd < 0) continue;   // dead or already freed
        if (top_known >= 0) {
            // Insertion-sorted by physical index (wrap can reorder them).
            const int phys = (final_top_known + d) & 7;
            int k = stp_cnt++;
            while (k > 0 && stp_phys[k - 1] > phys) {
                stp_phys[k] = stp_phys[k - 1];
                stp_fpr[k] = stp_fpr[k - 1];
                k--;
            }
            stp_phys[k] = phys;
            stp_fpr[k] = Dd;
        } else {
            emit_store_st(buf, Xbase, Wd_top, d, Wd_tmp, Dd, Xst_base);
        }
    }
    for (int k = 0; k < stp_cnt;) {
        if (k + 1 < stp_cnt && stp_phys[k + 1] == stp_phys[k] + 1) {
            emit_fldp_fstp_d(buf, /*is_load=*/0,
                             static_cast<int16_t>((kX87RegFileOff >> 3) + stp_phys[k]),
                             Xbase, stp_fpr[k], stp_fpr[k + 1]);
            k += 2;
        } else {
            emit_fstr_imm(buf, 3, stp_fpr[k], Xbase,
                          static_cast<int16_t>((kX87RegFileOff >> 3) + stp_phys[k]));
            k++;
        }
    }

    // 3. Write TOP to status_word if changed, or if it was already stale on
    //    entry (carried-in top_dirty from deferred pushes/pops).
    //    Skipped when an FSTSW already stored the halfword with the final TOP
    //    folded in (sw_sink_node).
    if ((ctx.top_delta != 0 || entry_top_dirty) && sw_sink_node < 0) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
    }

    // 4. Update tag word, folding in carried-in deferred push/pop tag updates
    //    (P pending set-valid, Q pending set-empty; P and Q never coexist).
    //    Relative to the FINAL top:
    //      valid slots:  V = max(0, P - top_delta)   at TOP .. TOP+V-1
    //      empty slots:  M = max(0, top_delta + Q - P) at TOP-M .. TOP-1
    //    With P = Q = 0 this reduces to the plain net push/pop cases.
    {
        const int set_valid = (entry_push_count - ctx.top_delta > 0)
                                  ? entry_push_count - ctx.top_delta : 0;
        const int set_empty = (ctx.top_delta + entry_pop_count - entry_push_count > 0)
                                  ? ctx.top_delta + entry_pop_count - entry_push_count : 0;
        if (set_valid > 0 || set_empty > 0) {
            int Wd_tmp2 = alloc_free_gpr(*result);
            int Wd_tagw = alloc_free_gpr(*result);
            if (top_known >= 0) {
                // Static slot positions → constant tag masks (wrap folded at
                // translate time): LDRH / ORR-imm / AND-imm / STRH. Masks are
                // contiguous 2-bit-group runs unless they wrap the 16-bit
                // field, so the immediate forms almost always encode; the
                // MOVZ + register-op pair is the wrap fallback.
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*LDR*/1,
                                 kX87TagWordImm12, Xbase, Wd_tagw);
                if (set_empty > 0) {
                    uint16_t mask = 0;
                    for (int k = 1; k <= set_empty; k++)
                        mask |= (uint16_t)(0x3u << (((final_top_known - k) & 7) * 2));
                    LogicalImmEncoding enc;
                    if (is_bitmask_immediate(false, mask, enc)) {
                        emit_logical_imm(buf, 0, /*ORR*/1, enc.N ? 1 : 0,
                                         static_cast<int8_t>(enc.immr),
                                         static_cast<int8_t>(enc.imms),
                                         Wd_tagw, Wd_tagw);
                    } else {
                        emit_movn(buf, 0, /*MOVZ*/2, 0, mask, Wd_tmp2);
                        emit_logical_shifted_reg(buf, 0, /*ORR*/1, 0, 0, Wd_tmp2,
                                                 0, Wd_tagw, Wd_tagw);
                    }
                }
                if (set_valid > 0) {
                    uint16_t mask = 0;
                    for (int k = 0; k < set_valid; k++)
                        mask |= (uint16_t)(0x3u << (((final_top_known + k) & 7) * 2));
                    // Clear = AND with the complement (BIC has no imm form).
                    // The upper half of Wd_tagw is zero after the LDRH, and
                    // ~mask keeps it zero.
                    LogicalImmEncoding enc;
                    if (is_bitmask_immediate(false, 0xFFFFFFFFu & ~(uint32_t)mask,
                                             enc)) {
                        emit_logical_imm(buf, 0, /*AND*/0, enc.N ? 1 : 0,
                                         static_cast<int8_t>(enc.immr),
                                         static_cast<int8_t>(enc.imms),
                                         Wd_tagw, Wd_tagw);
                    } else {
                        emit_movn(buf, 0, /*MOVZ*/2, 0, mask, Wd_tmp2);
                        emit_logical_shifted_reg(buf, 0, /*AND*/0, /*N=BIC*/1, 0,
                                                 Wd_tmp2, 0, Wd_tagw, Wd_tagw);
                    }
                }
                emit_ldr_str_imm(buf, /*size=*/1, /*is_fp=*/0, /*STR*/0,
                                 kX87TagWordImm12, Xbase, Wd_tagw);
            } else {
                if (set_empty > 0)
                    emit_x87_tag_set_empty_batch(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2,
                                                  Wd_tagw, set_empty);
                if (set_valid > 0)
                    emit_x87_tag_set_valid_batch(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2,
                                                  Wd_tagw, set_valid);
            }
            free_gpr(*result, Wd_tagw);
            free_gpr(*result, Wd_tmp2);
        }
    }

    // 5. Free all remaining FPRs held by node values (plan-pinned v16/v17
    //    were never pool-allocated — clear the binding only).
    for (int i = 0; i < ctx.num_nodes; i++) {
        if (fprs.node_fpr[i] >= 0) {
            if (!(fprs.pinned_mask >> fprs.node_fpr[i] & 1u))
                free_fpr(*result, fprs.node_fpr[i]);
            fprs.node_fpr[i] = -1;
        }
    }
    };  // emit_body

    // ── Emit the run: specialized (TOP==0) + generic behind a guard, or just
    //    the generic body. Branch offsets are patched after emission (the
    //    buffer may grow/move, so patch through buf.data at patch time).
    if (!top0_specialize) {
        emit_body(-1);
    } else {
        const uint32_t saved_gpr_mask = result->free_gpr_mask;
        const uint32_t saved_fpr_mask = result->free_fpr_mask;

        const uint64_t guard_off = buf.end;
        emit_cbz(buf, /*is_64bit=*/0, /*is_nz=*/1, Wd_top, /*imm19=*/0);  // CBNZ → generic
        emit_body(/*top_known=*/0);
        const uint64_t skip_off = buf.end;
        emit_b(buf, 0);                                                   // B → done
        // Patch the CBNZ to land on the generic body.
        buf.data[guard_off / 4] |=
            (((uint32_t)((buf.end - guard_off) / 4) & 0x7FFFF) << 5);

        // The specialized body is balanced, but restore allocation state
        // explicitly so the generic body starts from the identical pool.
        result->free_gpr_mask = saved_gpr_mask;
        result->free_fpr_mask = saved_fpr_mask;
        emit_body(/*top_known=*/-1);
        // Patch the skip branch to land after the generic body.
        buf.data[skip_off / 4] |= ((uint32_t)((buf.end - skip_off) / 4) & 0x3FFFFFF);
    }

    // 6. Clean up cache deferred state (we handled everything inline).
    result->x87_cache.top_dirty = 0;
    result->x87_cache.deferred_push_count = 0;
    result->x87_cache.deferred_pop_count = 0;
    result->x87_cache.reset_perm();

    // 7. Free scratch GPRs — or carry them across the bridge (OPT-BC).
    // When the cache stays active past this run, transfer up to kMaxCarried
    // pins (planned bases first, then still-valid older entries, then RC) to
    // X87Cache; the next IR run reuses them instead of re-materializing.
    // Dropped GPRs return to the pool when the caller recomputes
    // free_gpr_mask from pinned_mask().
    {
        bool base_carried[Context::kAddrCacheSlots] = {};
        bool rc_carried = false;
        const bool stays_active = xc.run_remaining > ctx.consumed;
        if (carry_on && stays_active) {
            bool run_has_fstsw = false;
            for (int i = 0; i < ctx.num_nodes; i++) {
                const auto& n = ctx.nodes[i];
                if (!(n.flags & kDead) && n.op == Op::FStsw) {
                    run_has_fstsw = true;
                    break;
                }
            }
            // Never carry x29 (pool slot 7 — compute_operand_address's
            // GS/TLS fallback fixed-allocates it) or a non-scratch register
            // (the 64-bit no-disp path returns the guest register itself).
            auto gpr_carryable = [](int g) {
                return g >= 0 && g != GPR::X29 && ((kGprScratchMask >> g) & 1u) != 0;
            };

            X87Cache::CarriedBase next[X87Cache::kMaxCarried];
            int8_t next_rc = -1;
            int nbase = 0;
            // This run's planned reps: plan_addr_cache already excluded
            // guest-written and FSTSW/RAX operands, so every rep qualifies.
            for (int k = 0; k < addr_n && nbase < X87Cache::kMaxCarried; k++) {
                if (!gpr_carryable(addr_reg[k])) continue;
                auto& c = next[nbase];
                c.addr_size = static_cast<uint8_t>(addr_rep[k]->mem.addr_size);
                c.mem_flags = addr_rep[k]->mem.mem_flags;
                c.base_reg = addr_rep[k]->mem.base_reg;
                c.index_reg = addr_rep[k]->mem.index_reg;
                c.shift_amount = addr_rep[k]->mem.shift_amount;
                c.gpr = static_cast<int8_t>(addr_reg[k]);
                base_carried[k] = true;
                nbase++;
            }
            // Older carried entries this run didn't plan stay valid unless
            // the run redefined their guest registers (inlined Guest nodes,
            // or FSTSW writing AX).
            for (int s = 0; s < X87Cache::kMaxCarried && nbase < X87Cache::kMaxCarried;
                 s++) {
                const auto& oc = xc.carried_base[s];
                if (oc.gpr < 0) continue;
                bool dup = false;
                for (int j = 0; j < nbase; j++)
                    if (next[j].gpr == oc.gpr) dup = true;
                if (dup) continue;
                uint16_t written = ctx.guest_written_mask;
                if (run_has_fstsw) written |= 1u;  // AX
                const bool stale =
                    ((oc.mem_flags & 1) && ((written >> (oc.base_reg & 0xF)) & 1)) ||
                    ((oc.mem_flags & 2) && ((written >> (oc.index_reg & 0xF)) & 1));
                if (stale) continue;
                next[nbase++] = oc;
            }
            if (Wd_rc_cached >= 0 && nbase < X87Cache::kMaxCarried &&
                gpr_carryable(Wd_rc_cached)) {
                next_rc = static_cast<int8_t>(Wd_rc_cached);
                rc_carried = true;
            }
            xc.carried_clear();
            for (int j = 0; j < nbase; j++)
                xc.carried_base[j] = next[j];
            xc.carried_rc_gpr = next_rc;
        } else if (carry_on) {
            // Run cache expires with this run; tick() clears the flags and
            // the caller resets the mask.
            xc.carried_clear();
        }

        for (int k = 0; k < addr_n; k++) {
            if (addr_owned[k] && !base_carried[k])
                free_gpr(*result, addr_reg[k]);
        }
        if (Wd_rc_cached >= 0 && !rc_carried)
            free_gpr(*result, Wd_rc_cached);
    }
    if (Wd_tmp >= 0) free_gpr(*result, Wd_tmp);

    // 8. If cache is about to expire (run_remaining will hit 0 after ticks),
    //    free the cache GPRs. Otherwise, leave them pinned for the next run.
    if (result->x87_cache.run_remaining <= ctx.consumed) {
        // Cache will be deactivated by tick(). Release GPRs now so they don't
        // stay allocated past the run.
        // (tick() resets gprs_valid=0 but doesn't free the mask bits.)
        // The caller (Translator.cpp) resets free_gpr_mask after ticking.
    }
}

// ── Peak GPR pressure query ──────────────────────────────────────────────────
//
// Returns the maximum number of scratch GPRs simultaneously in use during
// lowering (permanent + transient).  If this exceeds the available pool the
// caller should bail out to the ordinary per-instruction translation path.
//
// Permanent GPRs (held for the entire lower() duration):
//   - Xbase (pool 0), Wd_top (pool 1), Wd_tmp (pool 2), Xst_base (pool 6) = 4
//     ... except on mid-run entry (`gprs_cached`): x87_begin then reuses the
//     cache's already-pinned Xbase/Wd_top/Xst_base, which the caller has
//     already excluded from the free pool — counting them again would
//     double-charge 3 registers and spuriously decline nearly every mid-run
//     attempt. Only Wd_tmp is newly allocated in that case = 1.
//   - Wd_rc_cached (pool 3) when RC caching is active = +1
//
// Per-node transient GPR demand (mirrors the lowering code exactly):
//   - ReadSt, Const*, FAdd/FSub/FMul/FDiv, FMA*, FNeg/FAbs/FSqrt, FCSel, Cvt*: 0
//   - LoadF64, LoadF32Raw, StoreF64, StoreF32Raw: 1 (addr from compute_operand_address)
//   - LoadI16/I32/I64: 2 (addr + Wd_val)
//   - StoreI16/I32/I64: 2 (Wd_int + addr)
//   - FRndInt without RC cache: 1 (Wd_rc via alloc_gpr(3))
//   - FCmp/FTst: 4 peak inside emit_fcom_cc_pack (Wd_save + Wd_packed + Wd_cc + Wd_vs)
//     If kFcomFused, Wd_packed stays alive until consumed by FStsw.
//   - FComI: 3 (Wd_z + Wd_v + Wd_c)
//   - FStsw (fused): 2 (Wd_packed held from FCmp + Wd_sw_inner inside emit_fcom_cc_write_sw,
//     or Wd_sw + Wd_adj when top_delta != 0)
//   - FStsw (non-fused): 2 (Wd_sw + Wd_adj if top_delta != 0)
//   - StoreCW/LoadCW: 2 (addr + Wd_cw)
//   - Epilogue (top_delta != 0): 2 (Wd_tmp2 + Wd_tagw)
//
// Fused FCmp/FTst holds 1 GPR (Wd_packed) alive across nodes until FStsw.
// We track this as a "held" count that overlaps with per-node transient demand.
int peak_live_gprs(const Context& ctx, bool entry_deferred, bool gprs_cached) {
    // Determine if RC caching will be active (same logic as lower()).
    bool rc_cache = false;
    if (!(g_rosetta_config && g_rosetta_config->fast_round)) {
        int rc_count = 0;
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::StoreCW) continue;
            bool is_rc = (n.op == Op::FRndInt) ||
                ((n.op == Op::StoreI16 || n.op == Op::StoreI32 || n.op == Op::StoreI64)
                 && !(n.flags & kTruncate));
            if (is_rc && ++rc_count >= 2) { rc_cache = true; break; }
        }
    }

    int pinned = gprs_cached ? 1 : 4;  // Wd_tmp [+ Xbase, Wd_top, Xst_base]
    if (rc_cache) pinned++;            // Wd_rc_cached

    // NZCV hoisting/elision mirror (same predicates as lower()): when hoisting,
    // one GPR (Wd_nzcv_saved) is held from the first FCmp/FTst through the
    // last, and each compare no longer allocates a per-node Wd_save. When
    // eliding (nzcv_skip), compares cost 3 transient with nothing held.
    int nzcv_first_cmp = -1, nzcv_last_cmp = -1;
    bool nzcv_hoist = false;
    bool nzcv_skip = false;
    {
        int cmp_count = 0;
        bool has_nzcv_user = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            if (n.op == Op::FComI || n.op == Op::FCSel) { has_nzcv_user = true; break; }
            if (n.op == Op::FCmp || n.op == Op::FTst) {
                if (nzcv_first_cmp < 0) nzcv_first_cmp = i;
                nzcv_last_cmp = i;
                cmp_count++;
            }
        }
        nzcv_skip = ctx.nzcv_dead && !has_nzcv_user && cmp_count >= 1;
        nzcv_hoist = !nzcv_skip && !has_nzcv_user && cmp_count >= 2;
    }

    // Simulate GPR pressure across IR nodes.
    // "held" tracks GPRs held alive across node boundaries (fused FCmp→FStsw).
    int held = 0;
    int peak = pinned;  // at minimum, permanent GPRs

    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        int transient = 0;  // per-node transient GPR demand

        switch (n.op) {
        // No transient GPRs
        case Op::ReadSt:
        case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
        case Op::CvtF32ToF64: case Op::CvtF64ToF32:
        case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
        case Op::FNMul:
        case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
        case Op::FNeg: case Op::FAbs: case Op::FSqrt:
        case Op::FCSel:
            break;

        // 1 GPR: addr from compute_operand_address
        case Op::LoadF64: case Op::LoadF32Raw:
        case Op::StoreF64: case Op::StoreF32Raw:
            transient = 1;
            break;

        // 2 GPRs: addr + Wd_val
        case Op::LoadI16: case Op::LoadI32:
            transient = 2;
            break;

        // 1 GPR: addr only — the int64 is loaded into the FPR directly
        case Op::LoadI64:
            transient = 1;
            break;

        // 2 GPRs: Wd_int + addr
        case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            transient = 2;
            break;

        // FRndInt: 1 GPR if no RC cache (alloc_gpr(3) for Wd_rc), 0 with cache
        case Op::FRndInt:
            if (!rc_cache) transient = 1;
            break;

        // OPT-TI trig/pow calls: 1 transient GPR for the status RMW
        // (FSinCosProjCos is a bare FMOV — no GPR; F2XM1Call has no
        // status effect but keep the estimate uniform and safe)
        case Op::FCosCall: case Op::FSinCall: case Op::FPtanCall:
        case Op::FSinCosCall: case Op::F2XM1Call: case Op::FScaleCall:
        case Op::FYl2xCall: case Op::FYl2xp1Call: case Op::FPatanCall:
            transient = 1;
            break;

        // FCmp/FTst: 4 peak inside emit_fcom_cc_pack
        // (Wd_save + Wd_packed + Wd_cc + Wd_vs simultaneously live)
        // Hoisted: no per-node Wd_save (3 transient), but Wd_nzcv_saved is
        // held from the first compare through the last (held++ below).
        // If fused, Wd_packed stays alive after — but it is already part of
        // this node's transient count, so the held++ happens after node_total
        // below (adding it here would double-count it and spuriously bail
        // every fused single-compare run: 4 pinned + 4 + 1 = 9 > 8 pool).
        case Op::FCmp: case Op::FTst:
            if (nzcv_skip) {
                transient = 3;  // Wd_packed + Wd_cc + Wd_vs, no save
            } else if (nzcv_hoist) {
                transient = 3;
                if (i == nzcv_first_cmp) held++;  // Wd_nzcv_saved acquired
            } else {
                transient = 4;
            }
            break;

        // FComI: 3 GPRs (Wd_z + Wd_v + Wd_c)
        case Op::FComI:
            transient = 3;
            break;

        // FStsw: fused path holds Wd_packed (counted in held) + up to 2 more
        // Non-fused: up to 2 (Wd_sw + Wd_adj)
        case Op::FStsw:
            // FCom-fused: emit_fcom_cc_write_sw_keep allocates Wd_sw while
            // Wd_packed (held) is still live, then Wd_packed is freed and
            // Wd_sw + possibly Wd_adj coexist → peak 2 alongside held-1.
            // Non-fused: max(Wd_sw+Wd_adj) = 2
            transient = 2;
            if (n.flags & kFcomFused) {
                // Wd_packed is released during this node
                held--;
            }
            break;

        // StoreCW/LoadCW: 2 GPRs (addr + Wd_cw)
        case Op::StoreCW: case Op::LoadCW:
            transient = 2;
            break;

        // Inlined guest integers write guest GPRs directly; only a lea (or
        // an AluRI add/sub) with a disp fitting neither imm12 form allocates
        // a temp — charge 1 conservatively for every lea/AluRI.
        case Op::GuestMovRR: case Op::GuestMovRI: case Op::GuestExt:
            break;
        case Op::GuestLea: case Op::GuestAluRI:
            transient = 1;
            break;

        // Guest memory movs: data register is the guest GPR (loads/reg
        // stores) — only the uncached address computation allocates, so 1.
        // Imm stores also materialize the value into a scratch: 2. RMW
        // holds its value scratch across the uncached address computation: 2.
        case Op::GuestLoad: case Op::GuestStoreR:
            transient = 1;
            break;
        case Op::GuestStoreI: case Op::GuestRmwR:
            transient = 2;
            break;

        // push/pop: single writeback insn on x4 — no scratch; immediate
        // pushes materialize the value into one scratch.
        case Op::GuestPushR: case Op::GuestPop:
            break;
        case Op::GuestPushI:
            transient = 1;
            break;
        }

        int node_total = pinned + held + transient;
        if (node_total > peak) peak = node_total;

        // Fused FCmp/FTst: Wd_packed survives the node (until FStsw). It was
        // counted in this node's transient demand; from here on it's held.
        if ((n.op == Op::FCmp || n.op == Op::FTst) && (n.flags & kFcomFused))
            held++;

        // Wd_nzcv_saved is released at the end of the last compare node.
        if (nzcv_hoist && i == nzcv_last_cmp) held--;
    }

    // Epilogue: if top_delta != 0 (or carried-in deferred tag/top state must be
    // materialized), needs 2 more transient GPRs (Wd_tmp2 + Wd_tagw)
    if (ctx.top_delta != 0 || entry_deferred) {
        int epilogue_total = pinned + held + 2;
        if (epilogue_total > peak) peak = epilogue_total;
    }

    return peak;
}

// ── Peak FPR pressure query ──────────────────────────────────────────────────
//
// Simulates the liveness model used by the lowering pass and returns the
// maximum number of scratch FPRs simultaneously in use at any point.
//
// Rules (mirroring the lowering pass exactly):
//   - Value-producing nodes (ReadSt, Load*, Const*, FAdd, …) hold one FPR from
//     the point they are emitted until their last use is emitted.
//   - free_dead_inputs() fires at the end of each node, so the transient peak
//     *during* a node is: (currently live) + 1 for the new output, before dead
//     inputs are freed.  try_reuse_input() avoids the +1 by recycling a dying
//     input's FPR; we model it with the same claim order as lower().
//   - LDP/STP pairs shift liveness: a load pair allocates the partner's FPR at
//     the lead node; a store pair extends the sunk store's input to the
//     emission node.  Pairs are mirrored with reps == nullptr (any cacheable
//     base), a superset of what lower() forms — over- never under-estimating.
//   - StoreI*, FCmp, FTst, FStsw produce no FPR output and need no extra FPRs.
//   - Dead (kDead) nodes are skipped.
int peak_live_fprs(const Context& ctx) {
    // Step 1: compute last_use[] — same as FPRState::compute_last_uses.
    int16_t last_use[kMaxNodes];
    memset(last_use, -1, sizeof(last_use));
    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) last_use[n.inputs[j]] = static_cast<int16_t>(i);
        }
    }
    for (int d = 0; d < 8; d++) {
        int16_t val = ctx.slot_val[d];
        if (val >= 0 && val < ctx.num_nodes)
            last_use[val] = static_cast<int16_t>(ctx.num_nodes);
    }

    // Mirror the LDP/STP pair plan conservatively (reps == nullptr: any
    // base-cacheable operand may pair — a superset of lower()'s pairs).
    int16_t pair_with[kMaxNodes];
    bool pair_skip[kMaxNodes];
    compute_pairs(ctx, nullptr, 0, pair_with, pair_skip);
    for (int e = 0; e < ctx.num_nodes; e++) {
        if (pair_with[e] < 0) continue;
        const auto& en = ctx.nodes[e];
        if (en.op != Op::StoreF64 && en.op != Op::StoreF32Raw) continue;
        int16_t in_s = ctx.nodes[pair_with[e]].inputs[0];
        if (in_s >= 0 && last_use[in_s] < e)
            last_use[in_s] = static_cast<int16_t>(e);
    }

    // Step 2: simulate FPR allocation order, tracking live count.
    // A node holds an FPR from instruction i (inclusive) to last_use[i]
    // (exclusive — freed at the end of the last-use instruction).
    // live[i] = number of nodes alive at the *start* of instruction i.
    int live = 0;
    int peak = 0;

    // Track which nodes are currently holding an FPR (bit vector over kMaxNodes).
    bool holding[kMaxNodes] = {};

    for (int i = 0; i < ctx.num_nodes; i++) {
        const auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        if (!pair_skip[i]) {
            // Allocate FPR for nodes that produce an FPR-bearing value.
            // Ops that call try_reuse_input() in lower() can recycle a dying
            // input's FPR for their output (net-zero live change); model that
            // with the exact same claim order (inputs[0..2], first dying wins).
            bool produces_fpr = false;
            bool can_reuse = false;
            switch (n.op) {
            case Op::ReadSt:
            case Op::LoadF64: case Op::LoadF32Raw:
            case Op::LoadI16: case Op::LoadI32: case Op::LoadI64:
            case Op::ConstZero: case Op::ConstOne: case Op::ConstF64:
                produces_fpr = true;
                break;
            case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
            case Op::FNMul:
            case Op::FMAdd: case Op::FMSub: case Op::FNMSub:
            case Op::FNeg: case Op::FAbs: case Op::FSqrt: case Op::FRndInt:
            case Op::FCosCall: case Op::FSinCall: case Op::FPtanCall:
            case Op::FSinCosCall: case Op::FSinCosProjCos:
            case Op::F2XM1Call: case Op::FScaleCall:
            case Op::FYl2xCall: case Op::FYl2xp1Call: case Op::FPatanCall:
            case Op::FCSel:
            case Op::CvtF32ToF64: case Op::CvtF64ToF32:
                produces_fpr = true;
                can_reuse = true;
                break;
            default:
                break;
            }

            if (produces_fpr) {
                bool reused = false;
                if (can_reuse) {
                    for (int j = 0; j < 3; j++) {
                        int16_t in = n.inputs[j];
                        if (in >= 0 && last_use[in] == i && holding[in]) {
                            holding[in] = false;  // FPR claimed by this node's output
                            reused = true;
                            break;
                        }
                    }
                }
                if (!reused) live++;
                holding[i] = true;
                if (live > peak) peak = live;
            }

            // Load pair lead: the hoisted partner's FPR is allocated here too.
            const int j = pair_with[i];
            if (j >= 0 && (n.op == Op::LoadF64 || n.op == Op::LoadF32Raw)) {
                live++;
                holding[j] = true;
                if (live > peak) peak = live;
            }
        }

        // Free every held value whose (possibly pair-extended) last use is
        // this node — covers this node's inputs and, at a store-pair emission
        // node, the sunk partner's input (matching lower()'s explicit free).
        for (int h = 0; h < ctx.num_nodes; h++) {
            if (holding[h] && last_use[h] == i) {
                holding[h] = false;
                live--;
            }
        }
    }

    return peak;
}

// ── Entry point ─────────────────────────────────────────────────────────────

int compile_run(TranslationResult* result, IRInstr* instr_array, int64_t num_instrs,
                int64_t start_idx, int run_length, CompileError* err) {
    // Report a decline reason and yield 0 (nothing consumed) in one line.
    auto fail = [&](CompileError e) { if (err) *err = e; return 0; };

    // Fold carried-in deferred-FXCH permutation into the initial slot map.
    const auto& cache = result->x87_cache;
    const int8_t* perm = cache.perm_dirty ? cache.perm : nullptr;

    // Constant-load promotion reads guest memory at translation time — only
    // sound in JIT mode, where the guest address space is this process.
    // Constant-load promotion reads guest memory at translation time. The
    // page-protection probe is only compiled into the ROSETTA_RUNTIME build,
    // which is always injected into a live guest process; elsewhere
    // range_is_readonly() is stubbed to false, so the flag is inert.
    const bool const_promote =
        g_rosetta_config && g_rosetta_config->const_promote;

    // NOTE (2026-07-11): a pressure-decline PREFIX RETRY (halve run_length on
    // kFprPressure/kGprPressure and lower the fitting prefix) was implemented
    // here and reverted after measurement: it benched 16% SLOWER than the
    // full decline on the 8-live-loads shape. Splitting the run pays two
    // epilogues and breaks the deferred push/pop tag cancellation, while the
    // singular fallback keeps the run cache active and defers everything.
    // The effective fix for FPR-pressure declines is the extended FPR pool
    // (ROSETTA_X87_EXTENDED_FPR_SCRATCH=1): the same shape lowers as ONE run,
    // 2.3x faster than the decline path. If a retry is ever revisited, split
    // at a balanced point (cumulative top_delta == 0), never at consumed/2.
    Context ctx;
    if (!build(ctx, instr_array, num_instrs, start_idx, run_length, perm, const_promote))
        return fail(CompileError::kBuildFailed);

    optimize(ctx);

    // Guest-flags deadness: scan the guest instructions after the consumed
    // run; if they fully redefine EFLAGS before any possible reader, the
    // FCmp/FTst NZCV save/restore is elided in lowering.
    ctx.nzcv_dead = nzcv_dead_after_run(instr_array, num_instrs,
                                        start_idx + ctx.consumed) ? 1 : 0;

    // OPT-TI: runs containing a trig value call must never keep a value
    // resident in v16 across the call (d16 is the call's in/out register).
    // Exclude v16 from the pool for the whole run — BEFORE the pressure gate,
    // so the gate and the allocator agree on the available count.  Restored
    // after lower().
    bool has_fcos_call = false;
    bool has_sincos_call = false;   // additionally excludes v17 (cos output /
                                    // FScaleCall's ST(1) argument register)
    for (int ni = 0; ni < ctx.num_nodes; ni++) {
        const auto op = ctx.nodes[ni].op;
        if (ctx.nodes[ni].flags & kDead) continue;
        if (op == Op::FCosCall || op == Op::FSinCall || op == Op::FPtanCall ||
            op == Op::F2XM1Call)
            has_fcos_call = true;
        else if (op == Op::FSinCosCall || op == Op::FScaleCall ||
                 op == Op::FYl2xCall || op == Op::FYl2xp1Call ||
                 op == Op::FPatanCall)
            has_fcos_call = has_sincos_call = true;
    }
    const uint32_t fpr_mask_before_v16_excl = result->free_fpr_mask;
    if (has_fcos_call)
        result->free_fpr_mask &= ~(1u << 16);
    if (has_sincos_call)
        result->free_fpr_mask &= ~(1u << 17);
    // Restore on EVERY exit from here on (fail() paths included).
    struct V16Restore {
        TranslationResult* r;
        uint32_t mask;
        ~V16Restore() { r->free_fpr_mask = mask; }
    } v16_restore{result, fpr_mask_before_v16_excl};

    // Gate lowering on actual FPR pressure vs. available pool.
    uint32_t fpr_pool = result->free_fpr_mask;
    int available = 0;
    while (fpr_pool) { available++; fpr_pool &= fpr_pool - 1; }
    if (peak_live_fprs(ctx) > available) {
        return fail(CompileError::kFprPressure);
    }

    // Gate lowering on GPR pressure vs. available pool.
    {
        const bool entry_deferred = cache.top_dirty != 0 ||
                                    cache.deferred_push_count > 0 ||
                                    cache.deferred_pop_count > 0;
        uint32_t gpr_pool = result->free_gpr_mask;
        int gpr_available = 0;
        while (gpr_pool) { gpr_available++; gpr_pool &= gpr_pool - 1; }
        // Mid-run entry: x87_begin will reuse the cache's pinned GPRs (same
        // predicate), so the model must not charge for them — the caller
        // already removed them from free_gpr_mask.
        const bool gprs_cached = cache.run_remaining > 0 && cache.gprs_valid;
        const int peak = peak_live_gprs(ctx, entry_deferred, gprs_cached);
        if (peak > gpr_available) {
            // OPT-BC: carried pins are an optimization, releasable at will —
            // give their registers back and retry before declining the run.
            if (result->x87_cache.carried_any()) {
                result->x87_cache.carried_release(result->free_gpr_mask);
                gpr_pool = result->free_gpr_mask;
                gpr_available = 0;
                while (gpr_pool) { gpr_available++; gpr_pool &= gpr_pool - 1; }
            }
            if (peak > gpr_available)
                return fail(CompileError::kGprPressure);
        }
        // Base-address cache: each cached base pins exactly one extra GPR for
        // the whole run (on top of every per-node total), so peak+N is exact.
        // Degrade the plan until it fits. OPT-BC: a rep matching a carried
        // entry reuses its already-pinned GPR — it costs nothing new, so it
        // is not charged (otherwise a carried RC pin, which already shrank
        // the pool, would spuriously degrade the plan).
        int addr_n = plan_addr_cache(ctx);
        const bool carry_on = g_rosetta_config && g_rosetta_config->bridge_carry;
        auto chargeable = [&](int n) {
            if (!carry_on) return n;  // default accounting stays byte-identical
            int c = 0;
            for (int k = 0; k < n; k++) {
                const IROperand* mo = ctx.nodes[ctx.addr_cache_rep[k]].mem_operand;
                // 64-bit base-only operand: compute_operand_address returns
                // the guest register itself — nothing is pinned.
                if (mo->mem.addr_size == IROperandSize::S64 &&
                    mo->mem.mem_flags == 1)
                    continue;
                bool carried = false;
                for (int s = 0; s < X87Cache::kMaxCarried; s++) {
                    if (cache.carried_base[s].gpr >= 0 &&
                        carried_key_match(cache.carried_base[s], mo)) {
                        carried = true;
                        break;
                    }
                }
                if (!carried) c++;
            }
            return c;
        };
        while (addr_n > 0 && peak + chargeable(addr_n) > gpr_available)
            addr_n--;
        ctx.addr_cache_n = static_cast<int8_t>(addr_n);
    }

    lower(ctx, result);

    if (err) *err = CompileError::kSuccess;
    return ctx.consumed;
}

}  // namespace X87IR
