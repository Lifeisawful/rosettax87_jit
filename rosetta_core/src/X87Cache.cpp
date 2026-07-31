#include "rosetta_core/X87Cache.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"
#include "rosetta_config/Config.h"

// =============================================================================
// is_handled_x87 — returns true for opcodes that have a translate_* handler.
// Used by lookahead to determine consecutive x87 run lengths.
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
        case kOpcodeName_fisttp:
        case kOpcodeName_fidiv:
        case kOpcodeName_fimul:
        case kOpcodeName_fisub:
        case kOpcodeName_fidivr:
        case kOpcodeName_frndint:
        case kOpcodeName_fcomi:
        case kOpcodeName_fcomip:
        case kOpcodeName_fucomi:
        case kOpcodeName_fucomip:
        case kOpcodeName_ftst:
        case kOpcodeName_fist:
        case kOpcodeName_fisubr:
        case kOpcodeName_fcmovb:
        case kOpcodeName_fcmovbe:
        case kOpcodeName_fcmove:
        case kOpcodeName_fcmovnb:
        case kOpcodeName_fcmovnbe:
        case kOpcodeName_fcmovne:
        case kOpcodeName_fcmovu:
        case kOpcodeName_fcmovnu:
        case kOpcodeName_ficom:
        case kOpcodeName_ficomp:
        case kOpcodeName_fldcw:
        case kOpcodeName_fnstcw:
        case kOpcodeName_fnop:
            return true;
        // Stack-register maintenance family — no OpcodeId bits left, so the
        // whole family is gated by one config flag (also forced by
        // DISABLE_ALL_OPS). When disabled they must not join runs: the
        // dispatch declines them and Rosetta's own translation takes over.
        case kOpcodeName_fdecstp:
        case kOpcodeName_fincstp:
        case kOpcodeName_ffree:
            return !(g_rosetta_config && g_rosetta_config->disable_stack_ops);
        default:
            return false;
    }
}

// =============================================================================
// X87Cache member functions
// =============================================================================

bool X87Cache::active() const {
    return run_remaining > 0;
}

void X87Cache::carried_clear() {
    for (int i = 0; i < kMaxCarried; i++) carried_base[i].gpr = -1;
    carried_rc_gpr = -1;
}

void X87Cache::carried_release(uint32_t& free_gpr_mask) {
    for (int i = 0; i < kMaxCarried; i++) {
        if (carried_base[i].gpr >= 0) free_gpr_mask |= 1u << carried_base[i].gpr;
    }
    if (carried_rc_gpr >= 0) free_gpr_mask |= 1u << carried_rc_gpr;
    carried_clear();
}

void X87Cache::carried_drop_written(uint16_t guest_mask) {
    if (!guest_mask) return;
    for (int i = 0; i < kMaxCarried; i++) {
        auto& c = carried_base[i];
        if (c.gpr < 0) continue;
        const bool hit =
            ((c.mem_flags & 1) && ((guest_mask >> (c.base_reg & 0xF)) & 1)) ||
            ((c.mem_flags & 2) && ((guest_mask >> (c.index_reg & 0xF)) & 1));
        if (hit) c.gpr = -1;
    }
    // The RC cache tracks control_word, not a guest GPR — unaffected.
}

// Conservative written-GPR mask for a run-transparent instruction. Explicit
// register destinations plus the implicit writers in the transparent set;
// 0xFFFF (drop everything) for shapes this doesn't understand.
uint16_t X87Cache::gap_written_gpr_mask(const IRInstr* instr) {
    const uint16_t all = 0xFFFF;
    uint16_t mask = 0;
    const uint16_t op = instr->opcode();
    switch (op) {
        case kOpcodeName_nop:
        case kOpcodeName_cmp:
        // SSE compares write flags only.
        case kOpcodeName_ucomiss: case kOpcodeName_ucomisd:
        case kOpcodeName_comiss:  case kOpcodeName_comisd:
            return 0;
        // rax/rdx implicit writers.
        case kOpcodeName_cbw: case kOpcodeName_cwde: case kOpcodeName_cdqe:
            return 1u << 0;
        case kOpcodeName_cwd: case kOpcodeName_cdq:
            return 1u << 2;
        case kOpcodeName_mul:
            return (1u << 0) | (1u << 2);
        case kOpcodeName_imul:
            if (instr->num_operands <= 1) return (1u << 0) | (1u << 2);
            break;  // 2/3-operand form: explicit dst below
        case kOpcodeName_push:
        case kOpcodeName_pop:
        case kOpcodeName_pushd:
        case kOpcodeName_popd:
            mask |= 1u << 4;  // RSP
            break;
        case kOpcodeName_xchg: {
            // Both operands are written; include any register operand.
            for (int i = 0; i < 2 && i < instr->num_operands; i++) {
                const auto& o = instr->operands[i];
                if (o.kind == IROperandKind::Register) {
                    if (!o.reg.reg.is_gpr()) return all;
                    mask |= 1u << o.reg.reg.index();
                }
            }
            return mask;
        }
        default:
            break;
    }
    // Explicit destination: operands[0] when it is a register. GPR dst →
    // its bit (partial writes still change the value — must count). XMM/MM
    // dst or memory dst → no guest GPR written.
    if (instr->num_operands >= 1) {
        const auto& dst = instr->operands[0];
        if (dst.kind == IROperandKind::Register) {
            if (dst.reg.reg.is_gpr())
                mask |= 1u << dst.reg.reg.index();
            // vector destinations write no GPR
        }
    }
    return mask;
}

void X87Cache::invalidate() {
    gprs_valid = 0;
    top_dirty = 0;
    deferred_push_count = 0;
    deferred_pop_count = 0;
    run_remaining = 0;
    carried_clear();
    reset_perm();
}

void X87Cache::invalidate(uint32_t& free_gpr_mask, uint32_t scratch_mask) {
    invalidate();
    free_gpr_mask = scratch_mask;
}

void X87Cache::set_run(int run_length) {
    if (run_length >= 2)
        run_remaining = static_cast<int16_t>(run_length);
}

void X87Cache::tick() {
    if (run_remaining > 0) {
        run_remaining--;
        if (run_remaining == 0) {
            gprs_valid = 0;
            top_dirty = 0;
            deferred_push_count = 0;
            deferred_pop_count = 0;
            carried_clear();
        }
    }
}

void X87Cache::reset_perm() {
    for (int i = 0; i < 8; i++)
        perm[i] = static_cast<int8_t>(i);
    perm_dirty = 0;
}

bool X87Cache::perm_is_identity() const {
    for (int i = 0; i < 8; i++)
        if (perm[i] != i) return false;
    return true;
}

uint32_t X87Cache::pinned_mask() const {
    uint32_t mask = 0;
    if (gprs_valid) {
        mask |= (1u << base_gpr);
        mask |= (1u << top_gpr);
        mask |= (1u << st_base_gpr);
    }
    for (int i = 0; i < kMaxCarried; i++) {
        if (carried_base[i].gpr >= 0) mask |= 1u << carried_base[i].gpr;
    }
    if (carried_rc_gpr >= 0) mask |= 1u << carried_rc_gpr;
    return mask;
}

static OpcodeId opcode_to_id_local(uint16_t op) {
    using O = Opcode;
    using I = OpcodeId;
    switch (op) {
        case O::kOpcodeName_fldz:     return I::fldz;
        case O::kOpcodeName_fld1:     return I::fld1;
        case O::kOpcodeName_fldl2e:   return I::fldl2e;
        case O::kOpcodeName_fldl2t:   return I::fldl2t;
        case O::kOpcodeName_fldlg2:   return I::fldlg2;
        case O::kOpcodeName_fldln2:   return I::fldln2;
        case O::kOpcodeName_fldpi:    return I::fldpi;
        case O::kOpcodeName_fld:      return I::fld;
        case O::kOpcodeName_fild:     return I::fild;
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
        case O::kOpcodeName_fst:      return I::fst;
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

bool X87Cache::is_handled(uint16_t op) {
    return is_handled_x87(op);
}

// OPT-KA: TOP deltas match the runtime helpers' actual semantics
// (rosetta_runtime/src/X87.cpp), which push/pop unconditionally — not the
// Intel spec's conditional variants (e.g. hardware fptan skips the push when
// C2 is set; the helper never does).
std::optional<int> X87Cache::runtime_keepalive_top_delta(uint16_t op) {
    switch (op) {
        case kOpcodeName_f2xm1:
        case kOpcodeName_fsin:
        case kOpcodeName_fcos:
        case kOpcodeName_fscale:
        case kOpcodeName_fxam:
        case kOpcodeName_fprem:
        case kOpcodeName_fprem1:
            return 0;
        case kOpcodeName_fptan:
        case kOpcodeName_fsincos:
            return -1;  // helper pushes: TOP = (TOP - 1) & 7
        case kOpcodeName_fyl2x:
        case kOpcodeName_fyl2xp1:
        case kOpcodeName_fpatan:
            return 1;  // helper pops: TOP = (TOP + 1) & 7
        default:
            return std::nullopt;
    }
}

// OPT-RB: gap_gpr_demand — the per-opcode-family peak scratch-GPR demand
// model, and the SINGLE bridging gate — lives in X87BridgeDemand.cpp (built
// by the audit workflow in research/bridge_demand/WORKFLOW.md). A non-nullopt
// return certifies both that the opcode's family audit landed (safe in kind:
// first-free allocations only, no fixed pool slots, no runtime BLs) and that
// this shape's peak demand fits the reduced pool. The former is_transparent
// whitelist is subsumed by it; the audit-eligible opcode set is tracked in
// research/bridge_demand/families.py.

static bool op_disabled_for_run(uint16_t op, uint64_t disabled_ops_mask) {
    if (!disabled_ops_mask)
        return false;
    const auto id = opcode_to_id_local(op);
    return id != OpcodeId::kCount &&
           ((disabled_ops_mask >> static_cast<int>(id)) & 1u);
}

// A run member is a handled+enabled x87 instruction, an OPT-TI value-call
// FCOS (a real member: the IR consumes it as a node, the singular form
// uses x87_begin/x87_end like any handled op), or (OPT-KA) a keepalive
// transcendental — Rosetta translates the latter as a runtime BL that
// preserves the pinned cache GPRs. Shared by lookahead and seam_scan.
static bool x87_run_member(uint16_t op, uint64_t disabled_ops_mask,
                           bool runtime_keepalive) {
    if (g_rosetta_config) {
        if (op == kOpcodeName_fcos && trig_ir_fcos_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fsin && trig_ir_fsin_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fptan && trig_ir_fptan_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fsincos && trig_ir_fsincos_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_f2xm1 && trig_ir_f2xm1_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fscale && trig_ir_fscale_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fyl2x && trig_ir_fyl2x_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fyl2xp1 && trig_ir_fyl2xp1_enabled(*g_rosetta_config))
            return true;
        if (op == kOpcodeName_fpatan && trig_ir_fpatan_enabled(*g_rosetta_config))
            return true;
    }
    if (is_handled_x87(op))
        return !op_disabled_for_run(op, disabled_ops_mask);
    return runtime_keepalive &&
           X87Cache::runtime_keepalive_top_delta(op).has_value();
}

// ── OPT-SEAM ────────────────────────────────────────────────────────────────

bool X87Cache::is_x87_family(uint16_t op) {
    // The contiguous x87 mnemonic cluster (f2xm1..fyl2xp1 — includes the
    // state-observing fsave/fxsave/fldenv/fbld forms and every runtime-routine
    // transcendental), the fcmov+fcomi families that sit outside it
    // (0x25..0x30 — the ONLY x87 mnemonics outside the cluster, verified by
    // enumerating kOpcodeName_f*), and the two MMX-adjacent mnemonics that
    // alias the x87 register file. Anything here must observe correct
    // X87State memory, so a pending seam flushes first.
    static_assert(kOpcodeName_fcmovb < kOpcodeName_fcmovu &&
                      kOpcodeName_fcmovu < kOpcodeName_fcomi &&
                      kOpcodeName_fcomi < kOpcodeName_fucomip &&
                      kOpcodeName_fucomip < kOpcodeName_f2xm1,
                  "x87 out-of-cluster range moved — re-enumerate");
    if (op >= kOpcodeName_f2xm1 && op <= kOpcodeName_fyl2xp1) return true;
    if (op >= kOpcodeName_fcmovb && op <= kOpcodeName_fucomip) return true;
    switch (op) {
        case kOpcodeName_emms:
        case kOpcodeName_movq:  // MMX form aliases st[]/tags; SSE form is
                                // indistinguishable here — flush either way
            return true;
        default:
            return false;
    }
}

// Conservative allowlist: guest instructions that provably cannot touch
// X87State (integer/SSE only — X87State is host thread-context memory, not
// guest-addressable) and cannot leave the block. Anything unknown, any
// control flow, and anything MMX-ambiguous says no — a rejected gap only
// costs the seam, never correctness.
static bool seam_gap_transparent(uint16_t op) {
    switch (op) {
        // Integer moves / address arithmetic / stack ops.
        case kOpcodeName_mov: case kOpcodeName_movzx: case kOpcodeName_movsx:
        case kOpcodeName_movsxd: case kOpcodeName_lea:
        case kOpcodeName_push: case kOpcodeName_pushd: case kOpcodeName_pushw:
        case kOpcodeName_pop: case kOpcodeName_popd: case kOpcodeName_popw:
        case kOpcodeName_xchg: case kOpcodeName_leave:
        case kOpcodeName_cbw: case kOpcodeName_cwde: case kOpcodeName_cdqe:
        case kOpcodeName_cwd: case kOpcodeName_cdq:
        case kOpcodeName_nop: case kOpcodeName_wait:
        // Integer ALU (flag effects irrelevant — only X87State matters here).
        case kOpcodeName_add: case kOpcodeName_sub: case kOpcodeName_and:
        case kOpcodeName_or: case kOpcodeName_xor: case kOpcodeName_test:
        case kOpcodeName_cmp: case kOpcodeName_inc: case kOpcodeName_dec:
        case kOpcodeName_neg: case kOpcodeName_not:
        case kOpcodeName_shl: case kOpcodeName_shr: case kOpcodeName_sar:
        case kOpcodeName_rol: case kOpcodeName_ror:
        case kOpcodeName_imul: case kOpcodeName_mul:
        case kOpcodeName_setcc:
        // SSE scalar/packed moves, arithmetic, converts, compares — XMM/GPR
        // only. movq/movq2dq are NOT here (MMX-ambiguous).
        case kOpcodeName_movss: case kOpcodeName_movsd:
        case kOpcodeName_movaps: case kOpcodeName_movapd:
        case kOpcodeName_movups: case kOpcodeName_movupd:
        case kOpcodeName_movlps: case kOpcodeName_movhps:
        case kOpcodeName_movdqa: case kOpcodeName_movdqu:
        case kOpcodeName_movd:
        case kOpcodeName_addss: case kOpcodeName_addsd:
        case kOpcodeName_subss: case kOpcodeName_subsd:
        case kOpcodeName_mulss: case kOpcodeName_mulsd:
        case kOpcodeName_divss: case kOpcodeName_divsd:
        case kOpcodeName_sqrtss: case kOpcodeName_sqrtsd:
        case kOpcodeName_minss: case kOpcodeName_minsd:
        case kOpcodeName_maxss: case kOpcodeName_maxsd:
        case kOpcodeName_andps: case kOpcodeName_andpd:
        case kOpcodeName_orps: case kOpcodeName_orpd:
        case kOpcodeName_xorps: case kOpcodeName_xorpd:
        case kOpcodeName_shufps: case kOpcodeName_unpcklps:
        case kOpcodeName_pshufd:
        case kOpcodeName_cvtsi2ss: case kOpcodeName_cvtsi2sd:
        case kOpcodeName_cvtss2sd: case kOpcodeName_cvtsd2ss:
        case kOpcodeName_cvtss2si: case kOpcodeName_cvtsd2si:
        case kOpcodeName_cvttss2si: case kOpcodeName_cvttsd2si:
        case kOpcodeName_ucomiss: case kOpcodeName_ucomisd:
        case kOpcodeName_comiss: case kOpcodeName_comisd:
            return true;
        default:
            return false;
    }
}

bool X87Cache::seam_scan(IRInstr* instr_array, int64_t num_instrs,
                         int64_t gap_start, uint64_t disabled_ops_mask,
                         bool runtime_keepalive) {
    constexpr int kMaxSeamGap = 8;
    for (int64_t j = gap_start;
         j < num_instrs && j < gap_start + kMaxSeamGap; j++) {
        const uint16_t op = instr_array[j].opcode();
        if (x87_run_member(op, disabled_ops_mask, runtime_keepalive)) {
            // The successor must be able to CONSUME the seam through the IR
            // pipeline — a run whose build is structurally guaranteed to
            // decline would pay a flush on top of the legacy path, turning
            // the deferral into a net loss:
            //  - a run STARTING with an fcmov has no in-run flag producer
            //    (build_fcmov bails; a consumable cmp/test before it sits
            //    outside the window by definition);
            //  - fnstsw m16 and fld m80 are declined forms.
            if (op >= kOpcodeName_fcmovb && op <= kOpcodeName_fcmovu)
                return false;
            if (op == kOpcodeName_fstsw &&
                instr_array[j].num_operands >= 1 &&
                instr_array[j].operands[0].kind != IROperandKind::Register)
                return false;
            if (op == kOpcodeName_fld &&
                instr_array[j].num_operands >= 1 &&
                instr_array[j].operands[0].kind != IROperandKind::Register &&
                instr_array[j].operands[0].mem.size == IROperandSize::S80)
                return false;
            return true;
        }
        if (!seam_gap_transparent(op)) return false;
    }
    return false;
}

int X87Cache::lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx,
                        uint64_t disabled_ops_mask, bool bridge, bool runtime_keepalive) {
    auto run_member = [&](uint16_t op) {
        return x87_run_member(op, disabled_ops_mask, runtime_keepalive);
    };
    int count = 0;
    int64_t i = insn_idx;
    for (;;) {
        // Consume a maximal group of run-member instructions.
        int group = 0;
        while (i < num_instrs && run_member(instr_array[i].opcode())) {
            i++;
            group++;
        }
        count += group;
        if (!bridge || count == 0)
            break;
        // OPT-RB: cross a short transparent gap, but only when another enabled
        // x87 instruction follows — a trailing gap is never counted, so a run
        // always ends on an x87 instruction (see header comment).
        int gap = 0;
        int64_t j = i;
        while (j < num_instrs && gap < kMaxBridgeGap &&
               gap_gpr_demand(&instr_array[j]).value_or(kMaxBridgeDemand + 1) <=
                   kMaxBridgeDemand) {
            j++;
            gap++;
        }
        if (gap == 0 || j >= num_instrs || !run_member(instr_array[j].opcode()))
            break;
        count += gap;
        i = j;
    }
    // NOTE (2026-07-30): a TRAILING cmp/test extension (count the test after
    // the last member so the run consumes the `fcomp; fnstsw; test` tail)
    // was implemented here and reverted after measurement: +1.2% on
    // bench_fcomp_fnstsw_test. When the test trails the run, the forward
    // NZCV-deadness walk already elides the compare's save/restore, so
    // consumption only duplicates the test into both dual-body copies for
    // zero structural gain. cmp/test still enter windows MID-run (bridge gap
    // followed by more x87), where GuestCmpF consumption avoids a run break
    // and wins big (bench_fcmov −88%).
    return count;
}
