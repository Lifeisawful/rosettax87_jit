#include "rosetta_core/X87Cache.h"

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

// True for FILD m64 (DF /5), FISTP m64 (DF /7) and FISTTP m64 (DD /1) — the
// three encodings that move a full 64-bit integer through an x87 slot.
//
// Our slots are f64 and translate_fild lowers the load as SCVTF Xn -> Dd, so any
// qword with more than 53 significant bits comes back rounded.  Real x87 is
// lossless here: an 80-bit register has a full 64-bit mantissa, which is why the
// encoding exists.  That corrupts memory, not just arithmetic — Delphi's and Free
// Pascal's RTL implement Move() as an x87 block copy ("Pentium memcpy trick"),
// using fild qword / fistp qword purely as an 8-byte courier, so rounding the
// cargo garbles every copy whose qwords exceed 53 significant bits.
//
// Declined by the translator so x87_fild / x87_fist_i64 / x87_fistt_i64 handle
// them instead, keeping an exact int64 shadow.
bool x87_is_m64_int_memop(const IRInstr& ins) {
    switch (ins.opcode()) {
        case Opcode::kOpcodeName_fild:
        case Opcode::kOpcodeName_fistp:
        case Opcode::kOpcodeName_fisttp:
            break;
        default:
            return false;
    }
    const IROperand& op = ins.operands[0];
    if (op.kind != IROperandKind::MemRef && op.kind != IROperandKind::AbsMem)
        return false;
    return op.mem.size == IROperandSize::S64;
}

int X87Cache::lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx,
                        uint64_t disabled_ops_mask, bool bridge, bool runtime_keepalive) {
    // A run member is a handled+enabled x87 instruction, or (OPT-KA) a
    // keepalive transcendental — Rosetta translates the latter as a runtime
    // BL that preserves the pinned cache GPRs.
    auto run_member = [&](const IRInstr& ins) {
        const uint16_t op = ins.opcode();
        // Declined by the translator (see x87_is_m64_int_memop) — keep these out
        // of runs so the cache's run accounting matches what we actually emit.
        if (x87_is_m64_int_memop(ins))
            return false;
        if (is_handled_x87(op))
            return !op_disabled_for_run(op, disabled_ops_mask);
        return runtime_keepalive && runtime_keepalive_top_delta(op).has_value();
    };
    int count = 0;
    int64_t i = insn_idx;
    for (;;) {
        // Consume a maximal group of run-member instructions.
        int group = 0;
        while (i < num_instrs && run_member(instr_array[i])) {
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
        if (gap == 0 || j >= num_instrs || !run_member(instr_array[j]))
            break;
        count += gap;
        i = j;
    }
    return count;
}
