// =============================================================================
// X87BridgeDemand — peak scratch-GPR demand model for OPT-RB bridged gaps.
//
// X87Cache::gap_gpr_demand(instr) predicts the peak number of concurrently
// held first-free scratch GPRs Rosetta's own translate_insn will allocate
// while translating `instr` from the reduced pool (x87 cache pins excluded).
// Underestimating aborts translation ("no temporary GPR available to
// allocate"); overestimating breaks runs that could have been bridged.
//
// The model is built per opcode family from the labeled decompilation
// research/libRosettaAot.dylib.c via the audit workflow in
// research/bridge_demand/WORKFLOW.md. Every demand_<family>() function below
// mirrors the exact allocate/free sequence of the decompiled handler,
// composed from the shared shape helpers, and cites its audit:
// research/bridge_demand/families/<family>/AUDIT.md.
//
// NO GUESSING: std::nullopt means "do not bridge". Every opcode whose family
// audit has not landed refuses outright — all forms, including register and
// immediate ones (the old empirical "2" is gone). The run breaks and Rosetta
// translates the instruction at a run boundary with all 8 scratch GPRs free.
// Bridging coverage is regained exclusively by landing family audits.
//
// This is the SINGLE bridging gate (the former is_transparent whitelist is
// subsumed): a non-nullopt return certifies both kind-safety (the family
// audit verified first-free-only allocation, no fixed pool slots, no runtime
// BLs — the "allocator contract" of
// research/optimizations/01-run-transparent-integers.md) and pressure-fit.
// The audit-eligible opcode set lives in research/bridge_demand/families.py.
//
// PERMANENTLY EXCLUDED — never give these a family (from the whitelist-v2
// binary audit; recorded here because this switch is now the only gate):
//   - segment forms (mov_segment/pop_segment/...): fixed-allocate pool
//     slots 0/1.
//   - string/rep ops, cmpxchg family: fixed slots / runtime BLs.
// test left this list 2026-07-17 (user decision) and bridges via the audited
// test family below — every shape, since the fcom+fnstsw+test fusion (whose
// untick'd tail consumption once forced an fnstsw-adjacency guard in
// lookahead) was removed 2026-07-18.
//
// Execution constraints: this runs inside the lazy-translation hook on the
// guest thread with guest SIMD state live in the host vector registers — no
// SIMD (no __builtin_popcount), no allocation, no static constructors.
// =============================================================================

#include "rosetta_core/X87Cache.h"

#include <optional>

#include "rosetta_core/IRInstr.h"
#include "rosetta_core/Opcode.h"

namespace {

// -----------------------------------------------------------------------------
// Cost / Seq — the composition scheme.
//
// Each Rosetta helper call is modeled as a Cost:
//   peak — max concurrent first-free scratch GPRs live at any point INSIDE
//          the helper (transients included),
//   held — temps still allocated when the helper returns (survivors owned by
//          the caller until an explicit free or the per-instruction epilogue
//          reset, LABEL_705 in the decompilation).
// A family function replays the handler's helper sequence through Seq:
//   step(c):  peak = max(peak, running + c.peak); running += c.held
//   free(n):  running -= n            (explicit free_temporary_gpr calls)
// The final demand is Seq::demand().
//
// Canonical per-helper Costs live in research/bridge_demand/HELPER_COSTS.md
// with decompilation line evidence; the shape helpers below implement that
// table. Audit agents reference the table — they do not re-derive it.
// -----------------------------------------------------------------------------

struct Cost {
    int8_t peak;
    int8_t held;
};

struct Seq {
    int running = 0;
    int peak = 0;
    void step(Cost c) {
        const int p = running + c.peak;
        if (p > peak) peak = p;
        running += c.held;
    }
    void free(int n) { running -= n; }
    int demand() const { return peak; }
};

// ADD/SUB imm12 (optionally LSL #12) encodability of a displacement —
// mirrors disp_encodable in compute_mem_operand_address (decomp 26037-26067).
// Non-encodable displacements cost one materialization temp.
[[maybe_unused]] bool disp_add_encodable(int64_t d) {
    if (d < 0) d = -d;
    if (d <= 0xFFF) return true;
    return (d & 0xFFF) == 0 && (d >> 12) <= 0xFFF;
}

// compute_operand_address (decomp 25845-25977 / compute_mem_operand_address
// 25982-26379). `fresh_dst` = Rosetta passes dst hint XZR, so the address
// result register itself is first-free allocated (held by the caller);
// otherwise the address lands in a caller-provided register.
// Segment overrides and non-64-bit addressing never reach this model — the
// common prefix in gap_gpr_demand refuses them first.
[[maybe_unused]] Cost addr_cost(const IROperand& op, bool fresh_dst) {
    const int8_t result = fresh_dst ? 1 : 0;
    switch (op.kind) {
        case IROperandKind::MemRef: {
            const bool has_base = (op.mem.mem_flags & 1) != 0;
            const bool has_index = (op.mem.mem_flags & 2) != 0;
            if (has_base && has_index)
                // SIB: disp ADD (materialized if non-encodable) + shifted-reg
                // ADD; up to 2 concurrent (decomp 26078-26161).
                return {2, result};
            if (has_index)
                // index-only: shifted index + disp temp (decomp 26215-26304).
                return {2, result};
            if (has_base) {
                if (op.mem.disp == 0)
                    return {0, 0};  // 64-bit base passthrough (decomp 26363-26378)
                if (disp_add_encodable(op.mem.disp))
                    // single ADD imm into result (decomp 26352-26361)
                    return {result, result};
                // materialize disp + ADD reg (decomp 26310-26350)
                return {static_cast<int8_t>(1 + result), result};
            }
            // no base, no index: absolute disp materialization
            return {1, result};
        }
        case IROperandKind::AbsMem:
            // emit_load_immediate_no_xzr into result (decomp 25930-25941)
            return {1, result};
        case IROperandKind::Immediate:
            // RIP-relative/data-page: ADRP+ADD, plus a runtime-add temp when
            // the fixup needs it (decomp 25944-25972) — count the worst case.
            return {2, result};
        default:
            return {0, 0};
    }
}

// alloc_dst_gpr (decomp 27406-27438): architectural register for >=32-bit
// register destinations, one first-free temp otherwise (8/16-bit register
// destinations and all memory destinations). Never freed by the helper.
[[maybe_unused]] Cost alloc_dst_gpr_cost(const IROperand& dst) {
    if (dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64))
        return {0, 0};
    return {1, 1};
}

// read_operand_to_gpr (decomp 26385-26634). `hint_is_arch` = the caller
// passes an architectural destination register (the loaded value does not
// occupy a scratch GPR); otherwise the value register is first-free
// allocated and survives.
[[maybe_unused]] Cost read_to_gpr_cost(const IROperand& src, bool hint_is_arch) {
    switch (src.kind) {
        case IROperandKind::Register:
            // translate_gpr: same-width register passthrough is free; the
            // extend/copy paths allocate one only when the hint is XZR
            // (decomp 26669-26749). Worst case without a hint: 1.
            return hint_is_arch ? Cost{0, 0} : Cost{1, 1};
        case IROperandKind::Immediate:
            // emit_load_immediate materializes into a fresh temp
            // (decomp 26564-26633 / 14394+).
            return hint_is_arch ? Cost{0, 0} : Cost{1, 1};
        case IROperandKind::MemRef:
        case IROperandKind::AbsMem: {
            // value register (fresh unless arch hint) + address transients
            // computed into/around it (decomp 26437-26559).
            const Cost addr = addr_cost(src, /*fresh_dst=*/false);
            if (hint_is_arch)
                return {addr.peak, 0};
            return {static_cast<int8_t>(1 + addr.peak), 1};
        }
        default:
            return {1, 1};
    }
}

// write_gpr_to_operand (decomp 27643-27701): register destinations are free;
// memory destinations compute a fresh store address that is freed right
// after the store. The value register being stored is the caller's.
[[maybe_unused]] Cost write_to_operand_cost(const IROperand& dst) {
    if (dst.kind == IROperandKind::Register)
        return {0, 0};
    const Cost addr = addr_cost(dst, /*fresh_dst=*/true);
    return {addr.peak, 0};
}

// read_xmm_operand_to_fpr GPR side (decomp 26753-26880 / _maybe_alloc
// 26883-26971): register/XMM sources touch no GPR; memory sources allocate
// the address GPR fresh and never explicitly free it (the epilogue reclaims
// it), so it stays held for the rest of the instruction.
[[maybe_unused]] Cost read_xmm_gpr_cost(const IROperand& src) {
    if (src.kind == IROperandKind::Register)
        return {0, 0};
    const Cost addr = addr_cost(src, /*fresh_dst=*/true);
    return {addr.peak, 1};
}

// x86 LOCK is only encodable on the integer RMW group. Within the
// transparent set these are the opcodes whose translation switches to the
// exclusive-loop path when rep_prefix is set (decomp ~20883-22013) — a path
// with its own, higher temp demand that no audit has modeled yet.
bool lockable_rmw(uint16_t op) {
    switch (op) {
        case kOpcodeName_add:
        case kOpcodeName_sub:
        case kOpcodeName_and:
        case kOpcodeName_or:
        case kOpcodeName_xor:
        case kOpcodeName_adc:
        case kOpcodeName_sbb:
        case kOpcodeName_inc:
        case kOpcodeName_dec:
        case kOpcodeName_neg:
        case kOpcodeName_not:
        case kOpcodeName_xchg:
            return true;
        default:
            return false;
    }
}

// =============================================================================
// family: mov-movnti  — kOpcodeName_mov, kOpcodeName_movnti
// Audit: research/bridge_demand/families/mov-movnti/AUDIT.md (2026-07-16)
//
// One handler, translate_mov_movnti (decomp 17760-17820):
//   operands[0] = dst, operands[1] = src
//   read_operand_to_gpr(a1, size==S64, &operands[1], size==S32, hint)
//   write_gpr_to_operand(a1, operands, value)
//
// The source-read hint (decomp 17794-17811) is the architectural dst register
// only when dst is a register of size >= S32; otherwise XZR. With an
// architectural hint the loaded value occupies no scratch GPR.
//
// NOTE (see AUDIT discrepancy flags): a MemRef *source* is read via
// translate_prefetch_impl (decomp 26492), NOT compute_operand_address. When the
// hint is a real (held) value register the prefetch reuses it and allocates
// nothing further; when the hint is XZR (architectural value dst) the prefetch
// first-free allocates exactly one address temp and never frees it. Either way
// the MemRef read peaks at 1 / holds 1. These numbers are traced directly from
// the handler's actual callees, so this section does NOT use the generic
// addr_cost/read_to_gpr_cost helpers (whose HELPER_COSTS-derived MemRef numbers
// differ; both differences are safe over-estimates).
// -----------------------------------------------------------------------------

// translate_prefetch_impl's direct ldr/str-imm fast paths (decomp
// 25613-25627): a [base + disp] access whose displacement encodes as a
// scaled unsigned imm12 (disp >> size_log2 <= 0xFFF, exactly scaled) or a
// signed imm9 (-0x100..0xFF) is emitted as one ldr/str with NO address temp.
// Empirically confirmed by the aotinvoke gpr_demand instrumentation
// (actual=0 on every [rbp +/- small] access in the mov fixtures).
// IROperandSize S8..S64 enum values are the access-size log2 (0..3).
bool ldst_disp_encodable(int64_t disp, IROperandSize size) {
    const int size_log2 = static_cast<int>(size) <= 3 ? static_cast<int>(size) : 3;
    const uint64_t u = static_cast<uint64_t>(disp);
    if ((u >> size_log2) <= 0xFFF && ((u >> size_log2) << size_log2) == u)
        return true;                       // scaled unsigned imm12
    return disp >= -0x100 && disp <= 0xFF; // signed imm9 (ldur/stur)
}

// Address-temp allocations of translate_prefetch_impl with an XZR hint
// (decomp 25520-25840; every alloc is gated on the hint being XZR and lands
// in one register, incl. the non-encodable-disp emit_load_immediate whose
// dst is that same hint reg — decomp 25630/25760).
// SHARED across families: audited in the mov-movnti AUDIT (tightening
// addendum B) and reused by sse-mov-scalar — same callee, same XZR hint
// (26956 load / 27802 store), so the per-shape alloc count is identical.
int mov_prefetch_allocs(const IROperandMemRef& m) {
    const bool has_base = (m.mem_flags & 1) != 0;
    const bool has_index = (m.mem_flags & 2) != 0;
    if (has_base && !has_index)
        return ldst_disp_encodable(m.disp, m.size) ? 0 : 1;
    if (has_base && has_index && m.disp == 0 &&
        (m.shift_amount == 0 ||
         static_cast<int>(m.shift_amount) == static_cast<int>(m.size)))
        // SIB, disp 0, lsl 0 or lsl == access-size log2: direct
        // register-offset ldr/str, no temp (decomp 25812-25819 -> 25839).
        // AUDIT tightening addendum B; instrumented actual=0 at
        // [rsi+rdx*8], [rsi+rdx] load and store.
        return 0;
    if (!has_base && has_index && m.disp == 0 && m.shift_amount == 0)
        // Index-only, no shift, no disp, 64-bit: compute_mem_operand_address
        // returns the index register itself before any allocation gate
        // (26289-26290 `if ( is_64bit ) return scratch_reg;`) — 0 for any
        // hint. (Callers reach here only for addr_size S64; the S32 analog
        // allocates and is priced 1 by the callers' S32 branch.)
        // Instrumented exact: movq/movzbl (,%rcx,1) actual=0.
        return 0;
    // Other SIB / index-only / absolute forms: one addr temp for the
    // shifted-reg ADD chain (verified actual=1 at [rsi + rdx*8 + 0x12345]
    // and [rsi + rdx*4]).
    return 1;
}

// read_operand_to_gpr (decomp 26385-26634) as invoked by this handler.
// hint_is_arch: dst is a register of size >= S32 -> value lands in the
// architectural reg (no scratch held from the value itself).
Cost mov_read_cost(const IROperand& src, bool hint_is_arch) {
    switch (src.kind) {
        case IROperandKind::Register:
            // translate_gpr (decomp 26640-26750): every register source a
            // plain mov can encode passes through (26744-26746) or moves
            // into the arch hint (26748) with no alloc — EXCEPT high-byte
            // sources (AH/CH/DH/BH, encoded class reg>>4 == 1), whose
            // extract block (26666) first-free allocates under an XZR hint
            // (26669-26674). AUDIT tightening addendum A; instrumented:
            // mov cl,al / mov bx,ax actual=0, mov ch,ah actual=1.
            if (!hint_is_arch && (src.reg.reg.value >> 4) == 1)
                return Cost{1, 1};
            return Cost{0, 0};
        case IROperandKind::Immediate:
            // RIP-relative literal source (decomp 26564-26633): ADR-base /
            // value temp (26587) plus, on the unaligned data-page path, a
            // transient runtime-addend temp (25964-25971, freed 25971).
            // Instrumented exact: actual=2 on mov rcx, [text base + i].
            return Cost{2, 1};
        case IROperandKind::MemRef: {
            // MemRef source via translate_prefetch_impl (decomp 26492).
            // XZR hint: the fresh value reg (1, held) doubles as the address
            // hint, so the prefetch allocates nothing further — even for
            // non-encodable disps (emit_load_immediate targets it, 25630).
            // Arch hint: the hint collapses to XZR (26460) and the prefetch
            // allocates only what the addressing shape needs (0 for
            // encodable [base+disp] — instrumented actual=0 on
            // mov rax, [rbp-0x20]). 32-bit addressing skips every prefetch
            // fast path (25578-25588) and computes the address via
            // compute_mem_operand_address into ONE fresh reg — exactly 1
            // for every S32 shape (ADDR32.md).
            if (!hint_is_arch)
                return Cost{1, 1};
            const int8_t a = src.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(src.mem));
            return Cost{a, a};
        }
        case IROperandKind::AbsMem:
            // AbsMem source via compute_operand_address (decomp 26536 ->
            // 25930-25941): emit_load_immediate_no_xzr into a fresh reg.
            return Cost{1, 1};
        default:
            // BranchOffset (plain immediate) source: emit_load_immediate
            // (decomp 26562-26563 / 14394+). Value 0 returns XZR with no
            // alloc (14417-14418; instrumented: mov [rbp-0x40], 0x0
            // actual=0); an arch dst hint absorbs the materialization
            // (instrumented: mov rdx, 0x2 actual=0).
            if (src.branch.value == 0 || hint_is_arch)
                return Cost{0, 0};
            return Cost{1, 1};
    }
}

// write_gpr_to_operand (decomp 27643-27701) as invoked by this handler.
Cost mov_write_cost(const IROperand& dst) {
    switch (dst.kind) {
        case IROperandKind::Register:
            // write_gpr_result (decomp 27692 / 27704-27744): no allocation.
            return Cost{0, 0};
        case IROperandKind::MemRef:
            // MemRef store via translate_prefetch_impl(a6=XZR) (decomp
            // 27700): address temps per addressing shape, 0 for encodable
            // [base+disp] (instrumented actual=0 on every [rbp +/- small]
            // store), not freed (last op; LABEL_705 reclaims). S32
            // addressing: exactly 1 for every shape (ADDR32.md).
            if (dst.mem.addr_size == IROperandSize::S32)
                return Cost{1, 0};
            return Cost{static_cast<int8_t>(mov_prefetch_allocs(dst.mem)), 0};
        case IROperandKind::AbsMem:
            // AbsMem store: compute_operand_address (27681) then
            // free_temporary_gpr (27684). Peak 1, held 0.
            return Cost{1, 0};
        case IROperandKind::Immediate:
            // Immediate (RIP/abs) store target. Aligned: alloc 1, emit_adr,
            // str, free (27668-27684) -> peak 1. Unaligned: compute_operand_address
            // Immediate path holds 2 (ADR result + runtime addend, 25958-25971)
            // then free (27684). Worst case peak 2, held 0.
            return Cost{2, 0};
        default:
            return Cost{0, 0};
    }
}

int demand_mov_movnti(const IRInstr* instr) {
    const IROperand& dst = instr->operands[0];
    const IROperand& src = instr->operands[1];

    // Special path (decomp 17788-17792, 17816-17819): dst is a 16-bit register
    // and src is a BranchOffset -> emit_movn directly, no allocation.
    if (dst.kind == IROperandKind::Register && dst.reg.size == IROperandSize::S16 &&
        src.kind == IROperandKind::BranchOffset)
        return 0;

    // hint_is_arch: dst is a register of size >= S32 (decomp 17807-17811).
    const bool hint_is_arch =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);

    Seq seq;
    seq.step(mov_read_cost(src, hint_is_arch));   // decomp 17803 read_operand_to_gpr
    seq.step(mov_write_cost(dst));                // decomp 17804 write_gpr_to_operand
    return seq.demand();
}

// =============================================================================
// family: lea  — kOpcodeName_lea
// Audit: research/bridge_demand/families/lea/AUDIT.md (2026-07-17)
//
// One handler (decomp 16121-16128), destination is always a register:
//   operands[0] = dst register, operands[1] = memory source
//   is_64bit = operand_size_is_64bit(operands[0])        (16123, Cost {0,0})
//   dst_hint = alloc_dst_gpr(a1, &operands[0])            (16124)
//   addr     = compute_operand_address(a1, is_64bit, &src_copy, dst_hint) (16127)
//              — src_copy forces seg_override=0 (16126)
//   write_gpr_to_operand(a1, &operands[0], addr)          (LABEL_704 15116)
//
// The decisive fact (see AUDIT "Case A / Case B"): compute_operand_address is
// called with a NON-XZR hint (the dst register), so every first-free alloc
// inside it is either skipped (guarded on dst_reg==XZR) or reduced to a single
// TRANSIENT temp that is freed before return (arch-reg hint, Case A), or
// entirely elided via the X22/pool-slot reuse fast path (scratch-reg hint from
// an 8/16-bit dst, Case B). No address survivor is ever returned. Because this
// non-XZR-hint column is out of HELPER_COSTS.md's scope (its
// compute_operand_address rows tabulate the XZR/fresh case), this section
// traces the peaks directly rather than using the generic addr_cost helper —
// see the AUDIT discrepancy flag.
// -----------------------------------------------------------------------------

// compute_operand_address peak when the dst hint is an ARCHITECTURAL register
// (dst size >= S32; Case A). Every path emits into the arch dst; the shapes
// that first materialize a displacement/addend use exactly ONE scratch temp,
// freed before return (decomp 26129 / 26260 / 25971). All other shapes peak 0.
int8_t lea_addr_peak_arch(const IROperand& src) {
    switch (src.kind) {
        case IROperandKind::MemRef: {
            const bool has_base = (src.mem.mem_flags & 1) != 0;   // decomp 26069-26070
            const bool has_index = (src.mem.mem_flags & 2) != 0;
            const bool has_disp = src.mem.disp != 0;              // decomp 26078/26310
            if (has_base && has_index)
                // SIB: LABEL_41 allocs one temp for disp mat / result, freed at
                // 26129 (disp==0 path 26161-26181 allocs nothing).
                return has_disp ? 1 : 0;
            if (has_index)
                // index-only: LABEL_77 disp temp (26235), freed 26260; no-disp
                // paths (bitfield/mov/passthrough 26263-26304) alloc nothing.
                return has_disp ? 1 : 0;
            if (has_base)
                // base+disp: encodable -> single emit_add_imm into arch dst,
                // no temp (26360). Non-encodable -> LABEL_87 temp (26336),
                // freed 26129. disp==0 -> passthrough (26378).
                return (has_disp && !disp_add_encodable(src.mem.disp)) ? 1 : 0;
            // no base/index (disp-only): emit_load_immediate/movn into arch dst
            // (26197-26228), no temp.
            return 0;
        }
        case IROperandKind::AbsMem:
            // emit_load_immediate_no_xzr into arch dst; the dst_reg==XZR alloc
            // (25932-25938) is skipped for the non-XZR hint (decomp 25940).
            return 0;
        case IROperandKind::Immediate:
            // RIP-relative: adr+add into arch dst (25959-25961). The unaligned
            // data-page path adds one transient addend temp, freed 25971.
            return (src.imm.mem_flags & 1) == 0 ? 1 : 0;
        default:
            return 0;
    }
}

int demand_lea(const IRInstr* instr) {
    const IROperand& dst = instr->operands[0];   // decomp 16121-16122
    const IROperand& src = instr->operands[1];   // decomp 16125

    // 32-bit address computation (leal — is_64bit is the DST size, 17711 —
    // and 0x67-prefixed forms) changes NO cost here: with the non-XZR hint
    // this handler always passes, the is_64bit==0 paths of
    // compute_mem_operand_address allocate identically to the 64-bit trace
    // (ADDR32.md; leal matrix variants verify empirically).

    // alloc_dst_gpr (decomp 27406-27438): S32/S64 register dst -> architectural
    // register, {0,0}; <=S16 register dst -> one held scratch temp {1,1}.
    const bool dst_is_arch =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);

    Seq seq;
    if (dst_is_arch) {
        // Case A: arch-reg hint. AD {0,0}; CA holds no survivor, transient
        // peak per shape; WR (Register dst, decomp 27690-27693) {0,0}.
        seq.step(Cost{0, 0});                              // 16124 alloc_dst_gpr
        seq.step(Cost{lea_addr_peak_arch(src), 0});        // 16127 compute_operand_address
    } else {
        // Case B: <=S16 register dst. AD {1,1} (held dst temp); CA reuses that
        // temp via the X22/pool-slot fast path (decomp 26080/26134-26144) for
        // every MemRef/AbsMem shape (all allocs hint-gated) -> {0,0}.
        // EXCEPTION (matrix: leaw 0x100(%rip),%ax actual=2): the Immediate
        // path's runtime-addend transient (25962-25971) is gated on
        // imm.mem_flags bit0, NOT the hint — it allocates on top of the held
        // dst temp. See AUDIT reviewer addendum II.
        seq.step(Cost{1, 1});                              // 16124 alloc_dst_gpr (<=S16)
        if (src.kind == IROperandKind::Immediate && (src.imm.mem_flags & 1) == 0)
            seq.step(Cost{1, 0});                          // 25962-25971 addend transient
        else
            seq.step(Cost{0, 0});                          // 16127 compute_operand_address reuse
    }
    seq.step(Cost{0, 0});                                  // 15116 write_gpr_to_operand (Register)
    return seq.demand();
}

// =============================================================================
// family: sse-mov-scalar  — kOpcodeName_movss, kOpcodeName_movsd
// Audit: research/bridge_demand/families/sse-mov-scalar/AUDIT.md (2026-07-17)
//
// One handler translate_movsd_movss (decomp 40841-40935) for both opcodes; the
// size argument (S16/S8) only picks an FPR opcode variant and never changes any
// free_gpr_mask allocation (AUDIT "SPLIT REQUIRED? — NO"). Three GPR-relevant
// paths, dispatched on the two operand kinds (decomp 40865):
//
//   reg↔reg (op0.kind==0 && op1.kind==0, 40892-40930): translate_vector_low ×2
//            + translate_and_invalidate_vector_low — all FPR-side, 0 GPR.
//   store   (op0.kind!=0, op1.kind==0, 40867-40878): write_fpr_to_mem_operand
//            (40877) then early `return` (40878) — flush tail NOT reached.
//   load    (op0.kind==0, op1.kind!=0, 40879-40890): read_xmm_operand_to_fpr
//            (40881); mark_xmm_written (40890, FPR-side).
//
// Flush tail (40932-40934), reached by reg↔reg and load only, fires when op0 is
// a YMM-class register ((reg & 0xF0)==0x90): flush_xmm_to_thread_context allocs
// one first-free (27105) then frees it (27110) -> Cost {1,0}.
//
// All mem address helpers get the XZR hint (0x1F): translate_prefetch_impl
// (27802 store MemRef / 26956 load MemRef) and compute_operand_address
// (27781 store / 26940 load AbsMem+Immediate). movss/movsd source size is
// S32/S64 so read_xmm_operand_to_fpr's per-kind loop runs a single iteration
// (decomp 26788: v5==2 only for S256). Alignment (operand_addr_is_aligned reads
// the runtime text_base_align_offset, 25516) is NOT IR-decidable, so the
// Immediate paths fold to their peak-2 worst case. These are traced directly
// from the handler's callees (HELPER_COSTS read_xmm row has a line-attribution
// note — see AUDIT discrepancy flag; no cost change), so this section uses
// family-local costs rather than the generic scaffold helpers.
// -----------------------------------------------------------------------------

// write_fpr_to_mem_operand (decomp 27747-27803) GPR cost, by dst kind. All
// paths leave the address temp held (used by the trailing store, never freed).
Cost movs_write_mem_cost(const IROperand& dst) {
    switch (dst.kind) {
        case IROperandKind::MemRef: {
            // translate_prefetch_impl(…, a6=0x1F) (27802): XZR-hint prefetch —
            // exact per-shape count via the shared mov_prefetch_allocs (same
            // callee/hint as the mov family; 0 for encodable [base+disp] and
            // scale-encodable SIB, else 1, never freed). Reviewer addendum in
            // the sse-mov-scalar AUDIT; instrumented actual=0 on every
            // movsd [rbp +/- small] store. S32 addressing: exactly 1 for
            // every shape (ADDR32.md).
            const int8_t a = dst.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(dst.mem));
            return Cost{a, a};
        }
        case IROperandKind::AbsMem:
            // compute_operand_address(…, XZR) AbsMem (27781 -> 25930-25941):
            // emit_load_immediate_no_xzr into the fresh result reg, held.
            return Cost{1, 1};
        case IROperandKind::Immediate:
            // aligned: one first-free alloc (27770), held. unaligned:
            // compute_operand_address Immediate (27781 -> 25944-25972) peaks 2.
            // Alignment not IR-decidable (25516 runtime field) -> peak 2.
            return Cost{2, 1};
        default:
            return Cost{0, 0};
    }
}

// read_xmm_operand_to_fpr (decomp 26753-26880 / _maybe_alloc 26883-26971) GPR
// cost, by src kind. Single loop iteration (S32/S64); FPR temps excluded.
Cost movs_read_xmm_cost(const IROperand& src) {
    switch (src.kind) {
        case IROperandKind::MemRef: {
            // _maybe_alloc kind==1 -> translate_prefetch_impl(…, 0x1F) (26956):
            // exact per-shape count via the shared mov_prefetch_allocs (see
            // movs_write_mem_cost note; instrumented actual=0 on every
            // movsd xmm, [rbp +/- small] load). S32 addressing: exactly 1
            // for every shape (ADDR32.md).
            const int8_t a = src.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(src.mem));
            return Cost{a, a};
        }
        case IROperandKind::AbsMem:
            // _maybe_alloc kind==2 -> LABEL_20 compute_operand_address(…, 0x1F)
            // AbsMem (26940), addr temp held.
            return Cost{1, 1};
        case IROperandKind::Immediate:
            // _maybe_alloc kind==3: aligned first-free adr temp (26929) OR
            // compute_operand_address Immediate (26940) peak 2. Not
            // IR-decidable -> peak 2, held 1.
            return Cost{2, 1};
        default:
            // Register / XMM src (26962-26970): return reg & 0xF, 0 GPR.
            return Cost{0, 0};
    }
}

int demand_sse_mov_scalar(const IRInstr* instr) {
    const IROperand& op0 = instr->operands[0];   // decomp 40859 dst
    const IROperand& op1 = instr->operands[1];   // decomp 40860 src

    // Flush tail fires only for a YMM-class register dst (decomp 40933:
    // (reg & 0xF0) == 0x90) and only on reg↔reg / load paths (store returns
    // early at 40878).
    const bool flush =
        op0.kind == IROperandKind::Register && (op0.reg.reg.value & 0xF0) == 0x90;

    Seq seq;
    if (op0.kind != IROperandKind::Register) {
        // Store direction (decomp 40867-40878): write_fpr_to_mem_operand(op0),
        // then `return` — no flush tail.
        seq.step(movs_write_mem_cost(op0));                // 40877
        return seq.demand();
    }
    if (op1.kind != IROperandKind::Register) {
        // Load direction (decomp 40879-40890): read_xmm_operand_to_fpr(op1),
        // mark_xmm_written (FPR-side, 0 GPR), then flush tail.
        seq.step(movs_read_xmm_cost(op1));                 // 40881
    }
    // else reg↔reg (decomp 40892-40930): translate_vector_low ×2 +
    // translate_and_invalidate_vector_low — all FPR-side, 0 GPR.
    if (flush) {
        // 40934 flush_xmm_to_thread_context: one transient {1,0}. For an
        // Immediate (RIP) source, charge the read's runtime-addend transient
        // as if still held under the total-event convention (alu PEAK-vs-
        // TOTAL note): adr temp held + addend + flush = 3 total events,
        // true concurrent peak 2 (matrix: vmovss 0x100(%rip),%xmm7 actual=3).
        const bool imm_src = op1.kind == IROperandKind::Immediate;
        seq.step(Cost{static_cast<int8_t>(imm_src ? 2 : 1), 0});
    }
    return seq.demand();
}

// =============================================================================
// family: alu-binary  — kOpcodeName_add, _sub, _and, _or, _xor, _cmp
// Audit: research/bridge_demand/families/alu-binary/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. All six share one handler skeleton (translate_add
// 20944, translate_sub 22028, translate_cmp 21110, translate_and 27806,
// translate_or 27995, translate_xor 28289):
//   v11 = alloc_dst_gpr(operands[0])         (cmp: no dst reg; a flag temp
//                                             instead — see below)
//   operand_to_gpr = read_operand_to_gpr(operands[0], …, XZR)   // RMW/read src
//   src branch: Register (emit only) / Immediate (encodable → emit only;
//               non-encodable → a SECOND read_operand_to_gpr(operands[1], XZR))
//               / MemRef|AbsMem (second read_operand_to_gpr)
//   free(second read); free(operand_to_gpr); write_gpr_to_operand(operands[0])
// The differences (arith-imm vs bitmask-imm encodability; cmp's flag temp and
// missing writeback) are IR-decidable SHAPE dimensions, expressed below in ONE
// model — no structural split. The LOCK (rep_prefix==1) mem-RMW exclusive path
// (add 21078 / sub 22169 / and 27873 / or 28077 / xor 28417) is refused by the
// common prefix (lockable_rmw + has_mem + rep_prefix!=0); cmp has no LOCK form
// and never reads rep_prefix.
//
// Shape dimensions (all IRInstr/IROperand fields):
//   dst kind/size  (operands[0]): Register ≥S32 → arch (alloc_dst_gpr {0,0});
//                  Register ≤S16 or MemRef/AbsMem → {1,1} (27417-27424).
//   src kind       (operands[1]): whether a SECOND read fires and its cost.
//   imm encodability: add/sub/cmp = ADD-imm12(-shifted) of value or -value
//                  (21030-21075); and/or/xor = is_bitmask_immediate (27918 /
//                  28114 / 28386). Non-encodable ⇒ second read.
//
// PEAK vs verify's TOTAL-EVENT actual: for a MEMORY destination the handler
// frees operand_to_gpr (and the second-read temp) BEFORE write_gpr_to_operand
// allocates the store-address temp (add 21017→21018), so the true concurrent
// PEAK is 3 while verify (frees neutered) counts 4 total events. We model the
// conservative 4 for the mem-dst path (keep operand_to_gpr held across the
// write) — a safe over-estimate ≤ kMaxBridgeDemand, matching verify's actual.
//
// Matrix reconciliation (2026-07-17), see AUDIT.md "Matrix reconciliation":
//  - register reads via translate_gpr allocate iff extend_mode!=0 OR the reg is
//    a high-byte (class 1, reg>>4==1) — NOT simply "any non-64-bit reg". The
//    per-opcode extend_mode is a flag_liveness function (below), IR-decidable.
//  - Immediate-kind (RIP/data-page) operands: a read costs {2,1} (adr+addend),
//    an Immediate *writeback* peaks 2 → an Immediate RMW dst (add/sub/and/or/
//    xor) totals 5 + src-read events (honest, matrix-measured 5; over the
//    bridging ceiling, rejected by the callers). cmp (no writeback) Immediate
//    lhs stays at 2. Immediate src second-read costs 2.
//  - xor self-zero idiom (op0==op1 register, 28344) takes a read-free/alloc-
//    free fast path ⇒ demand 0.
// -----------------------------------------------------------------------------

// A register operand's encoded size class is reg.reg >> 4 (26661 `v7 = reg>>4`).
// MATRIX-RECONCILED encoding (empirically graded from the register bytes the IR
// carries — see AUDIT.md "Matrix reconciliation"):
//   class 0 = 8-bit low (AL..DIL), class 1 = 8-bit high (AH/CH/DH/BH),
//   class 2 = 16-bit, class 3 = 32-bit, class 4 = 64-bit.
// translate_gpr (26640-26750) first-free allocates for a read under an XZR hint:
//   class 1 (high byte)  → ALWAYS (26666 `v7 == 1` extract block; XZR alloc 26669)
//   class 0 / class 2    → iff extend_mode != 0 (26666 `!v8` for class 0;
//                          26688 `v7 == 2` for 16-bit; XZR alloc 26714)
//   class 3 (32-bit)     → iff extend_mode != 0 AND is_64bit (26721
//                          `extend_mode && a2==1 && v7==3`; XZR alloc 26728)
//   class 4 (64-bit)     → NEVER (no v7==4 alloc branch; 26744 passthrough)
bool alu_reg_read_allocs(const IROperand& regop, bool em_nonzero, bool is_64bit) {
    const unsigned cls = regop.reg.reg.value >> 4;           // 26661 v7
    if (cls == 1) return true;                               // high byte: always
    if (!em_nonzero) return false;                           // 26744 passthrough
    if (cls == 0 || cls == 2) return true;                   // 8L/16: 26666/26688
    if (cls == 3) return is_64bit;                           // 32-bit: 26721 a2==1
    return false;                                            // 64-bit: never
}

// AArch64 logical (bitmask) immediate encodability — faithful port of
// is_bitmask_immediate (decomp 3552-3615), pure arithmetic, no allocation.
// and/or/xor take the emit_*_imm (no second read) path iff this returns true.
bool alu_is_bitmask_immediate(bool is_64bit, uint64_t value) {
    unsigned i;                                            // 3554
    if (is_64bit) {                                        // 3563
        if (value + 1 < 2) return false;                  // 3565-3570
        i = 0x40;                                          // 3567
    } else {
        if ((uint32_t)(value + 1) < 2) return false;       // 3572-3573
        value = (uint32_t)value;                           // 3574
        i = 0x20;                                          // 3575
    }
    bool cont;                                             // 3576-3591 shrink loop
    do {
        unsigned v4 = i >> 1;                              // 3579
        i &= ~1u;                                          // 3580
        if ((((value >> v4) ^ value) & ~(0xFFFFFFFFFFFFFFFFULL << v4)) != 0) {  // 3581
            cont = false;                                  // 3583
        } else {
            i = v4;                                        // 3587
            cont = v4 > 2;                                 // 3588
        }
    } while (cont);
    uint64_t v6 = 0xFFFFFFFFFFFFFFFFULL >> (unsigned)(-(char)i);   // 3592
    uint64_t v7 = v6 & value;                             // 3593
    if (v7 != 0 && ((((v7 - 1) | v7) + 1) & ((v7 - 1) | v7)) == 0) {  // 3594
        // ones-run form encodable
        return true;                                      // 3595-3598
    }
    v7 = v6 & ~value;                                     // 3601
    if (v7 == 0 || ((((v7 - 1) | v7) + 1) & ((v7 - 1) | v7)) != 0)   // 3602
        return false;                                     // 3603
    return true;                                          // 3604-3614 (encodable)
}

// add/sub/cmp ADD-imm12(-shifted) encodability of the immediate src — mirrors
// translate_add 21030-21075 (value >= 0x1000 && (value & ~0xFFF000)!=0 →
// negate; if still non-encodable → LABEL_48 second read). Value or -value must
// fit imm12 (<0x1000) or imm12<<12 ((v & 0xFFFFFFFFFF000FFF)==0).
bool alu_addimm_encodable(uint64_t value) {
    if (value < 0x1000) return true;                      // 21031 (else branch)
    if ((value & 0xFFFFFFFFFF000FFFULL) == 0) return true; // 21033/21055 shifted
    uint64_t neg = (uint64_t)(-(int64_t)value);           // 21035 value = -value
    if (neg < 0x1000) return true;                        // 21036 (else)
    if ((neg & 0xFFFFFFFFFF000FFFULL) == 0) return true;   // 21038 shifted
    return false;                                         // 21039/21036→LABEL_48
}

// read_operand_to_gpr of an operand, XZR hint (decomp 26385-26634). The value
// register is first-free allocated (held) for mem/abs/imm sources; a Register
// source allocates only per alu_reg_read_allocs (translate_gpr, 26436). em_nonzero
// = this handler's extend_mode argument is nonzero.
Cost alu_read_cost(const IROperand& op, bool em_nonzero, bool is_64bit) {
    switch (op.kind) {
        case IROperandKind::Register:
            return alu_reg_read_allocs(op, em_nonzero, is_64bit) ? Cost{1, 1}
                                                                 : Cost{0, 0};
        case IROperandKind::MemRef:
        case IROperandKind::AbsMem:
            // 26440-26492 / 26498-26558: value reg first-free (held), addr folds
            // into it (S32: 1 via compute_mem_operand_address, ADDR32.md).
            return Cost{1, 1};
        case IROperandKind::Immediate:
        case IROperandKind::BranchOffset:
            // Immediate (RIP/data-page) read (26564-26633): adr-base/value temp
            // (26587, held) + an optional runtime-addend temp on the unaligned
            // path (freed 25971) → peak 2, held 1. HELPER_COSTS Immediate row.
            // A BranchOffset (plain literal) value==0 returns XZR, else 1
            // (emit_load_immediate 14417/14420).
            if (op.kind == IROperandKind::Immediate)
                return Cost{2, 1};
            return op.branch.value == 0 ? Cost{0, 0} : Cost{1, 1};
        default:
            return Cost{1, 1};
    }
}

// write_gpr_to_operand(operands[0]) (27643-27701): Register dst → 0; mem dst →
// store-address temp (mov_prefetch_allocs for MemRef; 1 for S32/AbsMem/Imm),
// freed after the store (27684) — but see the PEAK-vs-TOTAL note: for mem dst
// we keep operand_to_gpr held across this step, so `held` here is not decremented.
Cost alu_write_op0_cost(const IROperand& dst) {
    switch (dst.kind) {
        case IROperandKind::Register:
            return Cost{0, 0};                             // 27692 write_gpr_result
        case IROperandKind::MemRef: {
            const int8_t a = dst.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(dst.mem));
            return Cost{a, 0};                             // 27700 translate_prefetch_impl
        }
        case IROperandKind::AbsMem:
            return Cost{1, 0};                             // 27681-27684
        case IROperandKind::Immediate:
            return Cost{2, 0};                             // 27668-27684 (unaligned peak 2)
        default:
            return Cost{0, 0};
    }
}

// Per-opcode extend_mode-nonzero: whether the read_operand_to_gpr extend_mode
// argument this handler passes is nonzero (⇒ register reads allocate).
//   add   21001: v10 = 2*((fl & (OF|CF))!=0)
//   sub   22087: v10 = 2*((fl & 0x70)!=0)            (OF|CF|ZF)
//   cmp   21157: v11 = 2*((fl & (OF|CF|ZF))!=0)
//   or    28022-28044: v6  = 2 iff SF live, else 0
//   xor   28364-28378: v13 = 2 iff SF live, else 0
//   and   27837-27850: v7  = 0 if fl<OF or (BranchOffset src & sign-bit clear),
//                              else 1 (SF dead) / 2 (SF live)
bool alu_extend_nonzero(uint16_t op, const IRInstr* instr, const IROperand& src) {
    const uint8_t fl = instr->flag_liveness;
    switch (op) {
        case kOpcodeName_add:
            return (fl & (FLAG_OF | FLAG_CF)) != 0;                 // 20990
        case kOpcodeName_sub:
        case kOpcodeName_cmp:
            return (fl & (FLAG_OF | FLAG_CF | FLAG_ZF)) != 0;       // 22077 / 21155
        case kOpcodeName_or:
        case kOpcodeName_xor:
            return (fl & FLAG_SF) != 0;                             // 28031 / 28364
        case kOpcodeName_and: {
            if (fl < FLAG_OF) return false;                         // 27841 LABEL_6
            // 27842: BranchOffset src with the sign bit clear also forces v7=0.
            if (src.kind == IROperandKind::BranchOffset &&
                (static_cast<uint64_t>(src.branch.value) & 0x8000000000000000ULL) == 0)
                return false;                                       // 27842
            return true;                                            // 27847-27850 (1 or 2)
        }
        default:
            return false;
    }
}

int demand_alu_binary(const IRInstr* instr) {
    const IROperand& dst = instr->operands[0];   // add 20971 / cmp 21129
    const IROperand& src = instr->operands[1];   // add 21002 / cmp 21158
    const uint16_t op = instr->opcode();
    const bool is_cmp = (op == kOpcodeName_cmp);
    const bool logical = (op == kOpcodeName_and || op == kOpcodeName_or ||
                          op == kOpcodeName_xor);

    // operand size = operands[0].reg.size (add 20980 / cmp 21140). is_64bit
    // gates translate_gpr passthrough and imm width.
    const bool is_64bit = dst.reg.size == IROperandSize::S64;   // 21000/21156

    // xor self-zero idiom: op0 and op1 are the SAME register (28344
    // `operands[0].reg.reg == reg`) → a read-free / alloc-free fast path
    // (28444-28489, emit_movn/emit_logical_imm only). Demand 0.
    if (op == kOpcodeName_xor && dst.kind == IROperandKind::Register &&
        src.kind == IROperandKind::Register &&
        dst.reg.reg.value == src.reg.reg.value)                    // 28343-28344
        return 0;

    const bool dst_is_mem = dst.kind == IROperandKind::MemRef ||
                            dst.kind == IROperandKind::AbsMem;
    const bool dst_is_arch_reg =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);

    const bool em_nonzero = alu_extend_nonzero(op, instr, src);

    // Does a SECOND read_operand_to_gpr(operands[1]) fire, and what does it cost?
    //  - add/sub/cmp Register src: NO read (emit_*_ext_reg branch: add 21002-21019
    //    / sub 22088-22104 / cmp 21158-21172).
    //  - and/or/xor Register src: YES — read_operand_to_gpr(op1) (and 27929 /
    //    or 28127 / xor 28392).
    //  - Immediate src: read only when NOT imm-encodable for this opcode.
    //  - MemRef/AbsMem src: always a read (add LABEL_48 21024 / cmp LABEL_26 21177).
    bool second_read = false;
    switch (src.kind) {
        case IROperandKind::MemRef:
        case IROperandKind::AbsMem:
            second_read = true;                            // 21024 / 21177
            break;
        case IROperandKind::Register:
            // and/or/xor: ALWAYS read the reg src (27929 / 28127 / 28392).
            // add/sub/cmp: read (LABEL_48 / LABEL_26) only when `reg > 0xF` and
            // NOT the 16-bit fast branch: 21005/21160 `(reg&0xF0)==0x20` (class 2
            // = 16-bit) → inline emit_*_shifted_reg (no read); class 0 (8-bit low,
            // reg ≤ 0xF) → inline; classes 1 (8-bit high), 3 (32-bit), 4 (64-bit)
            // → LABEL_48/LABEL_26 read. Only a high-byte (class 1) src actually
            // ALLOCATES on that read (alu_reg_read_allocs); 32/64-bit pass through.
            if (logical) {
                second_read = true;
            } else {
                const unsigned cls = src.reg.reg.value >> 4;   // 21004/21160
                second_read = (cls != 0 && cls != 2);          // reg>0xF, not 16-bit
            }
            break;
        case IROperandKind::Immediate:
            // RIP/data-page MEMORY operand, not a plain literal: the handlers'
            // imm branches gate on kind == BranchOffset (add 21021 `if (
            // insn->operands[1].kind != BranchOffset )` -> LABEL_48; and
            // 27918), so an Immediate-kind src ALWAYS takes the second read
            // (cost {2,1}). Matrix: addq/subq/cmpq 0x100(%rip),%rcx actual=2
            // — value-encodability of the fixup field must not be consulted.
            second_read = true;
            break;
        case IROperandKind::BranchOffset: {
            const uint64_t v = static_cast<uint64_t>(src.imm.value);
            const bool encodable = logical ? alu_is_bitmask_immediate(is_64bit, v)
                                            : alu_addimm_encodable(v);
            second_read = !encodable;                      // 27918 / 21030-21075
            break;
        }
        default:
            break;
    }

    // Immediate-kind (RIP/data-page) RMW *destination* for the five writeback
    // opcodes: honest event total — alloc_dst {1} + op0 read {2 events, the
    // freed addend transient counts} + the src second-read's events +
    // Immediate write {2 events} (27668-27684). Matrix-measured:
    // addq %rax,0x100(%rip) actual=5. The Seq below cannot express this shape
    // (its peak forgets the op0 read's freed transient), so compose the events
    // directly; callers reject totals over the bridging ceiling. cmp has no
    // writeback and stays on the Seq path (Immediate lhs peak 2, exact).
    if (!is_cmp && dst.kind == IROperandKind::Immediate) {
        const int src_events =
            second_read ? alu_read_cost(src, em_nonzero, is_64bit).peak : 0;
        return 5 + src_events;
    }

    Seq seq;

    // 1) dst-slot allocation. cmp allocates no writeback register; instead it
    //    conditionally allocates ONE flag temp v9 (21147-21151) when
    //    size <= S16 AND a flag bit in (AF|PF_LO|OF|SF|CF) is live. add/sub/
    //    and/or/xor call alloc_dst_gpr (add 20991 / and 27869): arch reg → {0,0},
    //    ≤S16 reg or mem/imm → {1,1}.
    if (is_cmp) {
        const bool cmp_small =
            dst.kind == IROperandKind::Register && dst.reg.size <= IROperandSize::S16;
        const uint8_t fl = instr->flag_liveness;
        const uint8_t mask = static_cast<uint8_t>(FLAG_AF | FLAG_PF_LO | FLAG_OF |
                                                  FLAG_SF | 0x1);       // 21141
        const bool cmp_flag_temp = cmp_small && (fl & mask) != 0;       // 21141-21151
        seq.step(Cost{static_cast<int8_t>(cmp_flag_temp ? 1 : 0),
                      static_cast<int8_t>(cmp_flag_temp ? 1 : 0)});
    } else if (dst_is_arch_reg) {
        seq.step(Cost{0, 0});                              // 27426-27435 arch reg
    } else {
        seq.step(Cost{1, 1});                              // 27417-27424 held temp
    }

    // 2) read_operand_to_gpr(operands[0], …, XZR) — the RMW/compared value.
    seq.step(alu_read_cost(dst, em_nonzero, is_64bit));    // add 21001 / cmp 21157

    // 3) the SECOND read (operands[1]) when it fires; freed before writeback
    //    (add 21027 / and 27935) — so for the register-dst case we drop it.
    if (second_read) {
        seq.step(alu_read_cost(src, em_nonzero, is_64bit)); // add 21024 / and 27929
        if (!dst_is_mem)
            seq.free(1);                                   // add 21027 free(v27)
    }

    // 4) cmp has NO writeback (21213-21216 flag writeback only, no alloc).
    //    add/sub/and/or/xor: free(operand_to_gpr) then write_gpr_to_operand.
    //    For a mem dst we deliberately KEEP operand_to_gpr held across the
    //    write (PEAK-vs-TOTAL note) → conservative 4 when the second read fired.
    if (!is_cmp) {
        if (!dst_is_mem)
            seq.free(1);                                   // add 21017 free(operand_to_gpr)
        seq.step(alu_write_op0_cost(dst));                 // add 21018 write_gpr_to_operand
    }

    return seq.demand();
}

// =============================================================================
// family: adc-sbb  — kOpcodeName_adc, kOpcodeName_sbb
// Audit: research/bridge_demand/families/adc-sbb/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. Two handlers (translate_adc 20839-20941, translate_sbb
// 21925-22025) with parallel skeletons over the SAME shared helpers used by
// alu-binary (alloc_dst_gpr / read_operand_to_gpr(...,XZR) / write_gpr_to_operand
// / emit_flag_writeback). One model keyed on opcode + shape (push-pop / alu-unary
// precedent). Differences are IR-decidable:
//   adc (non-LOCK 20919-20940): read op0 always (20922); a SECOND read of op1
//        (20928) fires UNLESS flag_liveness==0 && op1==BranchOffset && value==0
//        (20926 else-branch, the `adc r,0` all-dead fast path). Both reads freed
//        (20931/20937) before write (20938).
//   sbb non-aliased (21967 false→21968): read op0 (21974) AND op1 (21975), both
//        freed (22019-22020) before write (22021).
//   sbb aliased `sbb r,r` (21967 true→else 22013): both value regs forced XZR
//        (22015-22016), NO reads — just alloc_dst_gpr(op0 reg) + write reg.
//
// em (read extend_mode) = 2*((fl & (OF|CF))!=0) for BOTH (adc 20881 / sbb 21969,
// 0x30 = OF|CF) — em_nonzero only makes a Register src of class 0/2/3 allocate a
// read temp (high-byte class 1 always does; alu_reg_read_allocs).
//
// PEAK vs verify TOTAL-EVENT: both free the read temps before write allocates
// its store-address temp. For a REGISTER dst peak==total. For a MEMORY dst the
// freed reads still count toward verify's neutered-free total, so — like
// alu-binary/alu-unary — the model KEEPS the reads held across the write (no
// free) for mem dsts, so the composed peak equals verify's total.
//
// Immediate-kind (RIP) RMW dst (priced FIRST, by event total): alloc_dst {1} +
// read op0 {2 events} + src second-read events + Immediate write {2 events} =
// 5 + src_events (alu-binary-identical; over the ceiling, callers reject). The
// Seq peak forgets read op0's freed addend transient, so this shape is composed
// as an event total directly.
//
// DISPOSITIONS. rep_prefix (20883/21966/21970/22013): rep_prefix==1 selects the
// mem-store exclusive LOCK path (adc 20884 / sbb 21978), whose
// compute_operand_address on a Register operands[0] asserts (25945) — so
// LOCK+register is malformed and LOCK+mem is already refused by the common
// prefix (lockable_rmw). The family REFUSES rep_prefix==1 outright.
// flag_liveness: OF|CF via em (Register-src read temp) and, for adc, any-nonzero
// forces the second read (20926) — both IR-decidable and modeled. emit_flag_
// writeback (24760-24790) is emit-only (no __clz/free_gpr_mask). GS fixed-slot-7
// / get_tls_base BL (25901-25906) live behind seg_override, refused by the common
// prefix. X22 read fast paths (26440/26500/26566) never fire (hint is XZR).
// Table v3.1; discrepancy flags: NONE.
// -----------------------------------------------------------------------------

int demand_adc_sbb(const IRInstr* instr) {
    const uint16_t op = instr->opcode();          // adc 0x4 / sbb 0x5C
    const IROperand& dst = instr->operands[0];    // RMW dst (20862/21945)
    const IROperand& src = instr->operands[1];    // src (20924/21965)
    const uint8_t fl = instr->flag_liveness;      // 20870 / 21953

    // operand size = operands[0].reg.size (20871 / 21954). is_64bit gates the
    // Register-read translate_gpr passthrough width.
    const bool is_64bit = dst.reg.size == IROperandSize::S64;   // 20871/21954

    // Read extend_mode nonzero ⇔ (OF|CF) live (adc 20881 / sbb 21969, 0x30).
    const bool em_nonzero = (fl & (FLAG_OF | FLAG_CF)) != 0;

    const bool dst_is_mem = dst.kind == IROperandKind::MemRef ||
                            dst.kind == IROperandKind::AbsMem;
    const bool dst_is_arch_reg =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);

    // sbb aliasing fast path: operands[0] and operands[1] are BOTH registers
    // AND the SAME register (`sbb %eax,%eax`) — no reads, just alloc_dst + write
    // (21967 `op0.kind | op1.kind || op0.reg.reg != op1.reg.reg` false → 22013).
    const bool sbb_aliased =
        op == kOpcodeName_sbb &&
        dst.kind == IROperandKind::Register &&
        src.kind == IROperandKind::Register &&
        dst.reg.reg.value == src.reg.reg.value;   // 21967

    // Does the SECOND read of operands[1] fire?
    //   sbb non-aliased: ALWAYS (21974-21975 unconditional).
    //   adc: fires UNLESS fl==0 && src==BranchOffset && src.value==0 (20926
    //        else-branch: `if (flag_liveness || op1.kind != BranchOffset ||
    //        op1.branch.value)`).
    //   sbb aliased: NO reads at all (handled below).
    bool second_read;
    if (op == kOpcodeName_sbb) {
        second_read = !sbb_aliased;               // 21974-21975 (else: 22013 XZR)
    } else {
        second_read = fl != 0 ||
                      src.kind != IROperandKind::BranchOffset ||
                      src.branch.value != 0;      // 20926
    }

    // Immediate-kind (RIP/data-page) RMW dst: honest event total (see header).
    // alloc_dst {1} + read op0 {2 events} + src second-read events + write {2}.
    // Cannot be the sbb-aliased shape (aliasing needs a Register dst). Priced
    // FIRST — the Seq below cannot express it (forgets read op0's freed addend).
    if (dst.kind == IROperandKind::Immediate) {   // 27668-27684 write peak 2
        const int src_events =
            second_read ? alu_read_cost(src, em_nonzero, is_64bit).peak : 0;
        return 5 + src_events;                     // alloc_dst 1 + read op0 2 + write 2
    }

    Seq seq;

    if (sbb_aliased) {
        // 21964 alloc_dst_gpr(op0 register): arch ≥S32 → {0,0}; ≤S16 → {1,1}.
        // Both value regs are XZR (22015-22016), write to a Register is free.
        seq.step(dst_is_arch_reg ? Cost{0, 0} : Cost{1, 1});   // 21964
        seq.step(Cost{0, 0});                                  // 22021 write reg
        return seq.demand();
    }

    // 1) alloc_dst_gpr(operands[0]) — adc 20882 / sbb 21964. Arch reg ≥S32 →
    //    {0,0} (27435); ≤S16 reg or mem/imm dst → {1,1} (27417-27424).
    seq.step(dst_is_arch_reg ? Cost{0, 0} : Cost{1, 1});       // 20882 / 21964

    // 2) read_operand_to_gpr(operands[0], em, XZR) — the RMW value (adc 20922 /
    //    sbb 21974). Same helper/hint as alu-binary → alu_read_cost.
    seq.step(alu_read_cost(dst, em_nonzero, is_64bit));        // 20922 / 21974

    // 3) the SECOND read of operands[1] when it fires (adc 20928 / sbb 21975),
    //    freed before the write (adc 20931 / sbb 22020). For a MEMORY dst we KEEP
    //    the reads held across the write (PEAK-vs-TOTAL) so the peak == verify's
    //    total-event count.
    if (second_read) {
        seq.step(alu_read_cost(src, em_nonzero, is_64bit));    // 20928 / 21975
        if (!dst_is_mem)
            seq.free(1);                                       // 20931 / 22020 free op1
    }

    // 4) free(operand_to_gpr) then write_gpr_to_operand(operands[0]) (adc
    //    20937-20938 / sbb 22019+22021). Mem dst: keep op0 held (PEAK-vs-TOTAL).
    if (!dst_is_mem)
        seq.free(1);                                           // 20937 / 22019 free op0
    seq.step(alu_write_op0_cost(dst));                         // 20938 / 22021

    // 5) emit_flag_writeback (20940 / 22024) — emit-only, 0 alloc.
    return seq.demand();
}

// =============================================================================
// family: movzx-movsx-movsxd  — kOpcodeName_movzx, _movsx, _movsxd
// Audit: research/bridge_demand/families/movzx-movsx-movsxd/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. Two case groups share one allocation skeleton; the
// ONLY difference is the read_operand_to_gpr extend_mode argument v49
// (movsx/movsxd: 2, decomp 16319; movzx: 1, decomp 16328), and that argument
// changes NO first-free allocation on any reachable path (proof below), so a
// single model covers all three opcodes.
//
// Handler skeleton (case_slice.c; both groups, goto tails LABEL_584/704/705
// inlined):
//   v44 = operand_size_is_64bit(dst.kind, dst.reg.size)   (16314/16324) {0,0}
//         — returns dst.reg.size == S64 (17711); pure, no alloc.
//   v45 = alloc_dst_gpr(a1, &operands[0])                 (16315/16325)
//   v264 = read_operand_to_gpr(a1, v44, &operands[1], v49, v45)  (16331 LABEL_584)
//   write_gpr_to_operand(a1, &operands[0], v264)          (15116 LABEL_704)
//
// KEY FACT: the destination (operands[0]) of movzx/movsx/movsxd is ALWAYS a
// Register (r16/r32/r64) — x86 has no memory destination for these opcodes.
// So the read hint v45 = alloc_dst_gpr(dst) is NEVER XZR: it is either the
// architectural dst register (dst size ≥ S32 -> reg & 0xF, 27427-27435) or a
// freshly-allocated held scratch (dst size == S16, LABEL_2 27418-27423). This
// non-XZR hint is decisive: in read_operand_to_gpr every value/address alloc
// gated on `hint == XZR` is skipped, and the loaded value lands in the hint
// register rather than a fresh temp.
//
//   * Register source (translate_gpr 26436 -> 26640-26750): with a non-XZR
//     hint EVERY class passes through with NO alloc — the class-0/1 extract
//     block (26666) allocs only under `hint == XZR` (26669); the 16-bit block
//     (26688) and the 32-bit block (26721, movsxd) likewise alloc only under
//     `hint == XZR` (26690/26723). So a register source costs {0,0} regardless
//     of extend_mode. (This is why movzx vs movsx does not split.)
//   * MemRef source (26440-26493): value lands in the hint (v5=v45), address
//     computed by translate_prefetch_impl with hint v13. Arch hint (dst ≥ S32):
//     pool-search fails -> v13 = XZR (26468) -> prefetch allocs the address
//     temp fresh = mov_prefetch_allocs (0 encodable / 1 non-encodable-SIB), 1
//     for S32 addressing (ADDR32.md), never freed -> {a,a}. Scratch hint
//     (dst == S16): the held scratch is in the pool -> v13 = hint (26470) ->
//     every prefetch alloc gated on v13==XZR is skipped, even for non-encodable
//     disp (emit_load_immediate targets v13, 25630) -> {0,0}.
//   * AbsMem source (26498-26558): compute_operand_address(op, v15). Arch hint:
//     v15 = XZR (26521/26528) -> emit_load_immediate_no_xzr into a fresh temp
//     (25932-25940), held -> {1,1}. Scratch hint: v15 = hint (26531) -> loads
//     into hint (25940 non-XZR), no alloc -> {0,0}.
//   * write_gpr_to_operand (27690-27693): Register dst -> write_gpr_result,
//     {0,0} always.
//
// Net peak demand: 0 (reg->reg with arch dst; encodable [base+disp] mem read
// with arch dst) up to 1 (any mem source with arch dst; ANY source with a
// 16-bit dst, whose alloc_dst_gpr temp is the peak). NEVER refused: no
// fixed-slot alloc is reachable (25901 GS path lives behind seg_override,
// refused by the common prefix), no runtime BL, every shape IR-decidable,
// max demand 1 <= kMaxBridgeDemand.
//
// DISPOSITIONS: rep_prefix — no access anywhere in the case bodies (16312-16336)
// or the helper closure; movzx/movsx/movsxd have no LOCK form. flag_liveness —
// no access; extend_mode is a hardcoded constant (v49), not flag-derived; these
// opcodes set no flags. addr_size (S32) — handled by mov_prefetch_allocs's S32
// branch (arch-hint mem read = 1) and folds to {0,0} under a scratch hint.
// X22 fast paths (26440/26500) — modeled via the allocating (non-X22) path per
// HELPER_COSTS caveat 1; they only ever reduce demand, never raise it.
// -----------------------------------------------------------------------------

// read_operand_to_gpr(&operands[1], v49, hint=alloc_dst_gpr result) as invoked
// by this family. hint_is_arch = dst is a register of size >= S32 (the hint is
// the architectural dst reg); otherwise the hint is a held scratch (dst S16)
// that the read reuses, adding nothing.
Cost movext_read_cost(const IROperand& src, bool hint_is_arch) {
    switch (src.kind) {
        case IROperandKind::Register:
            // translate_gpr (26436 -> 26640-26750): non-XZR hint -> every class
            // passes through, no alloc, for extend_mode 1 (movzx) or 2 (movsx/
            // movsxd). See the section header proof (26666/26688/26721 gates).
            return Cost{0, 0};
        case IROperandKind::MemRef: {
            // translate_prefetch_impl (26492). Scratch hint (S16 dst): the held
            // value reg doubles as the address hint (v13=hint), every prefetch
            // alloc gated on v13==XZR is skipped -> {0,0}. Arch hint: v13=XZR
            // (26468) -> one fresh address temp per shape (mov_prefetch_allocs;
            // S32 addressing forces 1 via compute_mem_operand_address,
            // ADDR32.md), held (never freed).
            if (!hint_is_arch)
                return Cost{0, 0};
            const int8_t a = src.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(src.mem));
            return Cost{a, a};
        }
        case IROperandKind::AbsMem:
            // compute_operand_address (26536). Arch hint -> v15=XZR ->
            // emit_load_immediate_no_xzr into a fresh temp (25932-25940), held.
            // Scratch hint -> v15=hint -> loads into hint, no alloc (25940).
            return hint_is_arch ? Cost{1, 1} : Cost{0, 0};
        default:
            // Immediate-kind (RIP/data-page) sources DO occur — movzx/movsx
            // from a RIP-relative global is common codegen. read_operand_to_gpr
            // Immediate path (26564-26633): {2,1} with an arch hint (adr-base
            // temp + runtime-addend transient); with a scratch hint the adr
            // base reuses the hint but the addend transient still allocates ->
            // {1,1} on top of the held dst temp (composed peak 2). Both
            // empirically exact (matrix: movzbl/movswl/movslq 0x100(%rip)
            // actual=2 arch; movzbw 0x100(%rip),%dx actual=2 S16). See AUDIT
            // reviewer addendum. BranchOffset cannot occur (no imm forms).
            return hint_is_arch ? Cost{2, 1} : Cost{1, 1};
    }
}

int demand_movzx_movsx_movsxd(const IRInstr* instr) {
    const IROperand& dst = instr->operands[0];   // 16312-16313 / 16322-16323
    const IROperand& src = instr->operands[1];   // v46 = v42 + 1 (16316/16326)

    // alloc_dst_gpr (16315/16325 -> 27406-27438): the dst is always a Register
    // for these opcodes. size >= S32 -> architectural register {0,0}
    // (27427-27435); size == S16 -> one held scratch {1,1} (LABEL_2
    // 27418-27423). The result is the read hint v45 (never XZR).
    const bool hint_is_arch =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);

    Seq seq;
    seq.step(hint_is_arch ? Cost{0, 0} : Cost{1, 1});    // 16315 alloc_dst_gpr
    seq.step(movext_read_cost(src, hint_is_arch));       // 16331 read_operand_to_gpr
    seq.step(Cost{0, 0});                                // 15116 write_gpr_to_operand (Register)
    return seq.demand();
}

// =============================================================================
// family: push-pop  — kOpcodeName_push, _pop, _pushd, _popd, _pushw, _popw
// Audit: research/bridge_demand/families/push-pop/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. One model keyed on opcode (push-side vs pop-side) and
// operand shape. Routing (case_slice.c; goto tails LABEL_501/525/705 inlined):
//   push (16930) → translate_push: Register non-RSP → peephole fast-path
//     (18188-18358), ZERO allocation; else (Register RSP / mem / imm) →
//     translate_pushd_pushw(a1, op, 3)          (18361)
//   pushd (16945-16947) → translate_pushd_pushw(a1, op, 2)   (16956 LABEL_501)
//   pop (16718) → translate_pop: Register non-RSP → peephole fast-path
//     (17922-17985), ZERO allocation; else (Register RSP / mem) →
//     translate_popd_popw(a1, op)               (17988)
//   popd (16732) → translate_popd_popw(a1, op)  directly
//   pushw (16952-16954) → translate_pushd_pushw(a1, op, 1)  (LABEL_501)
//   popw (16733, shares the popd case) → translate_popd_popw(a1, op)
// The register fast-paths of push/pop contain NO free_gpr_mask/__clz idiom and
// no allocating helper (all regs are architectural reg&0xF) → peak 0. push and
// pushd share translate_pushd_pushw (the size arg 3 vs 2 changes no alloc);
// pop and popd share translate_popd_popw. No structural divergence. pushw/popw
// run the SAME handlers (size arg 1 feeds only emit_str_pre_idx/emit_ldr_post_idx,
// which never allocate): a class-2 (S16) Register read takes translate_gpr's
// 16-bit-extend block (26688-26716) whose XZR-hint path first-free allocates
// a fresh scratch + bitfield-extracts ({1,1}) — so `pushw %sp` reads into a
// scratch ≠ 4 and the
// alias dup NEVER fires for pushw (its demand 1 is the read, not the dup);
// alloc_dst_gpr prices an S16 Register dst {1,1} (27418-27423, already
// modeled); write_gpr_result S16 is a bitfield insert (27731-27737, no alloc);
// mov_prefetch_allocs scales by m.size, so popw m16 boundaries sit at 0xFFF*2.
//
// push-side translate_pushd_pushw (decomp 18425-18433):
//   operand_to_gpr = read_operand_to_gpr(a1, size==S64, op, 2, XZR)   (18430)
//   v6 = dup_gpr_if_alias(a1, operand_to_gpr, 4)                       (18431)
//   emit_str_pre_idx(...)                                             (18432, no alloc)
// XZR hint → HELPER_COSTS "fresh" column. dup_gpr_if_alias(…, 4) allocates
// {1,1} iff operand_to_gpr == 4 (RSP arch index) — true ONLY for a Register
// source with reg&0xF==4 (a Register read returns the arch index; mem/abs/imm
// reads return a fresh scratch ≠ 4). IR-decidable RSP-alias dimension.
//
// pop-side translate_popd_popw (decomp 18118-18145):
//   v4 = alloc_dst_gpr(a1, op)                     (18124)
//   if (v4 == 4) v4 = __clz(__rbit32(free_gpr_mask))  (18125-18131 fixup)
//   emit_ldr_post_idx(...)                         (18143, no alloc)
//   write_gpr_to_operand(a1, op, v4)               (18144)
// alloc_dst_gpr returns 4 only for an arch-reg (≥S32) RSP dst; the v4==4 fixup
// then allocates a scratch → the pop-side RSP alias ({1,1} instead of {0,0}).
// The loaded value reg v4 stays held across the store (it is the store source).
//
// DISPOSITIONS: rep_prefix — no access (MANIFEST watch-list: none); no LOCK
// form; not in lockable_rmw. flag_liveness — one access (18248) is a
// push/sub-fusion predicate on a FOLLOWING sub inside the zero-alloc push
// fast-path; gates no allocation. addr_size(S32) — push MemRef read {1,1} every
// shape (held value reg absorbs the address); pop MemRef write = 1 for every
// S32 shape (ADDR32.md). RSP-alias — modeled both sides (see above). Segment
// pushes decode as separate _segment opcodes (default refuse). GS
// fixed-slot-7 / get_tls_base BL (25901-25906) live behind seg_override,
// refused by the common prefix — unreachable here. NO shape refuses; max
// demand 3 (pop RIP-Immediate dst) ≤ kMaxBridgeDemand.
// -----------------------------------------------------------------------------

// read_operand_to_gpr(op, extend_mode=2, XZR) as invoked by translate_pushd_pushw.
// XZR/fresh column (HELPER_COSTS v3.1). Returns the value register: the arch
// index for a Register source, else a first-free scratch (held).
Cost push_read_cost(const IROperand& src) {
    switch (src.kind) {
        case IROperandKind::Register:
            // translate_gpr (26436 -> 26640-26750), XZR hint, extend_mode 2:
            // push has no 8-bit form (class ∈ {2,3,4}). Register srcs reaching
            // here: RSP/ESP (non-RSP push registers take the peephole
            // fast-path) and any pushw r16. class 3 (pushd, is_64bit=0): 26744
            // `v7!=3` is false but `hint==XZR` true -> 26746 return reg&0xF.
            // class 4 (push %rsp, is_64bit=1): `v7!=3` true -> 26746 return.
            // class 2 (pushw r16): the `extend_mode && v7 == 2` 16-bit-extend
            // block (26688-26716) fires; under the XZR hint it first-free
            // allocates a scratch (26711-26714) and bitfield-extracts the low
            // 16 bits into it, {1,1} (empirically: pushw %ax actual=1). The
            // scratch is never arch 4, so the alias dup cannot fire for pushw
            // (see demand_push_pop).
            return src.reg.size == IROperandSize::S16 ? Cost{1, 1} : Cost{0, 0};
        case IROperandKind::MemRef:
            // 26440-26493 XZR branch: value reg first-free (26449), reused as
            // the prefetch address hint (26492) -> every prefetch alloc (gated
            // on hint==XZR) skipped, incl. non-encodable disp and S32 addressing
            // (ADDR32.md: held pool scratch -> 0 extra). {1,1} every shape.
            return Cost{1, 1};
        case IROperandKind::AbsMem:
            // 26498-26558 XZR branch: fresh reg (26511), compute_operand_address
            // into it.
            return Cost{1, 1};
        case IROperandKind::Immediate:
            // 26564-26633 XZR branch: adr-base/value temp (26587, held) + an
            // unaligned-path runtime-addend transient (25964-25971, freed 25971).
            // Alignment not IR-decidable -> peak 2, held 1.
            return Cost{2, 1};
        default:
            // BranchOffset (`push $imm`): emit_load_immediate(is_64bit, value,
            // XZR) (26562). value==0 returns XZR (no alloc); else fresh {1,1}.
            return src.branch.value == 0 ? Cost{0, 0} : Cost{1, 1};
    }
}

// write_gpr_to_operand(op, v4) as invoked by translate_popd_popw (decomp
// 27643-27701). The store source (v4) is the caller's held value reg.
Cost pop_write_cost(const IROperand& dst) {
    switch (dst.kind) {
        case IROperandKind::Register:
            return Cost{0, 0};                              // 27692 write_gpr_result
        case IROperandKind::MemRef: {
            // 27700 translate_prefetch_impl(…, XZR): address temp per shape
            // (mov_prefetch_allocs; 1 for every S32 shape, ADDR32.md), not freed.
            const int8_t a = dst.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(dst.mem));
            return Cost{a, 0};
        }
        case IROperandKind::AbsMem:
            return Cost{1, 0};                              // 27681-27684 (freed)
        case IROperandKind::Immediate:
            // 27668-27684: aligned peak 1; unaligned compute_operand_address
            // Immediate peaks 2 (25944-25972). Alignment not IR-decidable -> 2.
            return Cost{2, 0};
        default:
            return Cost{0, 0};
    }
}

int demand_push_pop(const IRInstr* instr) {
    const uint16_t op = instr->opcode();
    const IROperand& operand = instr->operands[0];   // push src / pop dst

    // RSP arch index is 4 (reg&0xF == 4), = kOpcodeName encoding 0x44 masked.
    const bool operand_is_reg = operand.kind == IROperandKind::Register;
    const bool operand_is_rsp =
        operand_is_reg && (operand.reg.reg.value & 0xF) == 4;   // 17924/18187/25463/18125

    const bool is_push = (op == kOpcodeName_push || op == kOpcodeName_pushd ||
                          op == kOpcodeName_pushw);

    if (is_push) {
        // push (Register non-RSP): translate_push peephole fast-path, 0 alloc
        // (18188-18358). pushd/pushw never take a fast-path (always
        // translate_pushd_pushw), so a pushd/pushw non-RSP register still runs
        // the read+dup model below — which costs 0 for it anyway.
        if (op == kOpcodeName_push && operand_is_reg && !operand_is_rsp)
            return 0;                                    // 18184-18187 fast-path

        // translate_pushd_pushw: read (18430) then dup_gpr_if_alias (18431).
        Seq seq;
        seq.step(push_read_cost(operand));               // 18430 read_operand_to_gpr
        // dup_gpr_if_alias(operand_to_gpr, 4): {1,1} iff a Register RSP/ESP src
        // (operand_to_gpr == 4); mem/abs/imm — and pushw's S16 bitfield-extract
        // — read into a fresh scratch ≠ 4, so only a ≥S32 RSP register src
        // (push %rsp / pushd %esp) trips the alias.
        const bool rsp_alias =
            operand_is_rsp && operand.reg.size != IROperandSize::S16;
        seq.step(rsp_alias ? Cost{1, 1} : Cost{0, 0});   // 18431 dup_gpr_if_alias
        return seq.demand();
    }

    // pop / popd / popw.
    // pop (Register non-RSP): translate_pop peephole fast-path, 0 alloc
    // (17922-17985). popd/popw always run translate_popd_popw (0 for a non-RSP
    // arch-reg ≥S32 dst; an S16 reg dst takes alloc_dst_gpr's held-temp path).
    if (op == kOpcodeName_pop && operand_is_reg && !operand_is_rsp)
        return 0;                                        // 17921-17924 fast-path

    // translate_popd_popw: alloc_dst_gpr (+v4==4 fixup) then write_gpr_to_operand.
    const bool dst_is_arch_reg =
        operand_is_reg &&
        (operand.reg.size == IROperandSize::S32 || operand.reg.size == IROperandSize::S64);

    Seq seq;
    // alloc_dst_gpr (18124): arch reg ≥S32 -> {0,0} (27435), EXCEPT RSP, where
    // the v4==4 fixup (18125-18131) re-allocates one scratch -> {1,1}. ≤S16 reg
    // or any mem dst -> {1,1} (27418-27423). Held (it is the loaded value reg).
    if (dst_is_arch_reg && !operand_is_rsp)
        seq.step(Cost{0, 0});                            // 27426-27435 arch reg
    else
        seq.step(Cost{1, 1});                            // 18130 fixup / 27418-27423
    seq.step(pop_write_cost(operand));                   // 18144 write_gpr_to_operand
    return seq.demand();
}

// =============================================================================
// family: alu-unary  — kOpcodeName_inc, _dec, _neg, _not
// Audit: research/bridge_demand/families/alu-unary/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. One model keyed on opcode + operand shape (the push-pop
// precedent: distinct handler skeletons unified in one function). The four
// opcodes are FOUR separate handlers (translate_inc 21677, translate_dec 21547,
// translate_neg 21807, translate_not 27944) with three distinct allocation
// sequences, but each is a short Seq and all read the SINGLE operand
// operands[0] (an in-place RMW target: Register / MemRef / AbsMem / Immediate).
//
// LOCK (rep_prefix==1): all four take a distinct ldaxr/stlxr exclusive-loop mem
// path (dec 21630 / inc 21760 / neg 21852 / not 27975) — unaudited, higher
// demand. LOCK+mem is refused by the common prefix (lockable_rmw covers inc/dec/
// neg/not + has_mem). LOCK on a register operand is malformed x86 that the prefix
// does NOT catch (has_mem false), so this model REFUSES rep_prefix==1 outright.
//
// Non-LOCK skeletons (rep_prefix != 1; goto tail LABEL_705 15117 resets the mask):
//   inc/dec (21721-21758 / 21591-21628):
//     v10  = alloc_dst_gpr(operands[0])                      (21720 / 21590)
//     otg  = read_operand_to_gpr(operands[0], em, XZR)       (21729 / 21599)
//     if (v8 && (fl & FLAG_CF)):  one csel temp v25          (21737-21738 / 21607-21608)
//     LABEL_34: free_temporary_gpr(otg); write_gpr_to_operand(operands[0], v10)
//                                                            (21743-21744 / 21613-21614)
//   neg (21901-21916):
//     v10  = alloc_dst_gpr(operands[0])                      (21849, before the rep branch)
//     otg  = read_operand_to_gpr(operands[0], em, XZR)       (21907)
//     free_temporary_gpr(otg); write_gpr_to_operand(operands[0], v10)  (21915-21916)
//   not (27986-27991):
//     otg  = read_operand_to_gpr(operands[0], 0, XZR)        (27987)
//     v11  = alloc_dst_gpr(operands[0])                      (27988)
//     write_gpr_to_operand(operands[0], v11)                 (27990) — NO free of otg
//
// All emit_* used on these paths (emit_csel 2922, emit_ccmp 3375, emit_add_imm
// 2525, emit_bitfield 2818, emit_logical_shifted_reg, emit_add_sub_shifted_reg,
// emit_flag_writeback 24760) only call AssemblerBuffer::emit — no first-free
// allocation (verified verbatim). read_operand_to_gpr (26385, XZR hint) and
// alloc_dst_gpr (27406) and write_gpr_to_operand (27643) match HELPER_COSTS
// v3.1; their shape costs are reused via alu_read_cost / alloc_dst_gpr_cost /
// alu_write_op0_cost from the alu-binary section (same helpers, same XZR hint).
//
// PEAK vs verify's TOTAL-EVENT actual: for a MEMORY destination the handler
// frees otg BEFORE write_gpr_to_operand allocates the store-address temp
// (inc/dec 21743→21744, neg 21915→21916), so the true concurrent PEAK is one
// below the total-event count. verify_demand neuters frees; to match it (and
// stay a safe over-estimate ≤ kMaxBridgeDemand) we KEEP otg held across the
// write for mem/abs destinations. Empirically (verify_demand --family):
// neg/not [rsi+rdx*8+0x12345] actual 3, inc/dec (same, CF live) actual 4.
// Immediate-kind dst totals 5-6 (matrix-exact) — over the ceiling, refused by
// the gap_gpr_demand gate; the model reports the honest number.
//
// DISPOSITIONS. rep_prefix: read by all four (21591/21721/21850/27973) — LOCK
// path refused (above). flag_liveness: read by inc/dec/neg (21579/21709/21838
// et al.) to pick extend_mode and gate the inc/dec CF csel temp; NOT read by
// not (27944-27992). All uses are IR-decidable and modeled below. not never
// touches flags. GS fixed-slot-7 / get_tls_base BL (25901-25906) live behind
// seg_override (25882), refused by the common prefix — unreachable here.
// -----------------------------------------------------------------------------

int demand_alu_unary(const IRInstr* instr) {
    const uint16_t op = instr->opcode();
    const IROperand& tgt = instr->operands[0];   // the single RMW operand
    const uint8_t fl = instr->flag_liveness;

    // Immediate-kind (RIP/data-page) RMW dst: honest event total — alloc_dst
    // {1} + read {2 events} + write {2 events} + the inc/dec CF csel temp
    // (matrix 2026-07-17: actual 5/5/6/6, exact). Totals above the bridging
    // ceiling are refused by the gap_gpr_demand gate, not here.
    if (tgt.kind == IROperandKind::Immediate) {
        const bool imm_v7 = (fl & (FLAG_PF_HI | FLAG_CF | FLAG_ZF)) != 0 ||
                            tgt.reg.size > IROperandSize::S16;   // 21711/21581
        const bool imm_cf = (op == kOpcodeName_inc || op == kOpcodeName_dec) &&
                            fl >= FLAG_AF && imm_v7 &&
                            (fl & FLAG_CF) != 0;   // 21712+21730-21732 / 21582+21600-21602
        return 5 + (imm_cf ? 1 : 0);
    }

    // operand size = operands[0].reg.size (21580/21710/21839/27964).
    const bool is_64bit = tgt.reg.size == IROperandSize::S64;

    const bool tgt_is_mem = tgt.kind == IROperandKind::MemRef ||
                            tgt.kind == IROperandKind::AbsMem ||
                            tgt.kind == IROperandKind::Immediate;

    // read_operand_to_gpr extend_mode: inc/dec/neg pass
    // 2*((fl & (OF|CF|ZF))!=0) (21729/21599/21911); not passes 0 (27987).
    const bool em_nonzero =
        op != kOpcodeName_not &&
        (fl & (FLAG_OF | FLAG_CF | FLAG_ZF)) != 0;   // 0x70 (21729/21599/21911)

    Seq seq;

    if (op == kOpcodeName_not) {
        // not: read → alloc_dst_gpr → write; otg is NEVER freed (27987-27990).
        seq.step(alu_read_cost(tgt, em_nonzero, is_64bit));   // 27987 read_operand_to_gpr
        seq.step(alloc_dst_gpr_cost(tgt));                    // 27988 alloc_dst_gpr
        seq.step(alu_write_op0_cost(tgt));                    // 27990 write_gpr_to_operand
        return seq.demand();
    }

    // inc / dec / neg: alloc_dst_gpr → read → (inc/dec CF csel temp) →
    // free otg → write.
    seq.step(alloc_dst_gpr_cost(tgt));                        // 21720/21590/21849 alloc_dst_gpr
    seq.step(alu_read_cost(tgt, em_nonzero, is_64bit));       // 21729/21599/21907 read_operand_to_gpr

    if (op == kOpcodeName_inc || op == kOpcodeName_dec) {
        // v8 = (fl >= FLAG_AF) && ((fl & (PF_HI|CF|ZF))!=0 || size > S16)
        //      (21712/21582); the CF csel temp fires under v8 && (fl & FLAG_CF)
        //      (21730+21732 / 21600+21602). One first-free temp v25, held.
        const bool v7 = (fl & (FLAG_PF_HI | FLAG_CF | FLAG_ZF)) != 0 ||
                        tgt.reg.size > IROperandSize::S16;   // 21711/21581
        const bool v8 = fl >= FLAG_AF && v7;                 // 21712/21582
        if (v8 && (fl & FLAG_CF) != 0)
            seq.step(Cost{1, 1});                            // 21737-21738 / 21607-21608 emit_csel temp
    }

    // LABEL_34: free_temporary_gpr(otg) then write_gpr_to_operand
    // (inc/dec 21743-21744 / neg 21915-21916). PEAK-vs-TOTAL: keep otg held for
    // a mem/abs/imm dst (matches verify's neutered-free total-event count).
    if (!tgt_is_mem)
        seq.free(1);                                         // 21743/21613/21915 free otg (reg dst)
    seq.step(alu_write_op0_cost(tgt));                       // 21744/21614/21916 write_gpr_to_operand
    return seq.demand();
}

// =============================================================================
// family: cmovcc  — kOpcodeName_cmovcc
// Audit: research/bridge_demand/families/cmovcc/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. One case group (decomp 15063-15121). operands[0] =
// ConditionCode, operands[1] = destination (ALWAYS a Register — 15066-15073
// deref its reg fields and assert on non-register), operands[2] = source.
//
// Handler order (goto tails LABEL_695/704/705 inlined):
//   otg = read_operand_to_gpr(a1, size==S64, &operands[2], 0, XZR)   (15070)
//   v84 = alloc_dst_gpr(a1, &operands[1])                            (15076)
//   cc  = operands[0].cc.cc                                          (15077)
//   if ( (cc & 0xFE) == 0xA )  // parity (P/NP): 3 inline first-free temps
//       v87/v90/v92 = __clz(__rbit32(...))  (15083/15092/15097), none freed,
//       + emit_set_carry_from_gpr (no alloc) + 3× emit_logical_shifted_reg
//   else  translate_condition_code + emit_csel                      (15109-15110, 0 alloc)
//   write_gpr_to_operand(a1, &operands[1], v84)                     (15116, Register → 0)
//
// The read uses extend_mode==0 (15070): in translate_gpr (26640-26750) v8=1
// (26665), so only the high-byte class (reg>>4==1) allocates ({1,1}); every
// other register class passes through ({0,0}). Parity vs non-parity is
// IR-decidable (operands[0].cc.cc). The three parity temps stack on the held
// read + dst survivors, so parity demand = read.held + dst.held + 3.
//
// Parity demand = read.peak + dst.held + 3 (honest total; the Immediate
// read's freed addend transient counts under the total-event convention —
// matrix-caught, actual=5 with an arch dst). Totals of 5-6 (any Immediate
// src, or a ≤S16 dst with a temp-holding src) exceed the bridging ceiling
// and are refused by the gap_gpr_demand GATE — this model just reports them.
// (High-byte src rows are analytic-only: cmov has no 8-bit encoding.)
//
// DISPOSITIONS. rep_prefix: no access anywhere in the case body (15063-15121)
// or the helper closure; no LOCK form. flag_liveness: no access; the read's
// extend_mode is the literal 0, not a flag function; selection depends only on
// operands[0].cc.cc. GS fixed-slot-7 (25901) / get_tls_base BL (25904-25906)
// live behind seg_override (25882), refused by the common prefix — unreachable.
// addr_size S32: MemRef src read is {1,1} for every addressing shape (the held
// value reg absorbs the address under the XZR hint), so S32 needs no special
// case here. Table v3.1; discrepancy flags: NONE.
// -----------------------------------------------------------------------------

// read_operand_to_gpr(&operands[2], extend_mode=0, XZR) as invoked by cmovcc.
// XZR/fresh column; extend_mode 0 makes a Register src allocate only for the
// high-byte class (translate_gpr 26665/26666).
Cost cmov_read_cost(const IROperand& src) {
    switch (src.kind) {
        case IROperandKind::Register:
            // translate_gpr (26436 -> 26640-26750), extend_mode 0: v8=1 (26665)
            // so the extract-block gate collapses to v7==1 (high byte). High
            // byte → XZR-hint first-free alloc (26674) {1,1}; every other class
            // → 26744/26746 passthrough {0,0}.
            return (src.reg.reg.value >> 4) == 1 ? Cost{1, 1} : Cost{0, 0};
        case IROperandKind::MemRef:
            // XZR hint (26444-26451): value reg first-free (26449), reused as
            // the prefetch address hint (26492) → no further alloc, every
            // addressing shape incl. S32 → {1,1}.
            return Cost{1, 1};
        case IROperandKind::AbsMem:
            // XZR hint (26506-26512): fresh reg, compute_operand_address into
            // it (26536) → {1,1}.
            return Cost{1, 1};
        case IROperandKind::Immediate:
            // XZR hint (26584-26593): adr-base/value temp (held) + unaligned
            // data-page runtime-addend transient (compute_operand_address
            // Immediate 25944-25972, peak 2, freed 25971). Alignment not
            // IR-decidable → {2,1}.
            return Cost{2, 1};
        default:
            // BranchOffset would go via emit_load_immediate (26562); cmovcc has
            // no such source form in practice, but price it as one held temp.
            return src.branch.value == 0 ? Cost{0, 0} : Cost{1, 1};
    }
}

int demand_cmovcc(const IRInstr* instr) {
    const IROperand& cc_op = instr->operands[0];   // 15077 ConditionCode
    const IROperand& dst = instr->operands[1];     // 15063-15073 destination (Register)
    const IROperand& src = instr->operands[2];     // 15070 source

    // Parity condition codes (P/NP) take the 3-temp inline path (15078-15102);
    // every other cc takes translate_condition_code + emit_csel (0 alloc).
    // (cc & 0xFE) == 0xA  ⇔  cc ∈ {0xA, 0xB}.  IR-decidable.
    const bool parity = (cc_op.cc.cc & 0xFE) == 0xA;   // 15078

    // alloc_dst_gpr(operands[1]) — always a Register: ≥S32 → arch {0,0}
    // (27435); ≤S16 → one held first-free temp {1,1} (27416-27423).
    const bool dst_is_arch =
        dst.kind == IROperandKind::Register &&
        (dst.reg.size == IROperandSize::S32 || dst.reg.size == IROperandSize::S64);
    const Cost dst_cost = dst_is_arch ? Cost{0, 0} : Cost{1, 1};   // 15076

    const Cost read_cost = cmov_read_cost(src);                    // 15070

    if (parity) {
        // 15083/15092/15097: three inline first-free temps, none freed, all
        // live across the three emit_logical_shifted_reg (15099-15101). They
        // stack on the held read + dst survivors. TOTAL-EVENT convention
        // (reviewer, matrix-caught): the Immediate read's freed addend
        // transient still counts toward verify's neutered-free total, so the
        // stack uses read.peak (2 for Immediate), not read.held. This total
        // dominates every Seq step, so it IS the demand (matrix: reg 3,
        // mem/abs 4, Imm 5, +1 each for an S16 dst — 5/6 exceed the ceiling
        // and are refused by the gap_gpr_demand gate, not here).
        return read_cost.peak + dst_cost.held + 3;   // 15083-15098 parity temps
    }
    // Non-parity: translate_condition_code + emit_csel (15109-15110), 0 alloc.
    Seq seq;
    seq.step(read_cost);                                           // 15070 read_operand_to_gpr
    seq.step(dst_cost);                                            // 15076 alloc_dst_gpr
    seq.step(Cost{0, 0});                                          // 15116 write_gpr_to_operand (Register)
    return seq.demand();
}

// =============================================================================
// family: setcc  — kOpcodeName_setcc (all cc variants sete/setne/seta/setp/…)
// Audit: research/bridge_demand/families/setcc/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. One case group (case_slice.c 15347-15363), one
// straight-line structure; the condition-code axis is demand-neutral and shape
// divergence lives entirely in the trailing write. operands[0] is the
// ConditionCode (15348), operands[1] the destination r/m8 (always S8; Register
// incl. high-byte, MemRef, AbsMem, or RIP Immediate).
//
// Handler order (LABEL_703/704 writeback + LABEL_705 epilogue inlined):
//   v206 = alloc_dst_gpr(a1, &operands[1])                         (15347)
//   cc test: 0xB → emit_set_and_clear_carry_from_gpr (24745-24750) /
//            0xA → emit_read_carry_to_gpr (24738-24742) /
//            else → translate_condition_code + emit_csel (15359-15360)
//        — ALL emit-only, 0 alloc (both carry helpers operate in v206 via
//          emit_mrs_fpcr_fpsr/emit_bitfield/emit_logical_imm; csel/translate_cc
//          allocate nothing). Parity ccs cost ZERO extra temps here, UNLIKE
//          cmovcc's 3-temp inline parity path — cc is NOT a shape dimension.
//   write_gpr_to_operand(a1, &operands[1], v206)                   (15116)
//
// alloc_dst_gpr (27406-27438): dst is always S8, so the Register path takes the
// size<=S16 first-free branch (27416) and MemRef/AbsMem/Immediate (kind-1<3,
// 27412) hit the same alloc — {1,1} on EVERY shape, held to the epilogue.
// write_gpr_to_operand (27643-27701): Register → write_gpr_result (0 alloc,
// incl. high-byte insertion 27736); MemRef → translate_prefetch_impl(XZR)
// store (mov_prefetch_allocs, S32:1); AbsMem/Immediate → compute_operand_address
// then str + free_temporary_gpr (27684). The dst temp v206 is HELD across the
// write (never freed before LABEL_705), so the write peak stacks on running=1
// and peak == verify's total-event count on every shape (no freed-transient
// undercount — the Immediate-dst worst case is priced first and matches).
//
// DISPOSITIONS. rep_prefix: no access anywhere in the case body (15347-15363)
// or the 33-helper closure; setcc has no LOCK form. flag_liveness: no access;
// selection reads only operands[0].cc.cc (15348). GS fixed-slot-7 (25901) /
// get_tls_base BL (25904-25906) live behind seg_override (25882), refused by
// the common prefix — unreachable. addr_size S32 handled per ADDR32.md. Table
// v3.1; discrepancy flags: NONE.
// -----------------------------------------------------------------------------

// write_gpr_to_operand(&operands[1], v206) as invoked by setcc — the value gpr
// is the caller's held dst temp; this returns the write's peak (held 0, all
// address temps freed after the store / reclaimed at the epilogue).
Cost setcc_write_cost(const IROperand& dst) {
    switch (dst.kind) {
        case IROperandKind::Register:
            // write_gpr_result (27692 / 27704-27744): emit-only, incl. the
            // high-byte insertion path (27736 emit_bitfield). No alloc.
            return Cost{0, 0};
        case IROperandKind::MemRef: {
            // translate_prefetch_impl(…, a6=XZR) (27700): XZR-hint prefetch,
            // same callee/hint as the mov store. mov_prefetch_allocs: 0 for
            // encodable [base+disp] / scale-SIB, else 1. S32 addr routes via
            // compute_operand_address (25578-25587) → 1 for every shape.
            const int8_t a = dst.mem.addr_size == IROperandSize::S32
                                 ? int8_t{1}
                                 : static_cast<int8_t>(mov_prefetch_allocs(dst.mem));
            return Cost{a, 0};
        }
        case IROperandKind::AbsMem:
            // compute_operand_address(…, XZR) AbsMem (27681 → 25930-25941):
            // one held first-free, freed after the store (27684). Peak 1.
            return Cost{1, 0};
        case IROperandKind::Immediate:
            // Immediate (RIP/abs) store target. Aligned: alloc 1 + emit_adr +
            // str + free (27668-27684) → peak 1. Unaligned: compute_operand_address
            // Immediate (27681 → 25944-25972) adr temp + runtime addend → peak 2,
            // freed 27684. Alignment not IR-decidable (25516 text_base_align_offset)
            // → fold to worst case, peak 2.
            return Cost{2, 0};
        default:
            return Cost{0, 0};
    }
}

int demand_setcc(const IRInstr* instr) {
    const IROperand& dst = instr->operands[1];   // 15347 destination r/m8

    Seq seq;
    seq.step(Cost{1, 1});                         // 15347 alloc_dst_gpr (always S8 → {1,1})
    seq.step(Cost{0, 0});                         // 15349-15360 cc block (emit-only, 0 alloc)
    seq.step(setcc_write_cost(dst));              // 15116 write_gpr_to_operand
    return seq.demand();
}

// =============================================================================
// family: shifts  — kOpcodeName_shl, _shr, _sar, _rol, _ror
// Audit: research/bridge_demand/families/shifts/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. All five case groups share ONE dispatch structure
// (case_slice.c 15314-15384): `if ( operands[1].kind == BranchOffset )
// translate_<op>_imm else translate_<op>_reg` (rol 15315-15318, ror 15322-15325,
// sar 15332-15335, shl 15366-15369, shr 15380-15383). operands[0] is the shift
// TARGET (an in-place RMW: Register / MemRef / AbsMem / Immediate), read as the
// source AND written back; operands[1] is the COUNT (a plain immediate =
// BranchOffset → _imm path, or CL = Register → _reg path). Ten short handlers,
// unified here keyed on opcode + path + shape (the push-pop / alu-unary
// precedent). rol/ror diverge from shl/shr/sar in flag handling but each is a
// straight-line total-event count, so a single model covers all ten.
//
// COUNTING CONVENTION — TOTAL EVENTS (frees neutered). verify_demand's `actual`
// is popcount(free_gpr_mask before & ~after) with free_temporary_gpr patched to
// RET (aotinvoke/src/RosettaAotApi.cpp 54-56, main.cpp 148-151): every distinct
// __clz(__rbit32(free_gpr_mask)) alloc site executed consumes a NEW scratch bit
// (a neutered free never restores one), and there is no decrement before the
// LABEL_705 reset. So demand = the number of first-free alloc sites reached on
// the shape's path, both inside the handler and inside its callees. This section
// composes those event counts directly (like the alu families' PEAK-vs-TOTAL
// composition) rather than the Seq peak idiom, which models frees.
//
// Shared-helper event counts on operands[0] (XZR hint throughout — read at
// 30285/30412/30603/30732/30829/30914/31040/31130?/31549/31674; the value reg is
// first-free allocated fresh):
//   read0  read_operand_to_gpr(op0, em, XZR): Register 0 (S32/S64) or 1 (S8/S16,
//          translate_gpr extend block XZR-alloc 26688-26714 / class-0 26666);
//          MemRef 1 (value reg absorbs address, every shape incl. S32, 26449);
//          AbsMem 1 (26511); Immediate 2 (adr temp + addend, 26587/25964).
//   dst    alloc_dst_gpr(op0) (27406-27438): Register ≥S32 0 (27435), else 1.
//   write  write_gpr_to_operand(op0) (27643-27701): Register 0; MemRef
//          mov_prefetch_allocs (1 for S32/SIB+disp, 0 for encodable [base+disp]);
//          AbsMem 1; Immediate 2.
//   nz     emit_nz_flags(fl,size) (24645-24735): 1 iff SF live AND size ≤ S16
//          (the 24675/24689 __clz allocs sit under the SF gate 24659; the ZF/PF
//          exit 24704+ is alloc-free), else 0. Called by shl/shr/sar; NOT by
//          rol/ror. MATRIX RECONCILIATION: SF-gate, not size alone.
//   dup    dup_gpr_if_alias(operand_to_gpr, v7) (25456-25474): allocates 1 iff
//          operand_to_gpr == v7. For a Register op0 ≥S32 the read returns the
//          arch reg and alloc_dst returns that SAME arch reg → alias fires; for
//          op0 ≤S16 (dst is a fresh scratch) or mem/abs/imm (read is a fresh
//          scratch, distinct from the dst scratch) it does not.
//
// DISPOSITIONS. rep_prefix: NO access anywhere in the ten handlers
// (30083-31741) or the helper closure (MANIFEST unresolved_calls: none;
// flags.txt rep_prefix section: none) — shifts have no LOCK form and are not in
// lockable_rmw, so no exclusive-loop path exists. flag_liveness: read pervasively
// (flags.txt lists every site) to gate CF/OF materialization and the
// read/emit_nz_flags extend paths; every use is IR-decidable (insn->flag_liveness
// + the immediate byte + operand size) and modeled below. flags.txt: the sole
// fixed-slot (allocate_temporary_gpr_num(a1,7) 25901) and runtime BL
// (get_tls_base 25904-25906) live inside compute_mem_operand_address's GS
// seg_override branch (25882), refused by the common prefix (seg_override != 0)
// before this model runs — the excluded slot-7 path, unreachable here. All
// flag_liveness / X22-fast-path entries are dispositioned in the AUDIT. NO shape
// refuses: no other fixed slot, no other runtime BL, every branch IR-decidable.
// -----------------------------------------------------------------------------

// read_operand_to_gpr(operands[0], em, XZR) event count. em (extend_mode) is 1
// for shl/shr/rol/ror and 2 for sar (30285/30412/30603/30829/30914/31040/31549/
// 31674 pass 1; 30732/30829 sar passes 2) — but it changes no count here: a
// Register op0 allocates iff its size is S8/S16 (translate_gpr's 8/16-bit extend
// blocks fire under the XZR hint for both em values), and a mem/imm op0 is
// hint-independent. So one function serves every opcode.
int shifts_read0_events(const IROperand& op0) {
    switch (op0.kind) {
        case IROperandKind::Register:
            // translate_gpr XZR hint (26640-26750): S16 → 16-bit extend block
            // allocs (26688-26714); S8 low → class-0 block allocs (26666-26674);
            // S32/S64 → passthrough (26744-26746). No high-byte shift target in
            // practice, but an 8-bit target still allocates one, safely.
            return op0.reg.size <= IROperandSize::S16 ? 1 : 0;
        case IROperandKind::MemRef:
        case IROperandKind::AbsMem:
            return 1;                                        // 26449 / 26511
        case IROperandKind::Immediate:
            return 2;                                        // 26587 + 25964 addend
        default:
            return 1;
    }
}

// alloc_dst_gpr(operands[0]) event count (27406-27438).
int shifts_dst_events(const IROperand& op0) {
    if (op0.kind == IROperandKind::Register &&
        (op0.reg.size == IROperandSize::S32 || op0.reg.size == IROperandSize::S64))
        return 0;                                            // 27435 arch reg
    return 1;                                                // 27418-27423
}

// write_gpr_to_operand(operands[0]) event count (27643-27701).
int shifts_write_events(const IROperand& op0) {
    switch (op0.kind) {
        case IROperandKind::Register:
            return 0;                                        // 27692 write_gpr_result
        case IROperandKind::MemRef:
            // 27700 translate_prefetch_impl(…, XZR): mov_prefetch_allocs (S32 → 1,
            // ADDR32.md; SIB+disp → 1; encodable [base+disp] → 0).
            return op0.mem.addr_size == IROperandSize::S32
                       ? 1
                       : mov_prefetch_allocs(op0.mem);
        case IROperandKind::AbsMem:
            return 1;                                        // 27681-27684
        case IROperandKind::Immediate:
            return 2;                                        // 27668-27684 (unaligned peak 2)
        default:
            return 0;
    }
}

// emit_nz_flags(flag_liveness, size) event count (24645-24735). MATRIX
// RECONCILIATION (2026-07-17): the S8/S16 temp is allocated ONLY on the
// SF-live branch — `24659|  if ( (flag_liveness & (unsigned __int8)FLAG_SF) != 0 )`
// guards the S8 (24672-24676) and S16 (24686-24690) __clz allocs; the ZF/PF
// path (`24704|  if ( (flag_liveness & (FLAG_PF_HI|FLAG_ZF)) == 0 )` onward,
// 24708-24734) is emit-only (emit_logical_imm / emit_logical_shifted_reg, no
// alloc). S32/S64 never allocate. So the event is gated on SF liveness AND
// size ≤ S16, not on size alone (the reviewer's OF|CF-only pads were SF-dead).
int shifts_nz_events(uint8_t fl, const IROperand& op0) {
    return ((fl & FLAG_SF) && op0.reg.size <= IROperandSize::S16) ? 1 : 0;
}

// dup_gpr_if_alias(operand_to_gpr, v7) event count (25456-25474): 1 iff the
// read of op0 and alloc_dst of op0 land in the SAME register (Register op0 ≥S32).
int shifts_dup_events(const IROperand& op0) {
    return (op0.kind == IROperandKind::Register &&
            (op0.reg.size == IROperandSize::S32 || op0.reg.size == IROperandSize::S64))
               ? 1
               : 0;
}

// Inline first-free alloc events of each of the ten handlers, exact per
// flag_liveness / immediate byte / operand size. size_le16 = op0 size ≤ S16.
// value_b = the low byte of the shift immediate (imm path only).
// dup/nz events are added by the caller (they are shared helpers).

// translate_shl_imm (30997-31116): v18 (31069) then v23 (31097). The nz temp
// (emit_nz_flags 31091) is added by the caller via shifts_nz_events, NOT here.
// v10=CF is gated OFF when value_b==0 (31045); v11=OF is gated OFF unless
// value_b==1 (31047-31050) — OF is x86-undefined for multi-bit shifts, so at
// count!=1 only CF drives the v18/v23 materialization (MATRIX RECONCILIATION).
int shl_imm_inline(uint8_t fl, unsigned value_b) {
    int v10 = (fl >> 5) & 1;                                 // 31044 CF bit
    if (value_b == 0) v10 = 0;                               // 31045-31046
    int v11 = (value_b == 1) ? ((fl >> 4) & 1) : 0;          // 31047-31050 OF bit
    int c = 0;
    if ((v10 | v11) & 1) c += 1;                             // 31069 v18
    if ((fl & 0xFF) && value_b && ((v10 | v11) & 1))         // 31087-31092
        c += 1;                                              // 31097 v23
    return c;
}

// translate_shr_imm (31636-31741): v8 (31692), v16 (31706), v18 (31732). nz temp
// added by the caller. of_live gated OFF unless value_b==1 (31679-31682).
int shr_imm_inline(uint8_t fl, unsigned value_b) {
    int of_live = (value_b == 1) ? ((fl >> 4) & 1) : 0;      // 31679-31682
    int c = 0;
    if (value_b && (fl & 0x20)) c += 1;                      // 31683 v8 (CF)
    if (of_live & 1) c += 1;                                 // 31697 v16
    if ((fl & 0xFF) && value_b &&                            // 31721-31724
        (((of_live | ((fl & 0xFF) >> 5)) & 1)))              // 31726
        c += 1;                                              // 31732 v18
    return c;
}

// translate_sar_imm (30795-30880): v13 (30846), v15 (30871). nz temp added by
// the caller. v10=OF gated OFF unless value_b==1 (30833-30835).
int sar_imm_inline(uint8_t fl, unsigned value_b) {
    int v10 = (value_b == 1) ? ((fl >> 4) & 1) : 0;          // 30833-30835
    int c = 0;
    if (value_b && (fl & 0x20)) c += 1;                      // 30837 v13 (CF)
    if ((fl & 0xFF) && value_b &&                            // 30860-30862
        (((v10 | ((fl & 0xFF) >> 5)) & 1)))                  // 30865
        c += 1;                                              // 30871 v15
    return c;
}

// translate_rol_imm (30243-30359): v13 (30302) + v18 (30314) ALWAYS, then v22
// (30342). emit_nz_flags NOT called. dup added by caller.
int rol_imm_inline(uint8_t fl, unsigned value_b) {
    int c = 2;                                               // 30302 v13 + 30314 v18
    if ((fl & (FLAG_OF | FLAG_CF)) && value_b) c += 1;       // 30337-30342 v22
    return c;
}

// translate_ror_imm (30560-30693): S8/S16 → v14 (30622/30639) + bit_width
// (30627/30644); S32/S64 → emit_extr (no alloc). Then, if OF|CF live and value,
// v22 (30669) + v25 (30679).
int ror_imm_inline(uint8_t fl, unsigned value_b, bool size_le16) {
    int c = 0;
    if (size_le16) c += 2;                                   // 30622/30627 (or 30639/30644)
    if ((fl & (FLAG_OF | FLAG_CF)) && value_b) c += 2;       // 30666-30679 v22 + v25
    return c;
}

// translate_shl_reg (30883-30991): v12 (30923) if any flag, v15 (30956) if OF|CF.
int shl_reg_inline(uint8_t fl) {
    int c = 0;
    if (fl & 0xFF) c += 1;                                   // 30923 v12
    if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) c += 1;   // 30956 v15
    return c;
}

// translate_shr_reg (31519-31631): v12 (31558), v16 (31591). Same shape.
int shr_reg_inline(uint8_t fl) {
    int c = 0;
    if (fl & 0xFF) c += 1;                                   // 31558 v12
    if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) c += 1;   // 31591 v16
    return c;
}

// translate_sar_reg (30696-30790): v13 (30741), v18 (30774). Same shape.
int sar_reg_inline(uint8_t fl) {
    int c = 0;
    if (fl & 0xFF) c += 1;                                   // 30741 v13
    if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) c += 1;   // 30774 v18
    return c;
}

// translate_rol_reg (30083-30235): v11 (30139) if OF|CF; then S8/S16 → v17+v14
// (30161/30166 or 30178/30183), S32/S64 → v14 (30202); then v28 (30218) if OF|CF.
int rol_reg_inline(uint8_t fl, bool size_le16) {
    int c = 0;
    if (fl & (FLAG_OF | FLAG_CF)) c += 1;                    // 30139 v11
    c += size_le16 ? 2 : 1;                                  // 30161+30166 / 30202 v14
    if (fl & (FLAG_OF | FLAG_CF)) c += 1;                    // 30218 v28
    return c;
}

// translate_ror_reg (30363-30516): v14 (30422) if OF|CF; then S8/S16 → v17+v19
// (30442/30447 or 30459/30464), S32/S64 → emit_crc32 (no alloc); then v29 (30492)
// + v32 (30502) if OF|CF.
int ror_reg_inline(uint8_t fl, bool size_le16) {
    int c = 0;
    if (fl & (FLAG_OF | FLAG_CF)) c += 1;                    // 30422 v14
    if (size_le16) c += 2;                                   // 30442+30447 / 30459+30464
    if (fl & (FLAG_OF | FLAG_CF)) c += 2;                    // 30492 v29 + 30502 v32
    return c;
}

int demand_shifts(const IRInstr* instr) {
    const uint16_t op = instr->opcode();
    const IROperand& op0 = instr->operands[0];   // shift target (RMW)
    const IROperand& cnt = instr->operands[1];   // count (BranchOffset imm or CL)
    const uint8_t fl = instr->flag_liveness;

    // operand size = operands[0].reg.size (30277/30594/30820/30906/31031/31665 …).
    // The union aliases size at +1 for every kind, so this read is shape-safe.
    const bool size_le16 = op0.reg.size <= IROperandSize::S16;

    // Shared events on op0, common to all ten handlers: read0 + alloc_dst +
    // write, plus dup (rol/ror + shl/shr/sar-reg) and nz (shl/shr/sar) below.
    const int shared = shifts_read0_events(op0) + shifts_dst_events(op0) +
                       shifts_write_events(op0);

    // Path split (case_slice.c 15315/15322/15332/15366/15380): a BranchOffset
    // count → _imm; anything else (CL register) → _reg. The _reg path also reads
    // operands[1] = CL (Register class 0, extend_mode 0 → translate_gpr
    // passthrough, 0 events; 30916/30734/31551/30132/30414).
    const bool imm_path = cnt.kind == IROperandKind::BranchOffset;
    const unsigned value_b =
        static_cast<unsigned>(static_cast<uint8_t>(cnt.branch.value));

    // dup_gpr_if_alias fires (is CALLED) on some paths; its alloc is further
    // gated on the operand_to_gpr == v7 alias (shifts_dup_events).
    const int dup = shifts_dup_events(op0);
    // emit_nz_flags allocates only when SF is live and size ≤ S16 (see
    // shifts_nz_events). Added by shl/shr/sar under their per-opcode call gate.
    const int nz = shifts_nz_events(fl, op0);

    int inline_events = 0;
    int dup_events = 0;
    int nz_events = 0;
    const int bitmask = (8 << static_cast<int>(op0.reg.size)) - 1;   // 30288 rot mask

    if (imm_path) {
        switch (op) {
            case kOpcodeName_shl:
                inline_events = shl_imm_inline(fl, value_b);
                nz_events = ((fl & 0xFF) && value_b) ? nz : 0;       // 31087-31091
                break;
            case kOpcodeName_shr:
                inline_events = shr_imm_inline(fl, value_b);
                nz_events = ((fl & 0xFF) && value_b) ? nz : 0;       // 31721-31725
                break;
            case kOpcodeName_sar:
                inline_events = sar_imm_inline(fl, value_b);
                nz_events = ((fl & 0xFF) && value_b) ? nz : 0;       // 30860-30864
                break;
            case kOpcodeName_rol: {
                inline_events = rol_imm_inline(fl, value_b);
                // 30292-30296: dup called iff CF live OR (rot==1 && OF live).
                const int rot = bitmask & static_cast<int>(value_b);
                if ((fl & FLAG_CF) || (rot == 1 && (fl & FLAG_OF)))
                    dup_events = dup;
                break;
            }
            case kOpcodeName_ror: {
                inline_events = ror_imm_inline(fl, value_b, size_le16);
                // 30610-30614: dup called iff CF live OR (rot==1 && OF live).
                const int rot = bitmask & static_cast<int>(value_b);
                if ((fl & FLAG_CF) || (rot == 1 && (fl & FLAG_OF)))
                    dup_events = dup;
                break;
            }
            default:
                break;
        }
    } else {
        switch (op) {
            case kOpcodeName_shl:
                inline_events = shl_reg_inline(fl);
                nz_events = (fl & 0xFF) ? nz : 0;                    // 30942-30946
                // 30930: dup called iff OF|CF live (and flags nonzero).
                if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) dup_events = dup;
                break;
            case kOpcodeName_shr:
                inline_events = shr_reg_inline(fl);
                nz_events = (fl & 0xFF) ? nz : 0;                    // 31577-31581
                if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) dup_events = dup;
                break;
            case kOpcodeName_sar:
                inline_events = sar_reg_inline(fl);
                nz_events = (fl & 0xFF) ? nz : 0;                    // 30760-30764
                if ((fl & 0xFF) && (fl & (FLAG_OF | FLAG_CF))) dup_events = dup;
                break;
            case kOpcodeName_rol:
                inline_events = rol_reg_inline(fl, size_le16);
                if (fl & (FLAG_OF | FLAG_CF)) dup_events = dup;      // 30134 dup
                break;
            case kOpcodeName_ror:
                inline_events = ror_reg_inline(fl, size_le16);
                if (fl & (FLAG_OF | FLAG_CF)) dup_events = dup;      // 30417 dup
                break;
            default:
                break;
        }
    }

    return shared + inline_events + dup_events + nz_events;
}

// =============================================================================
// family: extends  — kOpcodeName_cbw, _cwde, _cdqe, _cwd, _cdq
// Audit: research/bridge_demand/families/extends/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. These five implicit-operand sign/zero-extend opcodes
// (AL/AX/EAX/RAX, DX:AX/EDX:EAX — NO explicit operands, so no IROperand field
// is ever read) split into two structural buckets distinguished purely by
// opcode, expressed as one switch:
//
//   Bucket A (cbw, cwd): read free_gpr_mask, perform ONE first-free
//     __clz(__rbit32(...)) allocation (case_slice.c 15532 / 15631), clear the
//     bit, emit_bitfield (cost {0,0} — AssemblerBuffer::emit only, helper
//     2818-2846), and never free the temp before the LABEL_705 epilogue reset
//     (15118). Peak 1. (The `!v266` / `v143 == S32` tests at 15535 / 15634 are
//     demand-neutral skip-the-copy optimizations on the already-allocated
//     register number.)
//   Bucket B (cdq, cdqe, cwde, cqo): load a precomputed raw instruction word
//     into v24 and goto LABEL_561 (15542-15548 / 15643-15645 / 15569-15571),
//     which emits the one word (15897) — NO allocation. Peak 0. (cqo added
//     2026-07-17 per user decision — AUDIT.md addendum.)
//
// No mem/AbsMem/Immediate/addr_size/kind/disp shape dimensions exist (no
// operand fields read). No rep_prefix access, no flag_liveness access, no
// fixed-slot allocation, no runtime BL (flags.txt all empty; MANIFEST clean).
// No shape refuses ⇒ plain int return.
// -----------------------------------------------------------------------------
int demand_extends(const IRInstr* instr) {
    switch (instr->opcode()) {
        case kOpcodeName_cbw:   // 15532 __clz(__rbit32(free_gpr_mask)), held
        case kOpcodeName_cwd:   // 15631 __clz(__rbit32(free_gpr_mask)), held
            // One inline first-free alloc, never freed before LABEL_705.
            return 1;
        default:                // cdq/cdqe/cwde/cqo → LABEL_561 raw-word emit (15897)
            // No allocation on the raw-word emit path.
            return 0;
    }
}

// =============================================================================
// family: test  — kOpcodeName_test
// Audit: research/bridge_demand/families/test/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. One handler translate_test (decomp 28152-28286).
// test is cmp's sibling: TWO reads (operands[0] = r/m, operands[1] = reg or
// imm), NO writeback, pure flag write → the demand is just the two reads'
// composed peak. Every read uses an XZR hint (28261/28281), so each first-free
// allocates exactly like alu-binary's alu_read_cost; the handler contains NO
// explicit free_temporary_gpr, so both value regs are held to the LABEL_705
// epilogue and their peaks stack. All emitters (emit_logical_imm 2759,
// emit_ands_imm 2792, emit_logical_shifted_reg 2699, is_bitmask_immediate 3552)
// are pure AssemblerBuffer::emit / arithmetic — 0 alloc.
//
// Handler branch structure (all IR-decidable):
//   * Aliased-reg fast path (28180-28226): only-ZF-live (flag mask == FLAG_ZF)
//     AND op0,op1 both Register AND op0.reg == op1.reg → a single
//     emit_logical_imm (LABEL_48, 28206-28207), NO read → demand 0. This is
//     the hot `test eax,eax`/`test rax,rax` idiom. Non-aliased → LABEL_19.
//   * High-byte-imm bitmask fast path (28227-28249): op0 is a class-1 high-byte
//     Register ((reg & 0xF0)==0x10) AND only-ZF-live AND op1 is BranchOffset
//     AND is_bitmask_immediate(value<<8) → a single emit_ands_imm (28246), NO
//     read → demand 0. Non-encodable → falls into the general path.
//   * General path (LABEL_22, 28260-28285):
//       operand_to_gpr = read_operand_to_gpr(op0, extend_mode v12, XZR)  (28261)
//       second read of op1 fires (LABEL_30, 28281) UNLESS op0,op1 are the SAME
//       register (28274-28279 reuse operand_to_gpr) or op1 is a BranchOffset
//       that is_bitmask_immediate-encodable (28263-28270, emit_ands_imm only).
//       emit_logical_shifted_reg (28282) + optional CF emit (28285) — 0 alloc.
//
// extend_mode v12 ∈ {0,1,2} (28236 v12=0 / 28257 v12=1 SF-dead / 28259 v12=2
// SF-live) — only its NONZERO-ness (plus is_64bit for a 32-bit reg src) changes
// a Register read's alloc (translate_gpr 26662-26744; alu_reg_read_allocs).
//
// op1 (the reg/imm operand) is only ever Register or BranchOffset (x86 test has
// no memory src); op0 (r/m) may be Register/MemRef/AbsMem/Immediate(RIP).
//
// DISPOSITIONS. rep_prefix: NO access anywhere in translate_test (28152-28286)
// or the transitive closure (flags.txt "(none)"); test has no LOCK form and is
// not in lockable_rmw. flag_liveness (28179-28283): read to select the fast
// paths and to derive v12/em — every use IR-decidable, modeled per-bit below.
// GS fixed-slot-7 (25901) + get_tls_base BL (25904-25906) live inside
// compute_operand_address's seg_override branch, refused by the common prefix
// (seg_override != 0) before this model runs. X22 read fast paths
// (26440/26500/26566) never fire — every read hint is XZR. No fixed-slot
// alloc, no runtime BL, every shape IR-decidable → NEVER refused.
//
// Immediate-kind (RIP) op0 shape: priced FIRST by TOTAL events (the Seq peak
// forgets read op0's freed addend transient), matching verify's neutered-free
// convention (alu Immediate precedent).
// -----------------------------------------------------------------------------

int demand_test(const IRInstr* instr) {
    const IROperand& op0 = instr->operands[0];    // 28174 r/m operand
    const IROperand& op1 = instr->operands[1];    // 28176-28177 reg/imm src
    const uint8_t fl = instr->flag_liveness;      // 28179

    // is_64bit = operand_size_is_64bit(op0) → op0.reg.size == S64 (17711/28175).
    const bool is_64bit = op0.reg.size == IROperandSize::S64;

    // Only-ZF-live mask test (28180/28229): (fl & (AF|PF_HI|OF|CF|ZF|SF)) == ZF.
    const uint8_t zf_mask = static_cast<uint8_t>(FLAG_AF | FLAG_PF_HI | FLAG_OF |
                                                 FLAG_CF | FLAG_ZF | FLAG_SF);
    const bool only_zf = (fl & zf_mask) == FLAG_ZF;

    const bool op0_reg = op0.kind == IROperandKind::Register;
    const bool op1_reg = op1.kind == IROperandKind::Register;
    const bool op1_branch = op1.kind == IROperandKind::BranchOffset;

    // Aliased-reg fast path (28180-28225): only-ZF-live, both Register, same
    // register → single emit_logical_imm, no read.
    if (only_zf && op0_reg && op1_reg &&
        op0.reg.reg.value == op1.reg.reg.value)                     // 28184-28185
        return 0;

    // High-byte-imm bitmask fast path (28227-28248): op0 is a class-1 high-byte
    // register, only-ZF-live, op1 BranchOffset, imm<<8 is bitmask-encodable →
    // single emit_ands_imm, no read.
    if (op0_reg && (op0.reg.reg.value & 0xF0) == 0x10 &&            // 28227
        only_zf && op1_branch &&                                   // 28229
        alu_is_bitmask_immediate(
            is_64bit,
            (static_cast<uint64_t>(static_cast<uint8_t>(op1.imm.value)) << 8)))  // 28241
        return 0;

    // extend_mode v12 nonzero (28233-28259). v12 = 0 when fl < FLAG_OF (28233)
    // or when op1 is a sign-clear BranchOffset (28253); else 1 (SF dead) / 2 (SF
    // live) at LABEL_19 (28256-28259). Only nonzero-ness matters for a reg read.
    bool em_nonzero;
    if (fl < FLAG_OF) {                                            // 28233 v12=0
        em_nonzero = false;
    } else if (op1_branch &&
               (static_cast<uint64_t>(op1.imm.value) & 0x8000000000000000ULL) == 0) {
        em_nonzero = false;                                        // 28253 → v12=0
    } else {
        em_nonzero = true;                                         // 28257/28259 v12=1|2
    }

    // Does the general path's SECOND read of op1 fire (LABEL_30, 28281)?
    //   - op1 BranchOffset: NO read iff bitmask-encodable (28265 emit_ands_imm),
    //     else read (28272 → 28274/28276 → LABEL_30).
    //   - op0,op1 both the SAME register: NO read (28278-28279 reuse op0 value).
    //   - otherwise (op0 mem/abs/imm, or op1 a different register): read.
    bool second_read;
    if (op1_branch) {
        second_read = !alu_is_bitmask_immediate(
            is_64bit, static_cast<uint64_t>(op1.imm.value));      // 28265
    } else if (op0_reg && op1_reg &&
               op0.reg.reg.value == op1.reg.reg.value) {          // 28279
        second_read = false;
    } else {
        second_read = true;                                       // 28274/28276 → 28281
    }

    // Immediate-kind (RIP/data-page) op0: honest TOTAL events (Seq peak forgets
    // read op0's freed addend transient). read op0 = 2 events (adr+addend) +
    // op1 second-read events. No writeback (unlike alu), so no +2 write term.
    if (op0.kind == IROperandKind::Immediate) {                   // 26564-26633
        const int src_events =
            second_read ? alu_read_cost(op1, em_nonzero, is_64bit).peak : 0;
        return 2 + src_events;
    }

    Seq seq;
    // 1) read_operand_to_gpr(op0, v12, XZR) — the compared r/m value (28261).
    //    Same helper/hint as alu-binary → alu_read_cost. Held to the epilogue
    //    (no free_temporary_gpr in translate_test).
    seq.step(alu_read_cost(op0, em_nonzero, is_64bit));
    // 2) the SECOND read of op1 when it fires (28281). Also held to the epilogue,
    //    so it stacks on op0's survivor (no free between the two reads).
    if (second_read)
        seq.step(alu_read_cost(op1, em_nonzero, is_64bit));
    // 3) emit_logical_shifted_reg (28282) + optional CF emit (28285) — 0 alloc.
    return seq.demand();
}

// =============================================================================
// family: mul-imul  — kOpcodeName_mul, kOpcodeName_imul
// Audit: research/bridge_demand/families/mul-imul/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. ONE handler translate_imul_mul (decomp 28964-29243)
// serves BOTH opcodes and ALL THREE x86 form classes, distinguished purely by
// insn->num_operands (an IR field) and, within the flag block, by opcode:
//   * form (a) one-operand widening `mul/imul r/m` (rDX:rAX ← rAX × r/m):
//       num_operands == 1 → 29040. Also the fallback for num_operands ∉ {2,3}
//       (29054 `(num_operands & 0xFE) != 2` → goto LABEL_24).
//   * form (b) two-operand `imul r, r/m`:  num_operands == 2 → 29056 v13=1.
//   * form (c) three-operand `imul r, r/m, imm`: num_operands == 3 → v13=2.
//   forms (b)/(c) share the two-read path (29056-29071); only v13 (which of
//   operands[1]/[2] is the second read) differs — a shape, not a split.
//
// COUNTING CONVENTION — TOTAL EVENTS (frees neutered), like the shifts / alu
// PEAK-vs-TOTAL families: the S8/S16 imul flag path frees two temps
// (free_temporary_gpr 29231-29232) that verify's neutered-free `actual` still
// counts, and the handler has no other frees before the LABEL_705 epilogue
// reset (15117-15121). So demand = the number of first-free
// __clz(__rbit32(free_gpr_mask)) events reached on the shape's path, handler +
// callees. Composed directly (not the Seq peak idiom, which models frees).
//
// First-free __clz sites in the handler (all others are emit-only helpers —
// emit_madd 3260, emit_bitfield 2818, emit_mov_reg 3285, emit_add_imm 2525,
// emit_add_sub_shifted_reg 2635, emit_logical_imm 2759, emit_movn 3295,
// emit_csel 2922, emit_msr 3320 — verified verbatim, no free_gpr_mask/__clz):
//   29070  product reg   (forms b/c only)          — held
//   29078  madd-hi temp  (size ≤ S16, LABEL_25)    — held
//   29102  madd-hi temp  (size == S32 && v9)        — held
//   29129  alias temp    (size == S64 && v9 && v23) — held
//   29163+29168  v45,v47 overflow movn/csel pair (LABEL_74, OF|CF live) — held
//   29190+29195 / 29217+29222  v32,v34 (S8/S16 imul flag, LABEL_52) — FREED
//                              29231-29232, but counted (neutered convention)
//
// Reads (all XZR hint → each first-free allocates like alu-binary's
// alu_read_cost; the value regs are held to the epilogue):
//   form (a): translate_gpr(accumulator, extend v7, XZR)   (29047) +
//             read_operand_to_gpr(operands[0], extend v7, XZR) (29048)
//   form (b/c): read_operand_to_gpr(op[num_operands!=2], 2, XZR) (29060) +
//               read_operand_to_gpr(op[v13], 2, XZR)             (29061)
// v7 = 2 (imul) / 1 (mul) (29033-29036); is_64bit arg v11: form (a)
// `size==S32 && v9a || size==S64` (29043), form (b/c)
// `(fl&(OF|CF))!=0 && size==S32 || size==S64` (29052).
//
// The accumulator read (29047) reads the implicit AL/AX/EAX/RAX arch register
// (`qword_43BD8[size]`): translate_gpr under XZR + extend allocates 1 for the
// S8 low-byte extract (26666) and the S16 extract (26688), 1 for S32 only when
// is_64bit (26721), 0 for S64 passthrough (26746).
//
// The LABEL_25 mid-temp gate v9 and the LABEL_52 flag block are governed by
// flag_liveness. Form (a)'s v9a (29042) folds in a `dword_4C9F0[size] &
// insn->_pad08` term whose table is not in the package — NOT cleanly
// IR-decidable, so per the demand rule ("others fold to max") the form-(a)
// mid-temp is counted whenever it could fire. The LABEL_52 entry gate is the
// clean `flag_liveness & (OF|CF)` (29145), fully decidable. The S64 alias
// temp (29129) is gated on v23 = `v19==v14 || v19==operand_to_gpr` (29122) —
// a run-time register-number comparison, NOT IR-decidable → folded to max.
//
// DISPOSITIONS. rep_prefix: NO access anywhere in translate_imul_mul
// (28964-29243) or the transitive closure (flags.txt rep_prefix section:
// (none), grep-confirmed); mul/imul have no LOCK form and are not in
// lockable_rmw. flag_liveness (29037/29052/29145): (OF|CF) drives v9/v11 and
// gates the LABEL_52 overflow block — every use IR-decidable, modeled per-bit
// below (the S64-unconditional `|| size==S64` term of 29052 is honored). GS
// fixed-slot-7 (25901) + get_tls_base BL (25904-25906) live inside
// compute_operand_address's seg_override branch (25882), refused by the common
// prefix (seg_override != 0) before this model runs — the excluded slot-7 path
// is unreachable here. X22 read fast paths (26440/26500/26566) never fire —
// every read hint is XZR. addr_size S32 handled by alu_read_cost's MemRef/
// AbsMem rows (the held value reg absorbs the address, {1} every S32 shape,
// ADDR32.md). NO shape refuses: no reachable fixed-slot alloc, no runtime BL,
// every branch decidable from IRInstr/IROperand fields. Table v3.1;
// discrepancy flags: NONE.
// -----------------------------------------------------------------------------

// read_operand_to_gpr(operand, extend, XZR) event count as invoked by
// translate_imul_mul (29048/29060/29061). Same helper/hint as alu_read_cost,
// EXCEPT one traced correction for a base-only MemRef with a NON-encodable disp:
// read_operand_to_gpr first-free allocates the value reg (26449) and passes it
// as the prefetch/compute address hint (26492) — a NON-XZR hint. For that shape
// compute_mem_operand_address's LABEL_87 (26332-26343) cannot fold the disp
// materialization into the (non-XZR) hint and allocates a SEPARATE scratch
// (26336), so the read costs 2, not 1 (matrix fixture: `mul [rsi+0x12355]`
// actual=2). Every other addressing shape (encodable disp, disp==0, SIB,
// index-only, addr32 base) folds into the value reg → 1. Register/Immediate/
// AbsMem/BranchOffset are identical to alu_read_cost.
int mul_read_events(const IROperand& op, bool em_nonzero, bool is_64bit) {
    if (op.kind == IROperandKind::MemRef) {
        const bool has_base = (op.mem.mem_flags & 1) != 0;      // 26069-26070
        const bool has_index = (op.mem.mem_flags & 2) != 0;
        // base-only + non-encodable disp: value reg (26449) + disp temp (26336).
        if (has_base && !has_index && op.mem.disp != 0 &&
            !disp_add_encodable(op.mem.disp))                   // 26310-26343 LABEL_87
            return 2;
        return 1;                                              // value reg absorbs the address
    }
    return alu_read_cost(op, em_nonzero, is_64bit).peak;
}

// read_operand_to_gpr / translate_gpr of the implicit accumulator (form a,
// 29047): AL/AX/EAX/RAX by `size`. XZR hint, extend v7 nonzero.
int mul_acc_read_events(const IROperand& op0, bool is_64bit) {
    switch (op0.reg.size) {
        case IROperandSize::S8:                       // AL, class 0 extract (26666)
        case IROperandSize::S16:                      // AX, class 2 extract (26688)
            return 1;
        case IROperandSize::S32:                      // EAX, class 3 (26721 a2==1)
            return is_64bit ? 1 : 0;
        default:                                      // RAX, S64 passthrough (26746)
            return 0;
    }
}

int demand_mul_imul(const IRInstr* instr) {
    const uint16_t op = instr->opcode();          // mul 0x47 / imul 0x32
    const IROperand& op0 = instr->operands[0];    // 29016-29024 dst / accumulator sizing
    const uint8_t fl = instr->flag_liveness;      // 29037
    const int nops = instr->num_operands;         // 29039

    // size = operands[0].reg.size (29024). The union aliases .reg.size at +1
    // for every operand kind, so this read is shape-safe.
    const IROperandSize size = op0.reg.size;
    const bool of_cf_live = (fl & (FLAG_OF | FLAG_CF)) != 0;   // 29037 v8 / 29145

    // Form dispatch (29040 / 29054): num_operands==1 → form (a); ∈{2,3} → the
    // two-read path; anything else falls back to the form-(a) path (LABEL_24).
    const bool two_read = (nops == 2 || nops == 3);              // 29054 &0xFE==2
    const bool imul = (op == kOpcodeName_imul);

    // extend_mode v7 for the reads (29033-29036): imul 2, mul 1 — nonzero either
    // way, so a Register read allocates per alu_reg_read_allocs.
    const bool em_nonzero = true;

    // is_64bit arg v11 to the reads. Form (a): 29043 `size==S32 && v9a ||
    // size==S64`; form (b/c): 29052 `(fl&(OF|CF))!=0 && size==S32 || size==S64`.
    // Only affects a class-3 (32-bit) Register read. For a class-3 read the
    // form-(a) v9a term reduces to OF|CF liveness: the matrix confirms a
    // flags-dead `mull r/m` allocates 0 (rows 10/34), so the `dword_4C9F0[S32] &
    // _pad08` addend contributes nothing at S32. So both forms use of_cf_live.
    const bool is_64bit =
        size == IROperandSize::S64 ||
        (size == IROperandSize::S32 && of_cf_live);

    int events = 0;

    // ---- Reads ----------------------------------------------------------------
    if (!two_read) {
        // Form (a) one-operand widening: accumulator read (29047) + operands[0]
        // read (29048). operands[0] is the r/m factor (Register / MemRef /
        // AbsMem / Immediate).
        events += mul_acc_read_events(op0, is_64bit);            // 29047 translate_gpr
        events += mul_read_events(op0, em_nonzero, is_64bit);    // 29048 read_operand_to_gpr
    } else {
        // Forms (b)/(c): two source reads (29060/29061) + the product register
        // (29070, first-free, never freed). For num_operands==2 the reads are
        // operands[0] and operands[1]; for ==3 they are operands[1] and
        // operands[2] (the immediate).
        const IROperand& ra = instr->operands[nops != 2 ? 1 : 0];   // 29060
        const IROperand& rb = instr->operands[nops != 2 ? 2 : 1];   // 29061 v13
        events += mul_read_events(ra, /*em_nonzero=*/true, is_64bit);
        events += mul_read_events(rb, /*em_nonzero=*/true, is_64bit);
        events += 1;                                              // 29070 product reg
    }

    // ---- LABEL_25 mid-temp (madd high half / alias) ---------------------------
    // size ≤ S16: one temp always (29078, NOT gated on v9). size == S32: one iff
    // v9 (29097→29102). size == S64: one iff v9 AND the v23 alias fires
    // (29116→29122-29130). v9 is OF|CF liveness for every form (for the S32/S64
    // sites the form-(a) 29042 table addend is 0 — matrix rows 10/14/34/38: a
    // flags-dead `mul/imul r/m32|64 reg` allocates 0). The S64 alias v23 =
    // `v19==v14 || v19==operand_to_gpr` (29122) is register-number-dependent;
    // the matrix pins its IR-decidable shape:
    //   two-operand (nops==2): fires — dst operands[0] (v19) is also the first
    //     read (v14) (rows 60/68 reg+mem q, act 4/5).
    //   three-operand (nops==3): never — the reads are operands[1]/[2] ≠ dst
    //     (rows 74/86, act one below the two-operand analog).
    //   one-operand widening (form a): v19=0 (29049) and the accumulator read
    //     v14 passes through as RAX (index 0, 29047 S64 passthrough) so v19==v14
    //     ⇒ the alias fires for a Register/Immediate/AbsMem operand — EXCEPT a
    //     MemRef operand, whose address computation makes v14 non-zero so the
    //     alias misses (matrix: reg q row 12 act 3 fires, RIP-Imm row 50 act 5
    //     fires, mem q row 18 act 4 does NOT — read(2)+LABEL_52(2), no mid temp).
    if (size <= IROperandSize::S16) {
        events += 1;                                             // 29078
    } else if (size == IROperandSize::S32) {
        if (of_cf_live)                                         // 29097 v9
            events += 1;                                         // 29102
    } else {  // S64, 29116 v9 + 29122 v23
        const bool alias = two_read ? (nops == 2)
                                    : (op0.kind != IROperandKind::MemRef);
        if (of_cf_live && alias)
            events += 1;                                         // 29129 alias temp
    }

    // ---- LABEL_52 overflow flag block (only when OF|CF live, 29145) -----------
    if (of_cf_live) {
        if (size == IROperandSize::S32 || size == IROperandSize::S64) {
            // `size - 2 < S32` (29147): the S32/S64 branch. Allocates v45+v47
            // (29163/29168) then returns (29174).
            events += 2;
        } else {
            // S8/S16 (29180 if(size) → S16 / else → S8): imul allocates v32+v34
            // (29190+29195 / 29217+29222, freed 29231-29232 — counted) then
            // falls to LABEL_74's v45+v47; mul emits (29152/29240) then LABEL_74.
            events += imul ? 4 : 2;                             // 29190-29232 + 29163-29168
        }
    }

    return events;
}

// =============================================================================
// family: sse-arith  — kOpcodeName_addss/_addsd/_subss/_subsd/_mulss/_mulsd/
//                      _divss/_divsd/_sqrtss/_sqrtsd/_rsqrtss/_rcpss
// Audit: research/bridge_demand/families/sse-arith/AUDIT.md (2026-07-17)
//
// SPLIT REQUIRED? — NO. All twelve reach one of four thin translate functions
// (translate_addsd_..._subss 33597 / translate_rcpss 34138 / translate_rsqrtss
// 34195 / translate_sqrtsd_sqrtss 34261) that share one GPR-relevant skeleton:
//   prepare_xmm_scalar_operands(a1, &op[0], _, &op[1], _, &op[2], _, _, _) (33608/34144/34201/34271)
//   <emit one scalar-FP word>
//   emit_xmm_scalar_writeback(a1, _, fpr_info)                             (33618/34148/34205/34279)
// The opcode only selects the emitted FP word — no allocation difference.
//
// operands[1] is asserted Register (27495) — never memory. The ONLY GPR path
// is read_xmm_scalar_src_fpr(result, &operands[2], scalar_kind) (27505), the
// folded scalar SOURCE. Everything else in prepare_xmm_scalar_operands
// (translate_vector_low 27506/27507, copy_xmm_state 27526, maybe_spill_xmm_state
// 27542, alloc_tmp_fpr 27554, set_xmm_state 27564) is FPR/state-side only.
//
// read_xmm_scalar_src_fpr → read_xmm_operand_to_fpr (26753) → per-kind
// read_xmm_operand_to_fpr_maybe_alloc with address hint 0x1F (XZR):
//   Register/XMM src: 0 GPR (27607 return translate_vector_low).
//   MemRef  src: translate_prefetch_impl(...,0x1F) (26956) — XZR-hint prefetch,
//                per-shape count (mov_prefetch_allocs; 1 for every S32 shape),
//                held to LABEL_705.
//   AbsMem  src: compute_operand_address(...,0x1F) AbsMem (26940→25930-25941) — 1, held.
//   Immediate src (RIP/data-page): aligned adr temp (26929) OR compute_operand_address
//                Immediate (26940→25944-25972) peak 2; alignment not IR-decidable
//                (operand_addr_is_aligned reads runtime text_base_align_offset 25516)
//                → fold to peak 2, held 1.
// Scalar source size is S32/S64, so read_xmm_operand_to_fpr's per-kind loop runs
// once (26788 v5==2 only for S256); the S256 double-read does not occur.
//
// Writeback flush tail (27638-27639) fires only when fpr_info[5]==1, set iff
// src1 (operands[0], the dst XMM) has register class 0x90/0xA0 (27567-27571) —
// i.e. a YMM-class dst. flush_xmm_to_thread_context (27095-27111) allocs one
// GPR (27105) and frees it (27110) → transient {1,0}. For these SSE (non-VEX)
// opcodes the dst is XMM class 0x50, so the flush term is 0; modeled anyway on
// the YMM-class dst for completeness.
//
// rep_prefix / flag_liveness: NO access anywhere in the package (grep-clean;
// no LOCK/REP form, not in lockable_rmw; SSE arith writes MXCSR not EFLAGS).
// GS fixed-slot-7 (25901) / get_tls_base BL (25904-25906) sit behind
// seg_override (25882), refused by the common prefix. Table v3.1; discrepancy
// flags: NONE.
// -----------------------------------------------------------------------------

int demand_sse_arith(const IRInstr* instr) {
    const IROperand& dst = instr->operands[0];   // 33608 src1 / dst XMM
    const IROperand& src = instr->operands[2];   // 33608 dst-param = folded scalar source

    Seq seq;
    // 27505 read_xmm_scalar_src_fpr(result, &operands[2], scalar_kind): the
    // non-Register kinds route to read_xmm_operand_to_fpr (27591), the SAME
    // shared callee the sse-mov-scalar load path prices — reuse its cost
    // helper (Register src differs only in the 0-GPR return site, 27607
    // translate_vector_low vs 26962-26970).
    seq.step(movs_read_xmm_cost(src));

    // 27638-27639 emit_xmm_scalar_writeback flush tail: fires only for a
    // YMM-class dst (27567-27571 src1.reg & 0xF0 ∈ {0x90,0xA0}). One transient
    // {1,0} on top of any held source-address temp. XMM dst (class 0x50) → 0.
    // For an Immediate (RIP) source, charge the read's freed addend transient
    // as if still held under the total-event convention (alu PEAK-vs-TOTAL
    // note; same corner as demand_sse_mov_scalar's flush): adr temp held +
    // addend + flush = 3 total events, true concurrent peak 2 (matrix:
    // vaddss 0x100(%rip),%xmm2 actual=3).
    const unsigned dst_cls = dst.reg.reg.value & 0xF0;
    if (dst_cls == 0x90 || dst_cls == 0xA0) {
        const bool imm_src = src.kind == IROperandKind::Immediate;
        seq.step(Cost{static_cast<int8_t>(imm_src ? 2 : 1), 0});  // 27105
    }

    return seq.demand();
}

// =============================================================================
// family: sahf  — kOpcodeName_sahf
// Audit: research/bridge_demand/families/sahf/AUDIT.md (2026-07-31)
//
// SPLIT REQUIRED? — NO. One opcode, one case group of two lines (case_slice.c
// 15328-15329: `translate_sahf(a1); goto LABEL_705;`), one handler
// translate_sahf (decomp 25063-25095).
//
// sahf has NO explicit operands (implicit AH → EFLAGS) and the handler reads
// no IROperand field at all — grep over the whole package finds no `operands`,
// `mem_flags`, `disp`, `kind`, `addr_size`, `shift_amount`, `seg_override`.
// So there is exactly ONE shape and demand is a constant: no kind axis, no
// Immediate/AbsMem-destination corner, no S32-addressing (ADDR32) corner, and
// compute_operand_address / translate_prefetch_impl are never reached (hence
// the GS slot-7 / get_tls_base exclusion is not even relevant here).
//
// The handler performs TWO first-free __clz(__rbit32(free_gpr_mask)) allocs:
//   25074  v3       (the AH source scratch, consumed last by emit_msr 25094)
//   25080  dst_gpr  (the NZCV assembly scratch, used 25082-25093)
// They are concurrent — v3 is still live at 25094 — and there is NO
// free_temporary_gpr anywhere in the package, so both are held until the
// LABEL_705 epilogue mask reset (15118). Rosetta itself requires two: 25072
// aborts if the pool is empty before the first alloc and 25077 aborts if it is
// empty after it ("no temporary GPR available to allocate", 25079).
//
// Everything between the two allocs and the return is a pure AArch64 word
// encoder with cost {0,0}: emit_bitfield (2818-2846, ten calls), emit_csel
// (2922-2935), emit_msr (3320-3325) and emit_logical_shifted_reg (2699-2729,
// pruned from the package as a known allocation-free encoder — body verified
// against the same pinned decomp sha; see the AUDIT's manifest note).
//
// DISPOSITIONS. rep_prefix: NO access anywhere in the package (flags.txt
// "(none)"); sahf has no LOCK/REP encoding and is not in lockable_rmw.
// flag_liveness: NO access (flags.txt "(none)") — notable because sahf is a
// pure flag writer, yet the emit block 25082-25094 is unconditional
// straight-line code with no flag gate, so demand is 2 for every liveness
// value. No fixed-slot alloc, no runtime BL, no X22/slot-0 fast path (the
// handler takes no register hint at all). No shape refuses ⇒ plain int.
// HELPER_COSTS table v3.1 consumed; discrepancy flags: NONE (this family calls
// no tabled helper).
// -----------------------------------------------------------------------------

int demand_sahf(const IRInstr* /*instr*/) {
    Seq seq;
    // 25074 v3 = __clz(__rbit32(free_gpr_mask)) — first-free, held to 15118.
    seq.step(Cost{1, 1});
    // 25080 dst_gpr = __clz(__rbit32(v4)) — first-free, held to 15118, live
    // concurrently with v3 (both feed emit_bitfield 25093 / emit_msr 25094).
    seq.step(Cost{1, 1});
    // 25082-25094 emit_bitfield / emit_csel / emit_logical_shifted_reg /
    // emit_msr — pure AssemblerBuffer::emit encoders, {0,0}. No free.
    return seq.demand();
}

}  // namespace

// =============================================================================
// Dispatch. Audited families are listed explicitly and route to their
// demand_<family>() function; everything else takes the conservative
// fallback. Family sections are append-only — one delimited block per landed
// audit, in research/bridge_demand/STATUS.md order.
// =============================================================================

// Prefix checks + family dispatch. Returns the family's HONEST demand total
// (which may exceed kMaxBridgeDemand — the ceiling is bridging policy and
// lives at the call sites: Translator.cpp's bridge check and the
// x87_run_length lookahead), or nullopt only for UNPRICEABLE shapes:
// unaudited opcodes, shapes not decidable from IR fields, policy refusals
// (segment overrides, LOCK), and audited shapes whose exact total was never
// established.
std::optional<int> X87Cache::gap_gpr_demand(const IRInstr* instr) {
    // ---- Common refusal prefix (shapes no audit covers) ----
    bool has_mem = false;
    const int n = instr->num_operands < 4 ? instr->num_operands : 4;
    for (int i = 0; i < n; i++) {
        const auto& o = instr->operands[i];
        switch (o.kind) {
            case IROperandKind::MemRef:
                // Segment overrides are refused by POLICY (2026-07-17): the
                // GS path is a fixed-slot x29 demand + a runtime get_tls_base
                // BL that may clobber pinned cache GPRs mid-run — a
                // correctness hazard no demand count expresses (the FS
                // sub-branch is unaudited). 64-bit and 32-bit addressing are
                // audited (S32: research/bridge_demand/ADDR32.md — vital for
                // 32-bit games, where every mem operand is S32); anything
                // else (S16 addressing) stays refused.
                if (o.mem.seg_override != 0 ||
                    (o.mem.addr_size != IROperandSize::S64 &&
                     o.mem.addr_size != IROperandSize::S32))
                    return std::nullopt;
                has_mem = true;
                break;
            case IROperandKind::AbsMem:
            case IROperandKind::Immediate:
                // Both kinds reach compute_operand_address, which reads the
                // +3 byte as seg_override BEFORE any kind dispatch (decomp
                // 25882) — on these structs +3 is _pad that the decoder is
                // believed to zero. Enforce it instead of assuming: a nonzero
                // byte would route into the fixed-slot-7 / get_tls_base seg
                // branch that no audit admits.
                if (o.mem.seg_override != 0)
                    return std::nullopt;
                has_mem = true;
                break;
            case IROperandKind::SegmentRegister:
                // mov to/from a segment register — unaudited.
                return std::nullopt;
            default:
                break;
        }
    }
    // LOCK-prefixed RMW memory forms translate as ldaxr/stlxr exclusive
    // loops, not the audited straight-line paths. Refuse until a family
    // audit models the exclusive loop explicitly.
    if (instr->rep_prefix != 0 && has_mem && lockable_rmw(instr->opcode()))
        return std::nullopt;

    switch (instr->opcode()) {
        // ---- audited families (appended by the bridge_demand workflow) ----

        // ======================== family: mov-movnti =======================
        // Audit: research/bridge_demand/families/mov-movnti/AUDIT.md (2026-07-16)
        // Single handler translate_mov_movnti (decomp 17760-17820) for both
        // opcodes: read_operand_to_gpr(src) then write_gpr_to_operand(dst).
        case kOpcodeName_mov:
        case kOpcodeName_movnti:
            return demand_mov_movnti(instr);

        // =========================== family: lea ===========================
        // Audit: research/bridge_demand/families/lea/AUDIT.md (2026-07-17)
        // Single handler (decomp 16121-16128): alloc_dst_gpr(dst) then
        // compute_operand_address(src, hint=dst) then write_gpr_to_operand(dst).
        // compute_operand_address gets a non-XZR hint, so it never returns an
        // address survivor; peak demand is 1 across all shapes.
        case kOpcodeName_lea:
            return demand_lea(instr);

        // ===================== family: sse-mov-scalar ======================
        // Audit: research/bridge_demand/families/sse-mov-scalar/AUDIT.md (2026-07-17)
        // Single handler translate_movsd_movss (decomp 40841-40935) for both
        // opcodes: store (write_fpr_to_mem_operand, early return), load
        // (read_xmm_operand_to_fpr + optional YMM flush), or reg↔reg (0 GPR).
        // Peak demand 2 across all shapes; never refused.
        case kOpcodeName_movss:
        case kOpcodeName_movsd:
            return demand_sse_mov_scalar(instr);

        // ======================== family: alu-binary =======================
        // Audit: research/bridge_demand/families/alu-binary/AUDIT.md (2026-07-17)
        // One handler skeleton per opcode (translate_add/sub/cmp/and/or/xor):
        // alloc_dst_gpr(op0) [cmp: a flag temp], read op0, optional second read
        // of op1 (non-encodable imm / mem src), free, write op0 [cmp: none].
        // Peak demand ≤ 4 (mem-dst + non-encodable-imm src; PEAK-vs-TOTAL note).
        // LOCK mem-RMW refused by the common prefix; never otherwise refused.
        case kOpcodeName_add:
        case kOpcodeName_sub:
        case kOpcodeName_and:
        case kOpcodeName_or:
        case kOpcodeName_xor:
        case kOpcodeName_cmp:
            return demand_alu_binary(instr);

        // ========================== family: adc-sbb ========================
        // Audit: research/bridge_demand/families/adc-sbb/AUDIT.md (2026-07-17)
        // Two handlers (translate_adc/translate_sbb), one model keyed on opcode
        // + shape (no split): alloc_dst_gpr(op0) + read op0 + optional second
        // read of op1 (adc: unless all-flags-dead imm-0; sbb: always, except the
        // `sbb r,r` aliasing fast path with NO reads) + write op0. Reuses the
        // alu-binary shape helpers (same XZR-hint callees). Peak ≤4; Immediate-
        // kind (RIP) RMW dst totals 5 + src events (honest, over the ceiling).
        // rep_prefix==1 (LOCK) → mem-store exclusive path (LOCK+mem refused by
        // the common prefix via lockable_rmw; LOCK+register malformed) → REFUSE.
        case kOpcodeName_adc:
        case kOpcodeName_sbb:
            if (instr->rep_prefix == 1)
                return std::nullopt;
            return demand_adc_sbb(instr);

        // ==================== family: movzx-movsx-movsxd ====================
        // Audit: research/bridge_demand/families/movzx-movsx-movsxd/AUDIT.md (2026-07-17)
        // Two case groups (movsx/movsxd share; movzx separate) with ONE
        // allocation skeleton — differ only in the read extend_mode (2 vs 1),
        // which changes no alloc under the always-non-XZR dst-register hint:
        // alloc_dst_gpr(op0 reg) then read_operand_to_gpr(op1, hint=dst) then
        // write_gpr_to_operand(op0 reg). Peak demand 1 for every shape; never
        // refused (no fixed slot, no runtime BL, all shapes IR-decidable).
        case kOpcodeName_movzx:
        case kOpcodeName_movsx:
        case kOpcodeName_movsxd:
            return demand_movzx_movsx_movsxd(instr);

        // ========================= family: push-pop ========================
        // Audit: research/bridge_demand/families/push-pop/AUDIT.md (2026-07-17)
        // push/pop of a non-RSP register take a zero-alloc peephole fast-path;
        // otherwise push/pushd/pushw → translate_pushd_pushw (read src +
        // RSP-alias dup) and pop/popd/popw → translate_popd_popw (alloc dst +
        // RSP-alias fixup + write). The w-forms share the handlers with an
        // alloc-neutral size arg. Peak demand ≤ 3 (pop RIP-Imm dst); never refused
        // (GS fixed-slot/BL behind seg_override, refused by the common prefix).
        case kOpcodeName_push:
        case kOpcodeName_pop:
        case kOpcodeName_pushd:
        case kOpcodeName_popd:
        case kOpcodeName_pushw:
        case kOpcodeName_popw:
            return demand_push_pop(instr);

        // ========================= family: alu-unary =======================
        // Audit: research/bridge_demand/families/alu-unary/AUDIT.md (2026-07-17)
        // Four handlers (translate_inc/dec/neg/not), three non-LOCK skeletons,
        // one model keyed on opcode + operand shape (no split). alloc_dst_gpr +
        // read_operand_to_gpr(op0, XZR) + optional inc/dec CF csel temp +
        // write_gpr_to_operand(op0); not reads before alloc and never frees.
        // Peak demand ≤ 4 (mem-dst inc/dec with CF live); Immediate-kind (RIP)
        // RMW dst totals 5-6 (matrix-exact; gate-refused above the ceiling).
        // rep_prefix==1 selects the unaudited exclusive-loop path —
        // LOCK+mem is refused by the common prefix (lockable_rmw), LOCK+register
        // is malformed and refused here.
        case kOpcodeName_inc:
        case kOpcodeName_dec:
        case kOpcodeName_neg:
        case kOpcodeName_not:
            // rep_prefix==1 (LOCK) → exclusive-loop path, unaudited. LOCK+mem
            // already refused by the common prefix; refuse the malformed
            // LOCK+register form too (decomp 21630/21760/21852/27975).
            if (instr->rep_prefix == 1)
                return std::nullopt;
            return demand_alu_unary(instr);

        // ========================== family: cmovcc =========================
        // Audit: research/bridge_demand/families/cmovcc/AUDIT.md (2026-07-17)
        // Single case group (decomp 15063-15121): read_operand_to_gpr(src,
        // extend_mode 0, XZR) + alloc_dst_gpr(dst reg) + a parity-cc-gated
        // 3-temp inline block (P/NP) or emit_csel (all other cc, 0 alloc) +
        // write_gpr_to_operand(dst reg). Parity demand = read.held+dst.held+3;
        // REFUSES when that exceeds 4 (≤S16 reg dst + temp-holding src). All
        // other shapes ≤ 4. GS fixed-slot/BL behind seg_override, refused by
        // the common prefix.
        case kOpcodeName_cmovcc:
            return demand_cmovcc(instr);

        // ========================== family: shifts =========================
        // Audit: research/bridge_demand/families/shifts/AUDIT.md (2026-07-17)
        // Five case groups (case_slice.c 15314-15384) share one dispatch:
        // BranchOffset count → translate_<op>_imm, else (CL) → translate_<op>_reg
        // (ten handlers). operands[0] is the RMW target, operands[1] the count.
        // No split — total-event counts composed directly (frees neutered by
        // verify). No LOCK form (rep_prefix unread); flag_liveness + the immediate
        // byte + operand size fully decide every branch. GS fixed-slot-7 /
        // get_tls_base BL behind seg_override, refused by the common prefix. NEVER
        // refused on demand grounds; honest totals may exceed the ceiling (ror
        // reg S8/S16 with OF|CF live) — the callers apply it.
        case kOpcodeName_shl:
        case kOpcodeName_shr:
        case kOpcodeName_sar:
        case kOpcodeName_rol:
        case kOpcodeName_ror:
            return demand_shifts(instr);

        // ======================== family: nop-wait =========================
        // Audit: research/bridge_demand/families/nop-wait/AUDIT.md (2026-07-16)
        // No translate_insn case exists for either opcode — both fall to the
        // default label (decomp 17531-17532), which jumps straight to the
        // epilogue: nothing emitted, nothing allocated.
        case kOpcodeName_nop:
        case kOpcodeName_wait:
            return 0;

        // ========================== family: extends ========================
        // Audit: research/bridge_demand/families/extends/AUDIT.md (2026-07-17)
        // Five implicit-operand extend opcodes, two structural buckets keyed
        // on opcode: cbw/cwd perform ONE inline first-free __clz(__rbit32(...))
        // alloc held to the epilogue (case_slice.c 15532/15631) → demand 1;
        // cdq/cdqe/cwde emit one precomputed raw word via LABEL_561 (15897)
        // with no allocation → demand 0. No operand fields read (single shape
        // per opcode), no rep_prefix/flag_liveness, no fixed slot, no runtime
        // BL. Never refused.
        case kOpcodeName_cbw:
        case kOpcodeName_cwde:
        case kOpcodeName_cdqe:
        case kOpcodeName_cwd:
        case kOpcodeName_cdq:
        case kOpcodeName_cqo:   // added 2026-07-17 (AUDIT.md addendum): Bucket B, 0
            return demand_extends(instr);

        // ========================== family: setcc ==========================
        // Audit: research/bridge_demand/families/setcc/AUDIT.md (2026-07-17)
        // Single case group (case_slice.c 15347-15363): alloc_dst_gpr(operands[1])
        // → cc block (0xB/0xA carry helpers or translate_condition_code+emit_csel,
        // all emit-only, 0 alloc — parity ccs cost nothing here, unlike cmovcc)
        // → write_gpr_to_operand(operands[1]). dst is always r/m8 (S8), so
        // alloc_dst_gpr allocates {1,1} on every shape; cc is not a demand axis.
        // Peak demand: Register dst 1, MemRef(enc)/... 1, MemRef(non-enc)/S32/
        // AbsMem 2, Immediate(RIP) dst 3. Never refused (GS fixed-slot/BL behind
        // seg_override, refused by the common prefix; every shape IR-decidable).
        case kOpcodeName_setcc:
            return demand_setcc(instr);

        // =========================== family: test ==========================
        // Audit: research/bridge_demand/families/test/AUDIT.md (2026-07-17)
        // Single handler translate_test (decomp 28152-28286), cmp's sibling:
        // two XZR-hint reads (op0 r/m, op1 reg/imm), NO writeback. Aliased-reg
        // and high-byte-imm-bitmask fast paths cost 0; otherwise read op0 +
        // (optional) second read of op1, both held to the epilogue. Peak ≤ 4;
        // Immediate-kind (RIP) op0 priced by total events. Never refused (no
        // fixed slot, no runtime BL, no rep_prefix, every shape IR-decidable;
        // GS seg path behind the common prefix). The fnstsw-adjacent test tail
        // is kept out of the gap scan by X87Cache::lookahead's guard — this
        // model prices every test shape honestly with no adjacency logic.
        case kOpcodeName_test:
            return demand_test(instr);

        // ========================= family: mul-imul ========================
        // Audit: research/bridge_demand/families/mul-imul/AUDIT.md (2026-07-17)
        // ONE handler translate_imul_mul (decomp 28964-29243) for both opcodes
        // and all three x86 form classes, keyed on num_operands (1 = widening
        // mul/imul r/m rDX:rAX; 2 = imul r,r/m; 3 = imul r,r/m,imm) — no split.
        // Total-event count (frees neutered): reads (accumulator + r/m for the
        // widening form; two sources + a product reg for the two-read forms) +
        // a size-gated madd-high temp + the (OF|CF)-gated overflow block
        // (S32/S64: +2; S8/S16: +2 mul / +4 imul). Honest totals can exceed the
        // ceiling for narrow OF|CF-live imul (callers apply it). NEVER refused:
        // no fixed-slot alloc, no runtime BL, every branch IR-decidable (the
        // form-(a) v9a and the S64 v23 alias fold to max). rep_prefix unread (no
        // LOCK form); GS fixed-slot/BL behind seg_override, refused by the common
        // prefix.
        case kOpcodeName_mul:
        case kOpcodeName_imul:
            return demand_mul_imul(instr);

        // ========================== family: sse-arith ======================
        // Audit: research/bridge_demand/families/sse-arith/AUDIT.md (2026-07-17)
        // One skeleton (prepare_xmm_scalar_operands + emit + writeback) for all
        // twelve; the folded scalar SOURCE (operands[2]) is the only GPR axis
        // (operands[1] asserted Register). read hint is XZR: MemRef/AbsMem 1
        // (S32 always 1), Immediate(RIP) 2; +1 transient only for a YMM-class
        // dst flush (XMM dst → 0). Peak demand 2; never refused.
        case kOpcodeName_addss:
        case kOpcodeName_addsd:
        case kOpcodeName_subss:
        case kOpcodeName_subsd:
        case kOpcodeName_mulss:
        case kOpcodeName_mulsd:
        case kOpcodeName_divss:
        case kOpcodeName_divsd:
        case kOpcodeName_sqrtss:
        case kOpcodeName_sqrtsd:
        case kOpcodeName_rsqrtss:
        case kOpcodeName_rcpss:
            return demand_sse_arith(instr);

        // ============================ family: sahf =========================
        // Audit: research/bridge_demand/families/sahf/AUDIT.md (2026-07-31)
        // Single case group (case_slice.c 15328-15329) → translate_sahf
        // (decomp 25063-25095): TWO concurrent first-free allocs (25074 v3,
        // 25080 dst_gpr), both held to the LABEL_705 epilogue (no
        // free_temporary_gpr in the package); everything else is pure
        // AssemblerBuffer::emit. No operand fields read → exactly one shape,
        // constant demand 2. No rep_prefix / flag_liveness access, no
        // fixed-slot alloc, no runtime BL. Never refused.
        case kOpcodeName_sahf:
            return demand_sahf(instr);

        // ---- un-audited opcodes: refuse outright, no guessing ----
        default:
            // ALL forms refuse until the opcode's family audit lands — the
            // run breaks and Rosetta translates the instruction at a run
            // boundary with all 8 scratch GPRs free. This subsumes the old
            // guessed buckets (2 reg/imm, 4 mem, opcode refuse-list), all of
            // which under- or over-counted somewhere (e.g. the cmovcc inline
            // case truly holds 3, decomp 15083-15098). Bridging for an
            // opcode is re-enabled only by its family's audited case above.
            return std::nullopt;
    }
}
