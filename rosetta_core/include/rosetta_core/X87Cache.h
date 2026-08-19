#pragma once

#include <cstdint>
#include <optional>

struct IRBlock;
struct IRInstr;

// OPT-1: Cross-instruction x87 base/TOP register cache.
//
// When consecutive x87 instructions appear in a block, the base address
// (X18 + x87_state_offset) and the TOP field never change between instructions
// except through our own push/pop (which update the register in-place).
// Caching these two values across instructions saves 3-4 emitted AArch64
// instructions per x87 opcode after the first in a run.
struct X87Cache {
    int8_t base_gpr = 0;        // GPR holding X87State base
    int8_t top_gpr = 0;         // GPR holding TOP
    int16_t run_remaining = 0;  // Countdown; 0 = inactive
    int8_t st_base_gpr = 0;     // GPR holding &st[0] = Xbase + kX87RegFileOff
    int8_t top_dirty = 0;       // OPT-C: 1 = push skipped store_top, TOP in memory stale
    int8_t gprs_valid = 0;           // 1 = base/top/st_base GPR numbers are meaningful
    int8_t deferred_push_count = 0;     // OPT-D: 1 = push's tag-valid update deferred (cancel on next pop)
    int8_t deferred_pop_count = 0;   // OPT-D2: number of pop tag-set-empty updates deferred to run end

    // OPT-G: Deferred FXCH — compile-time register renaming.
    // perm[i] maps logical stack depth i to physical depth offset.
    // Identity: perm[i] == i for all i.  FXCH ST(n) swaps perm[0] and perm[n].
    // Flushed at run end by emitting the minimal memory swaps (cycle decomposition).
    int8_t perm[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    int8_t perm_dirty = 0;  // 1 = permutation is non-identity

    IRBlock* prev_block = nullptr;

    // OPT-BC (ROSETTA_X87_BRIDGE_CARRY): base-address-cache + RC GPRs carried
    // across bridged gaps so the next IR run skips re-materializing them.
    // Capacity is capped at kMaxCarried TOTAL pins (bases + RC combined) on
    // top of the 3 cache pins: the allocator-contract audit only established
    // headroom for whitelisted gap translations with ≥3 scratch GPRs free.
    //
    // A carried base is keyed by the address expression modulo displacement
    // (same key as the lowering's addr_base_key_equal); `gpr` holds the
    // materialized zero-disp base. Validity: the key's guest registers are
    // unchanged since transfer — enforced by carried_drop_written (bridged
    // gap writes / IR-inlined guest writes) and by releasing everything
    // before any non-IR x87 translation (singular fldcw/fstsw can change
    // control_word / AX behind our back).
    static constexpr int kMaxCarried = 2;
    struct CarriedBase {
        uint8_t addr_size, mem_flags, base_reg, index_reg, shift_amount;  // key
        int8_t gpr = -1;   // scratch GPR holding the base; -1 = slot empty
    };
    CarriedBase carried_base[kMaxCarried];
    int8_t carried_rc_gpr = -1;  // GPR holding the cached RC field; -1 = none

    bool carried_any() const {
        return carried_base[0].gpr >= 0 || carried_base[1].gpr >= 0 ||
               carried_rc_gpr >= 0;
    }
    void carried_clear();
    // Clear all carried entries and return their GPRs to the free mask.
    void carried_release(uint32_t& free_gpr_mask);
    // Drop carried bases whose key uses a guest GPR in `guest_mask`
    // (bit per guest reg index). Freed bits come back when the caller
    // recomputes free_gpr_mask from pinned_mask().
    void carried_drop_written(uint16_t guest_mask);
    // Written-guest-GPR mask of a run-transparent instruction (conservative:
    // includes implicit writers; returns 0xFFFF when unsure).
    static uint16_t gap_written_gpr_mask(const IRInstr* instr);

    bool active() const;
    void invalidate();
    void invalidate(uint32_t& free_gpr_mask, uint32_t scratch_mask);
    void set_run(int run_length);
    void tick();
    uint32_t pinned_mask() const;

    // OPT-G: permutation helpers
    void reset_perm();
    bool perm_is_identity() const;

    // True if the opcode has a translate_* handler (participates in x87 runs).
    static bool is_handled(uint16_t op);

    // OPT-KA (ROSETTA_X87_RUNTIME_KEEPALIVE): transcendentals Rosetta lowers as
    // a runtime-routine BL whose round trip preserves the pinned cache GPRs
    // (IDA-verified: only x27/x29 are clobbered; the transcendental entry
    // chunks pass no args and write no results in x22–x24, unlike the
    // arithmetic routines). Returns the op's fixed TOP delta in stack slots
    // (-1 = helper pushes, +1 = helper pops, 0 = neutral) so the cached TOP
    // register can be adjusted to match the memory TOP the helper writes;
    // nullopt = not a keepalive op (fxtract is excluded: its push is
    // conditional on the value and control word).
    static std::optional<int> runtime_keepalive_top_delta(uint16_t op);

    // OPT-RB: peak scratch-GPR demand of Rosetta's own translation of a
    // run-transparent instruction, from the per-family audited model in
    // X87BridgeDemand.cpp (built via research/bridge_demand/WORKFLOW.md
    // against the labeled decompilation).
    //
    // Returns std::nullopt when the instruction must NOT be bridged — no
    // guessing: opcodes whose family audit hasn't landed, refused shapes
    // (segment overrides, non-64-bit addressing, LOCKed RMW memory forms,
    // shapes not decidable from IR fields). Returns the HONEST demand total —
    // which may exceed kMaxBridgeDemand; callers compare against the ceiling
    // themselves (Translator.cpp bridge check, x87_run_length lookahead). On
    // nullopt (or a total over the ceiling) the run breaks and Rosetta
    // translates the instruction at a run boundary with all 8 scratch GPRs
    // free.
    //
    // A gap is only bridgeable when demand ≤ kMaxBridgeDemand: after a carried
    // release the cache pins only its 3 fixed GPRs, so 5 of the 8 scratch GPRs
    // are free — a demand-4 op then leaves 1 spare. Anything that could need 5
    // refuses (nullopt), not squeezed into a zero-headroom pool.
    static constexpr int kMaxBridgeDemand = 4;
    static std::optional<int> gap_gpr_demand(const IRInstr* instr);

    // Scan forward from insn_idx counting consecutive handled x87 instructions.
    // disabled_ops_mask: bitmask of OpcodeId bits for disabled opcodes — stops
    // counting when a disabled opcode is encountered (it will fall back to Rosetta,
    // breaking the run from our perspective).
    // bridge (OPT-RB): additionally count short gaps (≤ kMaxBridgeGap) of
    // bridgeable instructions (gap_gpr_demand admits — the single gate for
    // both opcode safety and GPR pressure) between x87 groups. A gap is only
    // counted when another enabled x87 instruction follows it — a run NEVER
    // ends on a bridged instruction (the deferred TOP/tag flush in x87_end /
    // the IR epilogue relies on the last counted instruction being x87).
    // runtime_keepalive (OPT-KA): additionally count keepalive transcendentals
    // (runtime_keepalive_top_delta) as run members — both inside x87 groups
    // and as the x87 instruction a gap must land on.
    static constexpr int kMaxBridgeGap = 16;
    static int lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx,
                         uint64_t disabled_ops_mask = 0, bool bridge = false,
                         bool runtime_keepalive = false);
};

// True for FILD m64 / FISTP m64 / FISTTP m64 — the encodings that move a full
// 64-bit integer through an x87 slot.  An f64 slot cannot carry a 64-bit
// mantissa, so these are declined and handled by the runtime, which keeps an
// exact int64 shadow.  See the definition in X87Cache.cpp.
bool x87_is_m64_int_memop(const IRInstr& ins);
