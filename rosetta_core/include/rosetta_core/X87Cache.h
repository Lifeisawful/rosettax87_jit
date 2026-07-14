#pragma once

#include <cstdint>

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

    bool active() const;
    void invalidate();
    void invalidate(uint32_t& free_gpr_mask, uint32_t scratch_mask);
    void set_run(int run_length);
    void tick();
    uint32_t pinned_mask() const;

    // OPT-G: permutation helpers
    void reset_perm();
    bool perm_is_identity() const;

    // Scan forward from insn_idx counting consecutive handled x87 instructions.
    // disabled_ops_mask: bitmask of OpcodeId bits for disabled opcodes — stops
    // counting when a disabled opcode is encountered (it will fall back to Rosetta,
    // breaking the run from our perspective).
    static int lookahead(IRInstr* instr_array, int64_t num_instrs, int64_t insn_idx,
                         uint64_t disabled_ops_mask = 0);

    // True if `op` is an x87 opcode we have a translate_* handler for.
    static bool is_handled(uint16_t op);
};
