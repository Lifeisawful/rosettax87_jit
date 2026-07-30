#pragma once

#include <cstdint>
#include <cstring>

struct TranslationResult;
struct IRInstr;
union IROperand;

namespace X87IR {

static constexpr int kMaxNodes = 128;

// ── IR opcodes ──────────────────────────────────────────────────────────────

enum class Op : uint8_t {
    // Pure values (no side effects)
    ReadSt,         // load initial stack slot (initial_depth in payload)
    LoadF64,        // load f64 from memory
    LoadF32Raw,     // load raw f32 bits from memory into an S register
    LoadI16,        // load i16, sign-extend, convert to f64
    LoadI32,        // load i32, convert to f64
    LoadI64,        // load i64, convert to f64
    ConstZero,      // 0.0
    ConstOne,       // 1.0
    ConstF64,       // arbitrary f64 constant (imm_bits in payload)

    // f32 <-> f64 conversion (pure unary). Raw-f32 values are produced only
    // by LoadF32Raw/CvtF64ToF32 and consumed only by CvtF32ToF64/StoreF32Raw;
    // stack slots always hold f64-typed nodes.
    CvtF32ToF64,    // FCVT Dd, Sn — widen (exact)
    CvtF64ToF32,    // FCVT Sd, Dn — narrow (rounds)

    // Binary arithmetic
    FAdd, FSub, FMul, FDiv,
    FNMul,          // -(inputs[0] * inputs[1])  (AArch64 FNMUL, from FNeg∘FMul)

    // FMA: inputs[0]*inputs[1] + inputs[2]  (FMADD encoding)
    //       inputs[2] - inputs[0]*inputs[1]  (FMSUB encoding)
    //       inputs[0]*inputs[1] - inputs[2]  (FNMSUB encoding)
    FMAdd,
    FMSub,
    FNMSub,

    // Unary
    FNeg, FAbs, FSqrt, FRndInt,

    // OPT-TI: cos/sin/tan(inputs[0]) via `BL _stub_{fcos,fsin,fptan}_val`
    // (d16 in/out, everything else preserved by the stub — huge/Inf/NaN
    // handled by value inside it).  Pure unary values for DSE/use-count
    // purposes; lowering additionally clears C1|C2 in status_word at the
    // node's program position, so they must be emitted in order relative to
    // FCmp/FTst/FStsw (they are: the node loop is program-ordered).  v16 is
    // excluded from the FPR pool for runs containing any of them (see
    // compile_run).  FPtanCall yields ONLY the tangent — build() pushes the
    // architectural 1.0 as a separate ConstOne node.
    FCosCall,
    FSinCall,
    FPtanCall,
    FSinCosCall,    // sin(inputs[0]) via _stub_fsincos_val (d16=sin, d17=cos);
                    // node value = the sine, the cosine is read by the
                    // adjacent FSinCosProjCos projection
    FSinCosProjCos, // the d17 (cosine) result of inputs[0], an FSinCosCall;
                    // build() emits it IMMEDIATELY after its call node and
                    // lowering relies on that adjacency (d17 must not be
                    // clobbered in between)

    // OPT-TI pow-trio: value calls whose entire math lives in the val stub's
    // assembly (no C fallback leg).  F2XM1Call = 2^inputs[0] - 1 via
    // `BL _stub_f2xm1_val` (d16 in/out; no status-word effect — the classic
    // helper touches none).  FScaleCall = scalbn-style
    // fscale(inputs[0], inputs[1]) via `BL _stub_fscale_val` (d16 = ST(0)
    // in/out, d17 = ST(1) in, consumed); lowering additionally clears C1.
    // Runs containing F2XM1Call exclude v16 from the pool; FScaleCall
    // excludes v16 AND v17 (see compile_run).
    F2XM1Call,
    FScaleCall,

    // OPT-TI pow-trio completion: FYl2xCall = inputs[1] * log2(inputs[0])
    // via `BL _stub_fyl2x_val` (d16 = ST(0) = x in/out, d17 = ST(1) = y in,
    // consumed); FYl2xp1Call is the same with log2(1 + x) and the classic
    // helper's tiny-|x| series.  Whole math in the val stub's assembly (no
    // C fallback leg).  Both ops write ST(1) and POP — build() sets
    // slot_val[1] and pops; the nodes themselves are pure values.  Lowering
    // additionally clears C1 (fyl2x_common parity).  Runs containing them
    // exclude v16 AND v17 from the pool (FScaleCall's rule).
    FYl2xCall,
    FYl2xp1Call,

    // FPatanCall = atan2(inputs[1], inputs[0]) via `BL _stub_fpatan_val`
    // (d16 = ST(0) = x in/out, d17 = ST(1) = y in, consumed).  Same popping
    // 2-input shape and rules as FYl2xCall (slot_val[1] + pop in build(),
    // C1 cleared inline, v16+v17 pool-excluded).
    FPatanCall,

    // Conditional select (FCMOV): inputs[0]=ST(0) false arm, inputs[1]=ST(i) true arm
    // imm_bits[3:0] = AArch64 condition code
    FCSel,

    // Memory stores (side effects — emitted in program order)
    StoreF64,       // store as f64 to memory
    StoreF32Raw,    // store raw f32 bits (input must be a raw-f32 node)
    StoreI16,       // convert f64 to signed i16, store
    StoreI32,       // convert f64 to signed i32, store
    StoreI64,       // convert f64 to signed i64, store

    // Compare (side effects — write CC to status_word)
    FCmp,           // compare two values, set C0/C2/C3
    FTst,           // compare value with zero, set C0/C2/C3

    // FCOMI family (side effects — write result directly to NZCV, not status_word)
    FComI,          // FCOMI/FUCOMI/FCOMIP/FUCOMIP: compare ST(0) vs ST(i), set NZCV
                    // inputs[0]=ST(0) node, inputs[1]=ST(i) node
                    // flags & kFcomIPopping: pop ST(0) after compare (FCOMIP/FUCOMIP)

    // Status word read
    FStsw,          // store status_word to AX (consumes CC from prior FCmp/FTst)

    // Control word
    StoreCW,        // FLDCW: load u16 from memory, write to X87State.control_word
    LoadCW,         // FNSTCW: read X87State.control_word, store u16 to memory

    // Run-transparent guest integer instructions (opt-in
    // ROSETTA_X87_TRANSPARENT_INT): mov/movzx/movsx/movsxd/lea consumed
    // mid-run so SSA values stay in FPRs across them. Side-effect nodes,
    // emitted in program order with flag-free encodings; the whole payload is
    // packed into imm_bits (see GuestPayload) — inputs[] stay -1 so the
    // optimizer's use-count / input-rewrite loops never touch guest fields.
    GuestMovRR,     // mov r32/r64, r
    GuestMovRI,     // mov r32, imm32 (64-bit imm dst declined at build); also
                    // xor r,r zero idiom under TRANSPARENT_FLAGS (imm 0)
    GuestLea,       // lea r32/r64, [base + index<<shift + disp32]
    GuestExt,       // movzx/movsx/movsxd r32/r64, r8/r16/r32 (register source)

    // Guest GPR memory traffic (Phase 3): mov r32←m (incl. movzx/movsx from
    // memory), mov m←r, mov m←i consumed mid-run. mem_operand holds the
    // memory operand (access width = its size field); reg / sign / imm live
    // in Node::aux (see the aux packing comments below).
    GuestLoad,      // load [mem] into guest GPR (zero- or sign-extended)
    GuestStoreR,    // store guest GPR (low `size` bits) to [mem]
    GuestStoreI,    // store immediate to [mem]

    // Flag-writing ALU forms (opt-in ROSETTA_X87_TRANSPARENT_FLAGS), consumed
    // only when Rosetta's flag-liveness analysis proves the EFLAGS this
    // instruction defines dead (per-form mask against IRInstr::flag_liveness;
    // inc/dec preserve CF so CF may stay live). Lowerings are flag-free A64.
    GuestAluRI,     // add/sub/and/or/xor r32/r64, imm; shl/shr/sar r32/r64, imm;
                    // inc/dec r (imm=1); neg r; not r (flag-neutral, INT tier)
                    // (payload in imm_bits, GuestAlu selector in aux)
    GuestRmwR,      // {add,sub,and,or,xor} [m32/m64], r — load/ALU/store
                    // (mem_operand + aux: bits[3:0] src reg, bits[6:4] GuestAlu)

    // Stack pushes/pops (opt-in ROSETTA_X87_TRANSPARENT_PUSHPOP). Flag-neutral
    // — no liveness gate. Lowered exactly like Rosetta's own translation:
    // STR pre-index / LDR post-index with writeback on the guest RSP (x4),
    // 64-bit address arithmetic (Rosetta parity; 32-bit esp wrap divergence
    // is the same accepted class as the base-address cache). RSP itself as
    // the pushed/popped register declines (old-value / discarded-increment
    // semantics plus the Rt==Rn writeback hazard).
    GuestPushR,     // push r32/r64: [rsp -= slot] = r  (payload in imm_bits)
    GuestPushI,     // push imm: [rsp -= slot] = imm (sign-extended for 64-bit)
    GuestPop,       // pop r32/r64: r = [rsp], rsp += slot

    // Guest flag DEFINER (opt-in via TRANSPARENT_FLAGS): cmp/test r32/r64
    // with register or immediate rhs, lowered to SUBS/ANDS — the same NZCV
    // guest state Rosetta's own translation of these opcodes leaves behind.
    // The one deliberate exception to the "Guest nodes are flag-free" rule:
    // this node REDEFINES the guest EFLAGS at its program position (that is
    // its whole architectural effect), which is exactly what lets an FCSel
    // consume a plain `cmp reg, imm` without ending the run. Build gates on
    // flag_liveness proving the unmaterialized flags dead (PF, and AF for
    // cmp — NZCV carries only SF/ZF/CF/OF). Payload in imm_bits
    // (GuestPayload: dst = lhs reg, src = rhs reg, imm, is64); aux bit0 =
    // test (ANDS) vs cmp (SUBS), bit1 = register rhs.
    GuestCmpF,
};

// ALU sub-op selector for GuestAluRI (whole aux) and GuestRmwR (aux[6:4]).
// GuestRmwR's 3-bit field only ever carries Add..Xor; the unary selectors
// (Neg = SUB from XZR, Not = ORN from XZR) are GuestAluRI-only.
enum class GuestAlu : uint8_t { Add = 0, Sub, And, Or, Xor, Shl, Shr, Sar,
                                Neg, Not };

enum NodeFlags : uint8_t {
    kNone         = 0,
    kDead         = 1 << 0,    // eliminated by optimization pass
    kFcomFused    = 1 << 1,    // FCOM+FSTSW fused: CC stays in register
    kTruncate     = 1 << 2,    // StoreI*: always truncate (FISTTP), skip RC dispatch
    kFcomIPopping = 1 << 3,    // FComI: pop ST(0) after compare (FCOMIP/FUCOMIP)
    kFCSelRaw     = 1 << 4,    // FCSel: condition remapped to read the raw
                               // FCMP NZCV of its FComI (see plan_fcomi_raw)
    kF32          = 1 << 5,    // arithmetic node computes in f32 (S-form): takes
                               // raw-f32 inputs, produces a raw-f32 value
    kPackSink     = 1 << 6,    // FCSel: its FComI's guest-EFLAGS pack is
                               // emitted after this node (raw flags stay live
                               // through it; CSET/FCSEL don't write NZCV)
};

// ── Guest* node payload ─────────────────────────────────────────────────────
//
// Packed into Node::imm_bits:
//   [31:0]  imm32 (GuestMovRI) / disp32 (GuestLea; sign-extended for 64-bit
//           address computation)
//   [35:32] dst guest reg index (guest GPR index == host GPR number,
//           binary-verified: Rosetta lowers `mov ecx, 1` to `MOVZ W1, #1`)
//   [39:36] src guest reg index (GuestMovRR/GuestExt) / lea base reg
//   [43:40] lea index reg
//   [45:44] lea shift amount / GuestExt source class (0=8lo, 1=8hi, 2=16, 3=32)
//   [46]    dst is 64-bit
//   [47]    GuestExt sign-extend (movsx/movsxd)
//   [48]    lea has_base
//   [49]    lea has_index
//   [50]    lea 32-bit address size (compute in W regs)

struct GuestPayload {
    uint32_t imm;
    uint8_t  dst, src, idx, cls;
    bool     is64, sign, has_base, has_index, addr32;
};

inline uint64_t guest_pack(const GuestPayload& p) {
    return static_cast<uint64_t>(p.imm) |
           (static_cast<uint64_t>(p.dst & 0xF) << 32) |
           (static_cast<uint64_t>(p.src & 0xF) << 36) |
           (static_cast<uint64_t>(p.idx & 0xF) << 40) |
           (static_cast<uint64_t>(p.cls & 0x3) << 44) |
           (static_cast<uint64_t>(p.is64) << 46) |
           (static_cast<uint64_t>(p.sign) << 47) |
           (static_cast<uint64_t>(p.has_base) << 48) |
           (static_cast<uint64_t>(p.has_index) << 49) |
           (static_cast<uint64_t>(p.addr32) << 50);
}

inline GuestPayload guest_unpack(uint64_t b) {
    GuestPayload p;
    p.imm       = static_cast<uint32_t>(b);
    p.dst       = (b >> 32) & 0xF;
    p.src       = (b >> 36) & 0xF;
    p.idx       = (b >> 40) & 0xF;
    p.cls       = (b >> 44) & 0x3;
    p.is64      = (b >> 46) & 1;
    p.sign      = (b >> 47) & 1;
    p.has_base  = (b >> 48) & 1;
    p.has_index = (b >> 49) & 1;
    p.addr32    = (b >> 50) & 1;
    return p;
}

// ── IR node ─────────────────────────────────────────────────────────────────

struct Node {
    Op       op;
    uint8_t  flags;
    int16_t  inputs[3];         // SSA references (node indices); -1 = unused
    union {
        uint64_t   imm_bits;        // ConstF64 / Guest* packed payload
        IROperand* mem_operand;     // Load*/Store*: pointer into original IRInstr
        int16_t    initial_depth;   // ReadSt: depth relative to initial TOP
    };
    // Secondary payload for nodes that need both a mem_operand and small
    // metadata (metadata must NOT live in inputs[]: the optimizer's
    // use-count and input-rewrite loops treat every non-negative input as a
    // node reference).
    //   GuestLoad:   bits[3:0] dst guest reg, bit[4] sign-extend
    //   GuestStoreR: bits[3:0] src guest reg
    //   GuestStoreI: bits[31:0] immediate (truncated to the access width)
    //   GuestAluRI:  GuestAlu selector (payload itself is in imm_bits)
    //   GuestRmwR:   bits[3:0] src guest reg, bits[6:4] GuestAlu selector
    //   FStsw:       bits[3:0] dst guest reg (0 = AX), bits[31:16] top_delta
    //                snapshot at the fnstsw (int16, for TOP patching)
    uint64_t aux;
};
static_assert(sizeof(Node) == 24, "X87IR::Node should be 24 bytes");

// ── IR context (all state for one run, lives on the stack) ──────────────────

struct Context {
    Node    nodes[kMaxNodes];       // 1024 bytes
    int16_t num_nodes;

    // Symbolic stack.
    //   val >= 0: IR node ID
    //   val < 0:  initial slot; initial_depth = -(val + 1)
    int16_t slot_val[8];
    int16_t top_delta;              // accumulated push(-) / pop(+)

    // Dedup cache for initial-slot reads (avoids duplicate ReadSt nodes).
    int16_t initial_read[8];        // node ID for initial depth d, or -1

    // Memory CSE table: recent load results (and forwardable f64 stores)
    // keyed by operand identity. Within a run, guest GPRs cannot change
    // (only x87 instructions — the sole exception, FSTSW AX, evicts
    // RAX-addressed entries), so identical operands always address the
    // same location.
    // Cleared conservatively on any memory write (Store*, FNSTCW).
    static constexpr int kMemCSESlots = 8;
    IROperand* mem_cse_op[kMemCSESlots];   // operand identity (compared by value)
    Op         mem_cse_kind[kMemCSESlots]; // the Load* op an entry satisfies
    int16_t    mem_cse_val[kMemCSESlots];  // node ID holding the f64 value
    int8_t     mem_cse_count;
    int8_t     mem_cse_next;               // rotating overwrite cursor when full

    // Narrow dedup: most recent CvtF64ToF32 node and its input, so repeated
    // f32 stores of one value (fst/fstp chains) share a single FCVT.
    // Pure value — never invalidated within a run.
    int16_t  last_narrow_input;
    int16_t  last_narrow_node;

    // Const dedup: reuse prior ConstZero/ConstOne/ConstF64 nodes.
    // Consts are pure values — never invalidated within a run.
    int16_t  const_zero_node;
    int16_t  const_one_node;
    static constexpr int kConstF64Slots = 4;
    int16_t  const_f64_node[kConstF64Slots];  // recent ConstF64 nodes
    uint64_t const_f64_bits[kConstF64Slots];  // their bit patterns
    int8_t   const_f64_count;
    int8_t   const_f64_next;        // rotating overwrite cursor when full

    // CC tracking for FCOM+FSTSW fusion.
    int16_t last_fcmp;              // most recent FCmp/FTst node ID, or -1

    // NZCV tracking for FCMOV safety gate.
    int16_t last_fcomi;             // most recent FComI node ID, or -1
    int16_t last_guest_flagdef;     // most recent GuestCmpF node ID, or -1
                                    // (an alternative NZCV producer for FCSel:
                                    // whichever of the two is LATER owns the
                                    // flags an FCSel reads)

    // How many x87 instructions were successfully consumed.
    int16_t consumed;

    // Base-address cache plan (filled by compile_run after the pressure gate,
    // consumed by lower()): node IDs whose mem_operand is the representative
    // operand of a cached guest base; addr_cache_n = how many are enabled.
    static constexpr int kAddrCacheSlots = 3;
    int16_t addr_cache_rep[kAddrCacheSlots];
    int8_t  addr_cache_n;

    // Guest EFLAGS are provably dead after this run (the next flag-relevant
    // guest instruction fully redefines them) — FCmp/FTst may skip the NZCV
    // save/restore. Set by compile_run from the post-run instruction stream.
    int8_t  nzcv_dead;

    // Allow promoting loads from read-only absolute addresses to constants
    // (set by build() from its parameter; JIT mode only).
    int8_t  const_promote;

    // Guest GPRs written by inlined Guest* nodes (bit per guest reg index).
    // Operands addressed through these registers are excluded from the
    // base-address cache for the whole run (the base is materialized in the
    // preamble, before any inlined write could happen).
    uint16_t guest_written_mask;

    void init() {
        num_nodes = 0;
        top_delta = 0;
        consumed = 0;
        last_fcmp = -1;
        last_fcomi = -1;
        last_guest_flagdef = -1;
        for (int i = 0; i < kAddrCacheSlots; i++) addr_cache_rep[i] = -1;
        addr_cache_n = 0;
        nzcv_dead = 0;
        const_promote = 0;
        guest_written_mask = 0;
        last_narrow_input = -1;
        last_narrow_node = -1;
        const_zero_node = -1;
        const_one_node = -1;
        const_f64_count = 0;
        const_f64_next = 0;
        for (int i = 0; i < 8; i++) {
            slot_val[i] = static_cast<int16_t>(-(i + 1));
            initial_read[i] = -1;
        }
        mem_cse_clear();
    }

    void mem_cse_clear() {
        mem_cse_count = 0;
        mem_cse_next = 0;
    }

    // Append a new node and return its index.
    int16_t add_node(Op op, int16_t in0 = -1, int16_t in1 = -1, int16_t in2 = -1) {
        if (num_nodes >= kMaxNodes) return -1;
        int16_t id = num_nodes++;
        auto& n = nodes[id];
        n.op = op;
        n.flags = kNone;
        n.inputs[0] = in0;
        n.inputs[1] = in1;
        n.inputs[2] = in2;
        n.imm_bits = 0;
        n.aux = 0;
        return id;
    }

    // Resolve the current value at logical stack depth `d`.
    // If the slot still holds an initial value, emits a ReadSt node.
    // Returns node ID, or -1 on failure.
    int16_t resolve(int d) {
        if (d < 0 || d >= 8) return -1;
        int16_t val = slot_val[d];
        if (val >= 0) return val;

        int init_d = -(val + 1);
        if (init_d < 0 || init_d >= 8) return -1;

        // Dedup: reuse prior ReadSt for same initial depth
        if (initial_read[init_d] >= 0) {
            slot_val[d] = initial_read[init_d];
            return initial_read[init_d];
        }

        int16_t id = add_node(Op::ReadSt);
        if (id < 0) return -1;
        nodes[id].initial_depth = static_cast<int16_t>(init_d);
        initial_read[init_d] = id;
        slot_val[d] = id;
        return id;
    }

    void push(int16_t node_id) {
        for (int i = 7; i > 0; i--) slot_val[i] = slot_val[i - 1];
        slot_val[0] = node_id;
        top_delta--;
    }

    void pop() {
        for (int i = 0; i < 7; i++) slot_val[i] = slot_val[i + 1];
        slot_val[7] = -100;  // sentinel: "popped past end"
        top_delta++;
    }
};

// ── Public API ──────────────────────────────────────────────────────────────

// Build IR from a sequence of x87 instructions.
// Returns the number of instructions consumed (stored in ctx.consumed).
// `perm` (optional): deferred-FXCH permutation carried in from the cache —
// logical depth d initially lives at physical depth perm[d]. Non-identity
// entries are force-resolved so lowering materializes the swap (identity
// afterward); the reads are DSE-able if the run overwrites those slots.
bool build(Context& ctx, IRInstr* instr_array, int64_t num_instrs, int64_t start_idx,
           int run_length, const int8_t* perm = nullptr, bool const_promote = false);

// Run optimization passes on the IR (DSE, FMA detection, FCOM+FSTSW fusion).
void optimize(Context& ctx);

// Compute the peak number of simultaneously live FPR-bearing nodes that the
// lowering pass will require, including LDP/STP pair-induced liveness shifts.
// Used to gate lowering against the available scratch FPR pool.
int peak_live_fprs(const Context& ctx);

// Lower IR to AArch64 instructions, writing into result->insn_buf.
void lower(Context& ctx, TranslationResult* result);

// Why compile_run declined a run (or that it succeeded). Reported via the
// optional `err` out-param; the int return still carries the consumed count.
enum class CompileError {
    kSuccess,       // run lowered; return value is the consumed count (>0)
    kBuildFailed,   // build() could not construct IR from the run
    kFprPressure,   // peak live FPRs exceeded the free FPR pool
    kGprPressure,   // peak live GPRs exceeded the free GPR pool
};

// Main entry point: build + optimize + lower.
// Returns the number of x87 instructions consumed (0 = IR couldn't handle any).
// `err` (optional out): why the run was declined, or kSuccess. See CompileError.
int compile_run(TranslationResult* result, IRInstr* instr_array, int64_t num_instrs,
                int64_t start_idx, int run_length, CompileError* err = nullptr);

}  // namespace X87IR
