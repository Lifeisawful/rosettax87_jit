#include "rosetta_core/X87IR.h"

#include <cstring>

#include "rosetta_config/Config.h"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/HookSafeFP.h"

namespace X87IR {

// ── Pass 0: Dead-compare elimination ────────────────────────────────────────
//
// FCmp/FTst's only architectural effect is writing C0/C2/C3 into status_word
// (exceptions are unmodeled). FStsw is the only IR node that reads
// status_word, and run end is the final observer. So a compare whose CC bits
// are overwritten by a later FCmp/FTst, with no FStsw in between, has no
// observable effect and can be killed outright — its FCMP, the NZCV
// save/restore, the CC pack, and the status_word RMW all disappear, and its
// value inputs may cascade dead in pass_dse.
//
// Backward scan: `overwritten` is true when a live FCmp/FTst lies below with
// no FStsw between it and the current node.

static void pass_dead_compares(Context& ctx) {
    bool overwritten = false;
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op == Op::FStsw) {
            overwritten = false;
        } else if (n.op == Op::FCmp || n.op == Op::FTst) {
            if (overwritten)
                n.flags |= kDead;
            else
                overwritten = true;
        }
    }
}

// ── Pass 0.5: Constant arithmetic ───────────────────────────────────────────
//
// With constant-load promotion, FP literals surface as Const* nodes:
//   FDiv(x, ConstF64 = ±2^k) → FMul(x, ±2^-k)  — exact (reciprocal of a
//     normal power of two is a normal power of two); FDIV is ~3-4× the
//     latency of FMUL. Requires a single-use divisor (bits are rewritten
//     in place).
//   FCmp(x, ±0.0 const) → FTst(x)  — FCMP #0.0 compares -0 == +0, matching
//     FCOM semantics; drops the constant materialization.
//   Identity folds (IEEE-exact for every input incl. ±0/NaN):
//     FMul(x, 1.0), FMul(1.0, x), FDiv(x, 1.0) → x
//     FSub(x, +0.0) → x     FAdd(x, -0.0) → x
//     (x + (+0.0) and x - (-0.0) are NOT identities: they flip -0 to +0.)
// Runs before pass_dse so orphaned constants are reaped.

// True if node c is a live constant with the given f64 bit pattern.
// alias_op (< 0 = none): the dedicated Const node kind for this value
// (ConstOne for 1.0, ConstZero for +0.0).
static bool const_is(const Context& ctx, int16_t c, int alias_op,
                     uint64_t f64_bits) {
    if (c < 0 || c >= ctx.num_nodes) return false;
    const auto& cn = ctx.nodes[c];
    if (cn.flags & kDead) return false;
    if (alias_op >= 0 && cn.op == static_cast<Op>(alias_op)) return true;
    return cn.op == Op::ConstF64 && cn.imm_bits == f64_bits;
}

static void pass_const_arith(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    // Replace every use of node i (a folded identity) with node keep and
    // kill i plus its constant operand if orphaned.
    auto fold_to = [&](int16_t i, int16_t keep, int16_t c) {
        for (int k = 0; k < ctx.num_nodes; k++) {
            auto& u = ctx.nodes[k];
            if (u.flags & kDead) continue;
            for (int j = 0; j < 3; j++) {
                if (u.inputs[j] == i) u.inputs[j] = keep;
            }
        }
        for (int d = 0; d < 8; d++) {
            if (ctx.slot_val[d] == i) ctx.slot_val[d] = keep;
        }
        use_count[keep] = static_cast<int16_t>(use_count[keep] + use_count[i] - 1);
        use_count[i] = 0;
        ctx.nodes[i].flags |= kDead;
        if (--use_count[c] == 0) ctx.nodes[c].flags |= kDead;
    };

    constexpr uint64_t kOneBits = 0x3FF0000000000000ULL;
    constexpr uint64_t kMZeroBits = 0x8000000000000000ULL;

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        // Identity folds.
        {
            int16_t keep = -1, cidx = -1;
            if ((n.op == Op::FMul || n.op == Op::FDiv) &&
                const_is(ctx, n.inputs[1], static_cast<int>(Op::ConstOne), kOneBits)) {
                keep = n.inputs[0]; cidx = n.inputs[1];
            } else if (n.op == Op::FMul &&
                       const_is(ctx, n.inputs[0], static_cast<int>(Op::ConstOne), kOneBits)) {
                keep = n.inputs[1]; cidx = n.inputs[0];
            } else if (n.op == Op::FSub &&
                       const_is(ctx, n.inputs[1], static_cast<int>(Op::ConstZero), 0)) {
                keep = n.inputs[0]; cidx = n.inputs[1];
            } else if (n.op == Op::FAdd &&
                       const_is(ctx, n.inputs[1], /*alias_op=*/-1, kMZeroBits)) {
                keep = n.inputs[0]; cidx = n.inputs[1];
            }
            if (keep >= 0) {
                fold_to(static_cast<int16_t>(i), keep, cidx);
                continue;
            }
        }

        if (n.op == Op::FDiv) {
            int16_t c = n.inputs[1];
            if (c < 0 || c >= ctx.num_nodes) continue;
            auto& cn = ctx.nodes[c];
            if (cn.op != Op::ConstF64 || (cn.flags & kDead) || use_count[c] != 1)
                continue;
            const uint64_t b = cn.imm_bits;
            const uint64_t exp = (b >> 52) & 0x7FF;
            // ±2^k with both value and reciprocal normal — exact.
            if ((b & 0x000FFFFFFFFFFFFFULL) == 0 && exp >= 1 && exp <= 2045) {
                cn.imm_bits = (b & 0x8000000000000000ULL) | ((2046 - exp) << 52);
                n.op = Op::FMul;
            } else if (g_rosetta_config && g_rosetta_config->fast_recip_div &&
                       exp >= 1 && exp <= 2046) {
                // Opt-in: any normal divisor whose reciprocal is also normal.
                // x * (1/d) differs from x / d by at most 1 ulp — the classic
                // fast-division fidelity trade. hook_safe: a plain 1.0/d here
                // compiled to fdiv d0,d1,d0 — clobbering live guest XMM0/1 in
                // the translation hook (same bug class as the const-promote
                // FCVT corruption).
                const uint64_t rb = hook_safe_recip_bits(b);
                const uint64_t rexp = (rb >> 52) & 0x7FF;
                if (rexp >= 1 && rexp <= 2046) {
                    cn.imm_bits = rb;
                    n.op = Op::FMul;
                }
            }
        } else if (n.op == Op::FCmp) {
            int16_t c = n.inputs[1];
            if (c < 0 || c >= ctx.num_nodes) continue;
            auto& cn = ctx.nodes[c];
            if (cn.flags & kDead) continue;
            const bool is_zero = cn.op == Op::ConstZero ||
                                 (cn.op == Op::ConstF64 && (cn.imm_bits << 1) == 0);
            if (!is_zero) continue;
            n.op = Op::FTst;
            n.inputs[1] = -1;
            if (--use_count[c] == 0)
                cn.flags |= kDead;
        }
    }
}

// ── Pass 1: Dead Store Elimination ──────────────────────────────────────────
//
// Walk backward. A value node is dead if it has no live consumers (no other
// node references it in inputs[], and it's not in the final slot_val[]).
// Side-effect nodes (Store*, FCmp, FTst, FStsw) are never eliminated.

static void pass_dse(Context& ctx) {
    // Count uses for each node.
    int16_t use_count[kMaxNodes] = {};

    // Final stack values count as uses.
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }

    // Forward pass to count uses from non-dead nodes.
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0)
                use_count[n.inputs[j]]++;
        }
    }

    // Backward pass: mark dead nodes (pure-value nodes with zero uses).
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        // Side-effect nodes are never dead.
        switch (n.op) {
            case Op::StoreF64: case Op::StoreF32Raw:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::FCmp: case Op::FTst: case Op::FStsw: case Op::FComI:
            case Op::StoreCW: case Op::LoadCW:
            case Op::GuestMovRR: case Op::GuestMovRI:
            case Op::GuestLea: case Op::GuestExt:
            case Op::GuestLoad: case Op::GuestStoreR: case Op::GuestStoreI:
                continue;
            default: break;
        }

        if (use_count[i] == 0) {
            n.flags |= kDead;
            // Decrement use counts for this node's inputs.
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0)
                    use_count[n.inputs[j]]--;
            }
        }
    }

    // Second backward pass to catch cascading dead nodes.
    for (int i = ctx.num_nodes - 1; i >= 0; i--) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        switch (n.op) {
            case Op::StoreF64: case Op::StoreF32Raw:
            case Op::StoreI16: case Op::StoreI32: case Op::StoreI64:
            case Op::FCmp: case Op::FTst: case Op::FStsw: case Op::FComI:
            case Op::StoreCW: case Op::LoadCW:
            case Op::GuestMovRR: case Op::GuestMovRI:
            case Op::GuestLea: case Op::GuestExt:
            case Op::GuestLoad: case Op::GuestStoreR: case Op::GuestStoreI:
                continue;
            default: break;
        }
        if (use_count[i] == 0) {
            n.flags |= kDead;
            for (int j = 0; j < 3; j++) {
                if (n.inputs[j] >= 0)
                    use_count[n.inputs[j]]--;
            }
        }
    }
}

// ── Pass 1.5: FNeg folding ──────────────────────────────────────────────────
//
// fchs is common in game FP code. Fold single-use FNeg nodes into their
// consumer (all rewrites are IEEE-exact — FSub(x,y) computes x + (-y)):
//   FAdd(x, FNeg(y)) → FSub(x, y)
//   FAdd(FNeg(x), y) → FSub(y, x)
//   FSub(x, FNeg(y)) → FAdd(x, y)
//   FNeg(FMul(a, b)) with single-use mul → FNMul(a, b)   (one FNMUL insn)
// Runs before pass_fma so the rewritten FAdd/FSub feed FMA detection.
// Note: FNMul diverges from FMUL+FNEG only in the sign bit of a NaN result
// (AArch64 propagates the input NaN unnegated) — same fidelity class as the
// FMA fusion's rounding difference, accepted.

static void pass_fneg_fold(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    auto single_use_op = [&](int16_t id, Op op) {
        return id >= 0 && id < ctx.num_nodes && ctx.nodes[id].op == op &&
               !(ctx.nodes[id].flags & kDead) && use_count[id] == 1;
    };

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;

        if (n.op == Op::FAdd || n.op == Op::FSub) {
            int16_t in0 = n.inputs[0], in1 = n.inputs[1];
            if (single_use_op(in1, Op::FNeg)) {
                auto& neg = ctx.nodes[in1];
                n.op = (n.op == Op::FAdd) ? Op::FSub : Op::FAdd;
                n.inputs[1] = neg.inputs[0];
                neg.flags |= kDead;
                use_count[in1] = 0;
                if (neg.inputs[0] >= 0) use_count[neg.inputs[0]]++;
            } else if (n.op == Op::FAdd && single_use_op(in0, Op::FNeg)) {
                auto& neg = ctx.nodes[in0];
                n.op = Op::FSub;
                n.inputs[0] = in1;
                n.inputs[1] = neg.inputs[0];
                neg.flags |= kDead;
                use_count[in0] = 0;
                if (neg.inputs[0] >= 0) use_count[neg.inputs[0]]++;
            }
        } else if (n.op == Op::FNeg) {
            int16_t m = n.inputs[0];
            if (single_use_op(m, Op::FMul)) {
                auto& mul = ctx.nodes[m];
                n.op = Op::FNMul;
                n.inputs[0] = mul.inputs[0];
                n.inputs[1] = mul.inputs[1];
                mul.flags |= kDead;
                use_count[m] = 0;
                if (mul.inputs[0] >= 0) use_count[mul.inputs[0]]++;
                if (mul.inputs[1] >= 0) use_count[mul.inputs[1]]++;
            }
        }
    }
}

// ── Pass 2: FMA Detection ───────────────────────────────────────────────────
//
// Pattern: FMul(a, b) with exactly one use → FAdd(mul, c) or FAdd(c, mul)
//          → replace with FMAdd(a, b, c).
//
// Similarly:
//   FAdd(c, mul) where mul = FMul(a, b)  → FMAdd(a, b, c)  [c + a*b]
//   FSub(c, mul)                          → FMSub(a, b, c)  [c - a*b]
//   FSub(mul, c)                          → FNMSub(a, b, c) [a*b - c]

static void pass_fma(Context& ctx) {
    // Count uses first to find single-use FMul nodes.
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op != Op::FAdd && n.op != Op::FSub) continue;

        int16_t in0 = n.inputs[0];
        int16_t in1 = n.inputs[1];

        // Check if one input is a single-use FMul.
        auto try_fuse = [&](int mul_input_idx, int other_input_idx) -> bool {
            int16_t mul_id = (mul_input_idx == 0) ? in0 : in1;
            int16_t other_id = (other_input_idx == 0) ? in0 : in1;
            if (mul_id < 0 || mul_id >= ctx.num_nodes) return false;
            auto& mul_node = ctx.nodes[mul_id];
            if (mul_node.op != Op::FMul) return false;
            if (mul_node.flags & kDead) return false;
            if (use_count[mul_id] != 1) return false;

            // Determine FMA variant.
            Op fma_op;
            if (n.op == Op::FAdd) {
                fma_op = Op::FMAdd;  // c + a*b (or a*b + c, same thing)
            } else {
                // FSub
                if (mul_input_idx == 0) {
                    // FSub(mul, c) → a*b - c = FNMSub
                    fma_op = Op::FNMSub;
                } else {
                    // FSub(c, mul) → c - a*b = FMSub
                    fma_op = Op::FMSub;
                }
            }

            // Rewrite: n becomes FMA, mul becomes dead.
            n.op = fma_op;
            n.inputs[0] = mul_node.inputs[0];  // a
            n.inputs[1] = mul_node.inputs[1];  // b
            n.inputs[2] = other_id;            // c (addend)
            mul_node.flags |= kDead;
            use_count[mul_id] = 0;
            // Update use counts for the rewritten inputs.
            if (mul_node.inputs[0] >= 0) use_count[mul_node.inputs[0]]++;
            if (mul_node.inputs[1] >= 0) use_count[mul_node.inputs[1]]++;
            // other_id already had its use from the original node; no change needed.
            return true;
        };

        if (!try_fuse(0, 1))
            try_fuse(1, 0);
    }
}

// ── Pass 2.5: f32 single-op narrowing ───────────────────────────────────────
//
// narrow(op_f64(widen(a), widen(b))) is bit-identical to op_f32(a, b) for
// FAdd/FSub/FMul/FDiv/FSqrt (Figueroa: double rounding through f64 is
// innocuous for one operation on f32 inputs since 53 ≥ 2·24 + 2) and
// trivially for FNeg/FAbs/FNMul (sign flips are exact). So when an f64 op
// whose inputs are all widened raw-f32 values dies into a CvtF64ToF32, the
// whole widen/compute/narrow sandwich can run in S registers — same result,
// 2–3 fewer FCVTs. The CvtF64ToF32 node is rewritten in place into the
// f32-typed op (kF32) reading the raw sources, so consumers keep seeing a
// raw-f32 value at the same node ID; the f64 op dies here and orphaned
// widens are reaped by the final pass_dse.
//
// Runs after pass_fma: f64 FMAs get first pick (narrowing a fused FMA is
// NOT exact — the a*b+c sum double-rounds — so FMA stays f64).

static bool f32_narrowable_op(Op op, int* num_inputs) {
    switch (op) {
        case Op::FAdd: case Op::FSub: case Op::FMul: case Op::FDiv:
        case Op::FNMul:
            *num_inputs = 2; return true;
        case Op::FNeg: case Op::FAbs: case Op::FSqrt:
            *num_inputs = 1; return true;
        default:
            return false;
    }
}

static void pass_f32_narrow(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& c = ctx.nodes[i];
        if (c.flags & kDead) continue;
        if (c.op != Op::CvtF64ToF32) continue;
        const int16_t x = c.inputs[0];
        if (x < 0 || x >= ctx.num_nodes) continue;
        auto& xn = ctx.nodes[x];
        if ((xn.flags & kDead) || (xn.flags & kF32)) continue;
        int nin;
        if (!f32_narrowable_op(xn.op, &nin)) continue;
        if (use_count[x] != 1) continue;  // f64 value must die into this narrow

        // Every input must be a widened raw-f32 value.
        int16_t raw[2] = {-1, -1};
        bool ok = true;
        for (int j = 0; j < nin; j++) {
            const int16_t in = xn.inputs[j];
            if (in < 0 || in >= ctx.num_nodes ||
                ctx.nodes[in].op != Op::CvtF32ToF64 ||
                (ctx.nodes[in].flags & kDead)) {
                ok = false;
                break;
            }
            raw[j] = ctx.nodes[in].inputs[0];
        }
        if (!ok) continue;

        c.op = xn.op;
        c.flags |= kF32;
        c.inputs[0] = raw[0];
        c.inputs[1] = raw[1];
        xn.flags |= kDead;
        use_count[x] = 0;
        for (int j = 0; j < nin; j++) {
            // Orphaned widens die now so later candidates see live counts;
            // the final pass_dse handles any cascade below them.
            if (--use_count[xn.inputs[j]] == 0)
                ctx.nodes[xn.inputs[j]].flags |= kDead;
            use_count[raw[j]]++;
        }
    }
}

// ── Pass 2.6 (opt-in): f32 chain arithmetic ─────────────────────────────────
//
// ROSETTA_X87_F32_ARITH=1: keep INTERMEDIATE values of f32-sourced arithmetic
// chains in f32 (fld m32; fadd m32; fmul m32; fstp m32 runs entirely in S
// registers). Unlike pass_f32_narrow this is NOT bit-exact — x87 code
// computed the intermediates in f64 — hence the opt-in flag.
//
// Fixpoint: a candidate f64 arithmetic node is f32-eligible while
//   - every input is a widen of a raw-f32 value, a raw-f32 producer
//     (kF32 arithmetic), ConstZero (an S read of a zeroed D is 0.0f), or
//     another eligible node, and
//   - every use is a CvtF64ToF32 or another eligible node — in particular it
//     is not a final stack value (slots stay f64) and feeds no compare/FMA.
// Eligible nodes are flipped to kF32 with widen inputs unwrapped; narrows of
// flipped producers become copies and are bypassed. Orphans die in pass_dse.

static void pass_f32_chain(Context& ctx) {
    bool elig[kMaxNodes] = {};
    int8_t nin_of[kMaxNodes];
    bool any = false;
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & (kDead | kF32)) continue;
        int nin;
        if (f32_narrowable_op(n.op, &nin)) {
            elig[i] = true;
            nin_of[i] = static_cast<int8_t>(nin);
            any = true;
        }
    }
    if (!any) return;

    // Final stack values must stay f64.
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            elig[ctx.slot_val[d]] = false;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (int i = 0; i < ctx.num_nodes; i++) {
            const auto& n = ctx.nodes[i];
            if (n.flags & kDead) continue;
            // Input legality for eligible nodes.
            if (elig[i]) {
                for (int j = 0; j < nin_of[i]; j++) {
                    const int16_t in = n.inputs[j];
                    const bool ok =
                        in >= 0 && in < ctx.num_nodes &&
                        !(ctx.nodes[in].flags & kDead) &&
                        (ctx.nodes[in].op == Op::CvtF32ToF64 ||
                         (ctx.nodes[in].flags & kF32) ||
                         ctx.nodes[in].op == Op::ConstZero || elig[in]);
                    if (!ok) {
                        elig[i] = false;
                        changed = true;
                        break;
                    }
                }
            }
            // Use legality: only a narrow or an eligible node may consume an
            // eligible value.
            const bool consumer_ok = (n.op == Op::CvtF64ToF32) || elig[i];
            if (consumer_ok) continue;
            for (int j = 0; j < 3; j++) {
                const int16_t in = n.inputs[j];
                if (in >= 0 && in < ctx.num_nodes && elig[in]) {
                    elig[in] = false;
                    changed = true;
                }
            }
        }
    }

    // Flip eligible nodes to f32 and unwrap their widen inputs.
    any = false;
    for (int i = 0; i < ctx.num_nodes; i++) {
        if (!elig[i]) continue;
        auto& n = ctx.nodes[i];
        n.flags |= kF32;
        for (int j = 0; j < nin_of[i]; j++) {
            const int16_t in = n.inputs[j];
            if (ctx.nodes[in].op == Op::CvtF32ToF64)
                n.inputs[j] = ctx.nodes[in].inputs[0];
        }
        any = true;
    }
    if (!any) return;

    // Narrows of flipped producers are now copies — bypass and kill them.
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op != Op::CvtF64ToF32) continue;
        const int16_t src = n.inputs[0];
        if (src < 0 || src >= ctx.num_nodes || !elig[src]) continue;
        for (int k = 0; k < ctx.num_nodes; k++) {
            auto& u = ctx.nodes[k];
            if (u.flags & kDead) continue;
            for (int j = 0; j < 3; j++) {
                if (u.inputs[j] == i) u.inputs[j] = src;
            }
        }
        n.flags |= kDead;
    }
}

// ── Pass 2.7 (opt-in): f32 FMA ──────────────────────────────────────────────
//
// Same shapes as pass_fma, restricted to kF32 nodes produced by
// pass_f32_chain (the f32 FMA vs mul+add difference is within the fidelity
// class the flag already accepts).

static void pass_f32_fma(Context& ctx) {
    int16_t use_count[kMaxNodes] = {};
    for (int d = 0; d < 8; d++) {
        if (ctx.slot_val[d] >= 0 && ctx.slot_val[d] < ctx.num_nodes)
            use_count[ctx.slot_val[d]]++;
    }
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        for (int j = 0; j < 3; j++) {
            if (n.inputs[j] >= 0) use_count[n.inputs[j]]++;
        }
    }

    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (!(n.flags & kF32)) continue;
        if (n.op != Op::FAdd && n.op != Op::FSub) continue;

        auto try_fuse = [&](int mul_idx) -> bool {
            const int16_t mul_id = n.inputs[mul_idx];
            const int16_t other_id = n.inputs[1 - mul_idx];
            if (mul_id < 0 || mul_id >= ctx.num_nodes) return false;
            auto& mul = ctx.nodes[mul_id];
            if (mul.op != Op::FMul || !(mul.flags & kF32)) return false;
            if (mul.flags & kDead) return false;
            if (use_count[mul_id] != 1) return false;

            if (n.op == Op::FAdd)
                n.op = Op::FMAdd;
            else
                n.op = (mul_idx == 0) ? Op::FNMSub : Op::FMSub;
            n.inputs[0] = mul.inputs[0];
            n.inputs[1] = mul.inputs[1];
            n.inputs[2] = other_id;
            mul.flags |= kDead;
            use_count[mul_id] = 0;
            if (mul.inputs[0] >= 0) use_count[mul.inputs[0]]++;
            if (mul.inputs[1] >= 0) use_count[mul.inputs[1]]++;
            return true;
        };

        if (!try_fuse(0))
            try_fuse(1);
    }
}

// ── Pass 3: FCOM + FSTSW Fusion ─────────────────────────────────────────────
//
// If a FCmp/FTst node is immediately followed by a FStsw with no intervening
// CC-modifying node, mark both with kFcomFused. The lowering keeps packed CC
// in a GPR between the two nodes, avoiding one LDRH in FStsw.

static void pass_fcom_fstsw_fusion(Context& ctx) {
    for (int i = 0; i < ctx.num_nodes; i++) {
        auto& n = ctx.nodes[i];
        if (n.flags & kDead) continue;
        if (n.op != Op::FStsw) continue;

        int16_t fcmp_id = n.inputs[0];
        if (fcmp_id < 0 || fcmp_id >= ctx.num_nodes) continue;
        auto& fcmp_node = ctx.nodes[fcmp_id];
        if (fcmp_node.op != Op::FCmp && fcmp_node.op != Op::FTst) continue;

        // Check no intervening CC-modifying instruction between fcmp and fstsw.
        bool clean = true;
        for (int j = fcmp_id + 1; j < i; j++) {
            auto& between = ctx.nodes[j];
            if (between.flags & kDead) continue;
            if (between.op == Op::FCmp || between.op == Op::FTst) {
                clean = false;
                break;
            }
        }
        if (clean) {
            fcmp_node.flags |= kFcomFused;
            n.flags |= kFcomFused;
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

void optimize(Context& ctx) {
    pass_dead_compares(ctx);
    pass_const_arith(ctx);
    pass_dse(ctx);
    pass_fneg_fold(ctx);
    const bool f32_narrow_on =
        g_rosetta_config && g_rosetta_config->f32_narrow;
    const bool f32_chain_on =
        f32_narrow_on && g_rosetta_config && g_rosetta_config->f32_arith;
    if (f32_chain_on) {
        // Chains must form before f64 FMA fusion claims the mul+add pairs;
        // pass_fma then fuses whatever stayed f64.
        pass_f32_narrow(ctx);
        pass_f32_chain(ctx);
        pass_f32_fma(ctx);
        pass_fma(ctx);
        pass_dse(ctx);  // reap widens orphaned by the f32 rewrites
    } else {
        pass_fma(ctx);
        if (f32_narrow_on) {
            pass_f32_narrow(ctx);
            pass_dse(ctx);
        }
    }
    pass_fcom_fstsw_fusion(ctx);
}

}  // namespace X87IR
