#include "rosetta_core/X87IR.h"

#include <cstring>

#include "rosetta_config/Config.h"
#include "rosetta_core/AssemblerHelpers.hpp"
#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRInstr.h"
#include "rosetta_core/IROperand.h"
#include "rosetta_core/Opcode.h"

#if defined(ROSETTA_RUNTIME)
// clang-format off
#include "rosetta_core/RuntimeLibC.h"
// clang-format on
#endif

namespace X87IR {

// ── Constant-load promotion ─────────────────────────────────────────────────
//
// 32-bit guests reference FP literals through absolute addresses
// (fld [0x4A5B60]). When such an address lies in a read-only mapping, its
// value cannot change at runtime, so the load can be promoted to a ConstF64
// node at translation time: no runtime load, constants participate in dedup /
// FDiv-reciprocal / FMOV-imm8 lowering. Only sound in JIT mode (the guest
// address space is this process's address space); the caller gates on that.

// Absolute-address operands: AbsMem, or MemRef with neither base nor index.
static bool const_promote_addr(const IROperand* op, uint64_t* addr_out) {
    if (op->kind == IROperandKind::AbsMem) {
        uint64_t a = static_cast<uint64_t>(op->abs_mem.value);
        if (op->abs_mem.addr_size == IROperandSize::S32) a &= 0xFFFFFFFFu;
        *addr_out = a;
        return a != 0;
    }
    if (op->kind == IROperandKind::MemRef && op->mem.seg_override == 0 &&
        (op->mem.mem_flags & 3) == 0) {
        uint64_t a = static_cast<uint64_t>(op->mem.disp);
        if (op->mem.addr_size == IROperandSize::S32) a &= 0xFFFFFFFFu;
        *addr_out = a;
        return a != 0;
    }
    return false;
}

#if defined(ROSETTA_RUNTIME)
// True if [addr, addr+bytes) lies in a mapped, readable region that can
// NEVER become writable: both protection and max_protection must lack
// VM_PROT_WRITE. Current protection alone is not enough — a page that is
// read-only at translation time can be mprotect'ed writable later (asset
// streaming, Wine's VirtualProtect, unpackers), which would leave the
// promoted value stale in translated code. mprotect can never exceed
// max_protection, so a max-RO verdict holds for the mapping's lifetime.
// Queried via proc_info(PROC_PIDREGIONINFO); the last positive region is
// cached (translation is single-threaded).
static bool range_is_readonly(uint64_t addr, uint64_t bytes) {
    static uint64_t cached_lo = 1, cached_hi = 0;  // empty range
    if (addr >= cached_lo && addr + bytes <= cached_hi) return true;

    struct {
        uint32_t protection, max_protection, inheritance, flags;
        uint64_t offset;
        uint32_t behavior, user_wired_count, user_tag, pages_resident,
                 pages_shared_now_private, pages_swapped_out, pages_dirtied,
                 ref_count, shadow_depth, share_mode, private_pages_resident,
                 shared_pages_resident, obj_id, depth;
        uint64_t address, size;
    } ri;
    static_assert(sizeof(ri) == 96, "proc_regioninfo layout");

    const int n = rt_proc_pidinfo(rt_getpid(), /*PROC_PIDREGIONINFO*/ 7, addr, &ri,
                                  (int)sizeof(ri));
    if (n < (int)sizeof(ri)) return false;
    // The kernel returns the region containing addr — or the next one if
    // addr is unmapped — so containment must be checked explicitly.
    if (addr < ri.address || addr + bytes > ri.address + ri.size) return false;
    if ((ri.protection & 0x2 /*VM_PROT_WRITE*/) != 0) return false;
    if ((ri.max_protection & 0x2 /*VM_PROT_WRITE*/) != 0) return false;
    if ((ri.protection & 0x1 /*VM_PROT_READ*/) == 0) return false;
    cached_lo = ri.address;
    cached_hi = ri.address + ri.size;
    return true;
}
#else
// Non-runtime builds (aotinvoke) don't translate a live guest address space.
static bool range_is_readonly(uint64_t, uint64_t) { return false; }
#endif

// ── Memory CSE ──────────────────────────────────────────────────────────────

// Operand identity for memory CSE. Only MemRef and AbsMem participate;
// compare fields explicitly (the union has padding that may be garbage).
static bool mem_operand_equal(const IROperand* a, const IROperand* b) {
    if (a->kind != b->kind) return false;
    if (a->kind == IROperandKind::MemRef) {
        return a->mem.size == b->mem.size &&
               a->mem.addr_size == b->mem.addr_size &&
               a->mem.seg_override == b->mem.seg_override &&
               a->mem.mem_flags == b->mem.mem_flags &&
               a->mem.base_reg == b->mem.base_reg &&
               a->mem.index_reg == b->mem.index_reg &&
               a->mem.shift_amount == b->mem.shift_amount &&
               a->mem.disp == b->mem.disp;
    }
    if (a->kind == IROperandKind::AbsMem) {
        return a->abs_mem.size == b->abs_mem.size &&
               a->abs_mem.addr_size == b->abs_mem.addr_size &&
               a->abs_mem.value == b->abs_mem.value;
    }
    if (a->kind == IROperandKind::Immediate) {
        // Text-base-relative operands: value is the byte offset from the
        // guest text base (mem_flags selects the target/addend encoding, so
        // it must match for the values to be comparable).
        return a->imm.size == b->imm.size &&
               a->imm.addr_size == b->imm.addr_size &&
               a->imm.mem_flags == b->imm.mem_flags &&
               a->imm.value == b->imm.value;
    }
    return false;
}

static int mem_operand_width(const IROperand* op) {
    const IROperandSize sz =
        (op->kind == IROperandKind::AbsMem) ? op->abs_mem.size : op->mem.size;
    switch (sz) {
        case IROperandSize::S16: return 2;
        case IROperandSize::S32: return 4;
        case IROperandSize::S64: return 8;
        default: return 0;  // unknown width — treated as may-alias
    }
}

// Provably disjoint accesses: same-kind operands whose address expressions
// share the exact same dynamic base (registers cannot change within a run)
// and whose [disp, disp+width) byte ranges do not overlap. Anything not
// provable — different base registers, segment overrides, mixed kinds —
// counts as aliasing. 32-bit addressing note: disps are compared without
// mod-2^32 wrap, the same (documented) divergence the base-address cache
// accepts — only reachable via pointer wraparound.
static bool mem_operands_no_alias(const IROperand* a, const IROperand* b) {
    const int aw = mem_operand_width(a), bw = mem_operand_width(b);
    if (aw == 0 || bw == 0) return false;
    if (a->kind == IROperandKind::MemRef && b->kind == IROperandKind::MemRef) {
        if (a->mem.seg_override != 0 || b->mem.seg_override != 0) return false;
        if (a->mem.addr_size != b->mem.addr_size ||
            a->mem.mem_flags != b->mem.mem_flags ||
            a->mem.base_reg != b->mem.base_reg ||
            a->mem.index_reg != b->mem.index_reg ||
            a->mem.shift_amount != b->mem.shift_amount)
            return false;
        return a->mem.disp + aw <= b->mem.disp || b->mem.disp + bw <= a->mem.disp;
    }
    if (a->kind == IROperandKind::AbsMem && b->kind == IROperandKind::AbsMem) {
        uint64_t aa = static_cast<uint64_t>(a->abs_mem.value);
        uint64_t ba = static_cast<uint64_t>(b->abs_mem.value);
        if (a->abs_mem.addr_size == IROperandSize::S32) aa &= 0xFFFFFFFFu;
        if (b->abs_mem.addr_size == IROperandSize::S32) ba &= 0xFFFFFFFFu;
        return aa + aw <= ba || ba + bw <= aa;
    }
    if (a->kind == IROperandKind::Immediate &&
        b->kind == IROperandKind::Immediate &&
        a->imm.mem_flags == b->imm.mem_flags) {
        // Same text base, disjoint [offset, offset+width) byte ranges.
        const int64_t av = a->imm.value, bv = b->imm.value;
        return av + aw <= bv || bv + bw <= av;
    }
    return false;
}

// Drop every CSE entry the store may alias, keeping proven-disjoint ones.
static void mem_cse_evict_may_alias(Context& ctx, const IROperand* store_op) {
    int kept = 0;
    for (int i = 0; i < ctx.mem_cse_count; i++) {
        if (mem_operands_no_alias(ctx.mem_cse_op[i], store_op)) {
            ctx.mem_cse_op[kept] = ctx.mem_cse_op[i];
            ctx.mem_cse_kind[kept] = ctx.mem_cse_kind[i];
            ctx.mem_cse_val[kept] = ctx.mem_cse_val[i];
            kept++;
        }
    }
    ctx.mem_cse_count = static_cast<int8_t>(kept);
    ctx.mem_cse_next = 0;
}

// True if the operand's address depends on guest GPR `reg` (base or index).
// AbsMem never references registers.
static bool mem_operand_uses_reg(const IROperand* op, int reg) {
    if (op->kind != IROperandKind::MemRef) return false;
    if ((op->mem.mem_flags & 1) && (op->mem.base_reg & 0xF) == reg) return true;
    if ((op->mem.mem_flags & 2) && (op->mem.index_reg & 0xF) == reg) return true;
    return false;
}

// Drop every CSE entry whose address uses guest GPR `reg` — after an inlined
// guest instruction redefines it, the same operand text addresses a
// different location.
static void mem_cse_evict_reg(Context& ctx, int reg) {
    int kept = 0;
    for (int i = 0; i < ctx.mem_cse_count; i++) {
        if (!mem_operand_uses_reg(ctx.mem_cse_op[i], reg)) {
            ctx.mem_cse_op[kept] = ctx.mem_cse_op[i];
            ctx.mem_cse_kind[kept] = ctx.mem_cse_kind[i];
            ctx.mem_cse_val[kept] = ctx.mem_cse_val[i];
            kept++;
        }
    }
    ctx.mem_cse_count = static_cast<int8_t>(kept);
    ctx.mem_cse_next = 0;
}

static int16_t mem_cse_lookup(Context& ctx, const IROperand* op, Op kind) {
    for (int i = 0; i < ctx.mem_cse_count; i++) {
        if (ctx.mem_cse_kind[i] == kind && mem_operand_equal(ctx.mem_cse_op[i], op))
            return ctx.mem_cse_val[i];
    }
    return -1;
}

static void mem_cse_insert(Context& ctx, IROperand* op, Op kind, int16_t val) {
    if (op->kind != IROperandKind::MemRef && op->kind != IROperandKind::AbsMem &&
        op->kind != IROperandKind::Immediate)
        return;
    int slot;
    if (ctx.mem_cse_count < Context::kMemCSESlots) {
        slot = ctx.mem_cse_count++;
    } else {
        slot = ctx.mem_cse_next;
        ctx.mem_cse_next = static_cast<int8_t>((slot + 1) % Context::kMemCSESlots);
    }
    ctx.mem_cse_op[slot] = op;
    ctx.mem_cse_kind[slot] = kind;
    ctx.mem_cse_val[slot] = val;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

static int16_t build_const(Context& ctx, uint64_t bits);

// Constant node for a known f64 bit pattern; +0.0 / +1.0 get the cheaper
// MOVI / FMOV-one nodes (and their dedup).
static int16_t const_node_for_bits(Context& ctx, uint64_t bits) {
    if (bits == 0) {
        if (ctx.const_zero_node >= 0) return ctx.const_zero_node;
        auto id = ctx.add_node(Op::ConstZero);
        if (id >= 0) ctx.const_zero_node = id;
        return id;
    }
    if (bits == 0x3FF0000000000000ULL) {
        if (ctx.const_one_node >= 0) return ctx.const_one_node;
        auto id = ctx.add_node(Op::ConstOne);
        if (id >= 0) ctx.const_one_node = id;
        return id;
    }
    return build_const(ctx, bits);
}

// f32 → f64 widening in pure integer arithmetic (exact; every f32 is
// representable). Translation-time code runs on the guest thread with the
// guest's live XMM state in v0-v15, so it must not execute FP instructions:
// a compiler-emitted FCVT here deposits the promoted constant's value into a
// live guest register (this was a real, layout-sensitive corruption bug —
// research/const_promote_isinf_bug/).
static uint64_t widen_f32_to_f64_bits(uint32_t fb) {
    const uint64_t sign = static_cast<uint64_t>(fb >> 31) << 63;
    const uint32_t exp = (fb >> 23) & 0xFF;
    const uint64_t frac = fb & 0x7FFFFF;

    if (exp == 0xFF) {  // Inf / NaN — quiet the NaN like hardware FCVT does
        uint64_t f = frac << 29;
        if (frac != 0) f |= 0x0008000000000000ULL;
        return sign | 0x7FF0000000000000ULL | f;
    }
    if (exp == 0) {
        if (frac == 0) return sign;  // ±0
        // Denormal: value = frac * 2^-149; normalize into f64 (always normal).
        const int n = 31 - __builtin_clz(static_cast<unsigned>(frac));  // MSB pos
        const uint64_t mant = (frac << (52 - n)) & 0x000FFFFFFFFFFFFFULL;
        return sign | (static_cast<uint64_t>(n - 149 + 1023) << 52) | mant;
    }
    return sign | (static_cast<uint64_t>(exp - 127 + 1023) << 52) | (frac << 29);
}

// Promote an fp load from a read-only absolute address to a constant node.
// Returns the node ID, or -1 if not promotable.
static int16_t try_const_promote(Context& ctx, const IROperand* op, Op load_op) {
    if (!ctx.const_promote) return -1;
    uint64_t addr;
    if (!const_promote_addr(op, &addr)) return -1;
    const uint64_t width = (load_op == Op::LoadF32Raw) ? 4 : 8;
    if (!range_is_readonly(addr, width)) return -1;

    uint64_t bits;
    if (load_op == Op::LoadF32Raw) {
        uint32_t fb;
        memcpy(&fb, reinterpret_cast<const void*>(addr), 4);
        bits = widen_f32_to_f64_bits(fb);  // integer-only: no FP insns here
    } else {
        memcpy(&bits, reinterpret_cast<const void*>(addr), 8);
    }
    return const_node_for_bits(ctx, bits);
}

// Convert an x87 80-bit extended value (64-bit mantissa with explicit integer
// bit + sign/15-bit-exponent word) to f64 bits, round-to-nearest-even — the
// same result the runtime fld_fp80 routine produces (ST regs are f64).
// Returns false for values this converter doesn't handle (results that would
// be denormal in f64) — the caller then declines promotion.
static bool f80_to_f64_bits(uint64_t m, uint16_t se, uint64_t* out) {
    const uint64_t sign = static_cast<uint64_t>(se >> 15) << 63;
    int e = se & 0x7FFF;

    if (m == 0) {  // ±0 (e==0) or pseudo-infinity (invalid; don't promote)
        if (e != 0) return false;
        *out = sign;
        return true;
    }
    if (e == 0x7FFF) {
        if ((m << 1) == 0) {  // infinity (only the integer bit set)
            *out = sign | 0x7FF0000000000000ULL;
            return true;
        }
        // NaN: keep the top fraction bits, force the quiet bit (matches the
        // x87 load behavior of quieting SNaNs).
        uint64_t frac = (m >> 11) & 0x000FFFFFFFFFFFFFULL;
        frac |= 0x0008000000000000ULL;
        *out = sign | 0x7FF0000000000000ULL | frac;
        return true;
    }

    // Normalize (covers denormals e==0 and unnormals with a clear integer
    // bit): value = m * 2^(max(e,1) - 16383 - 63).
    if (e == 0) e = 1;
    const int shift = __builtin_clzll(m);
    m <<= shift;
    int E = (e - 16383) - shift;  // exponent of the (now bit-63) leading 1

    // Round the 64-bit mantissa to 53 bits (round-to-nearest-even).
    uint64_t mant = m >> 11;
    const uint64_t rem = m & 0x7FF;
    if (rem > 0x400 || (rem == 0x400 && (mant & 1))) {
        if (++mant == (1ULL << 53)) { mant >>= 1; E++; }
    }
    if (E > 1023) {  // overflows f64 → infinity
        *out = sign | 0x7FF0000000000000ULL;
        return true;
    }
    if (E < -1022) return false;  // would be denormal — decline
    *out = sign | (static_cast<uint64_t>(E + 1023) << 52) |
           (mant & 0x000FFFFFFFFFFFFFULL);
    return true;
}

// FLD m80fp from a read-only absolute address: promote to a constant node
// (the only way the IR can handle m80 — there is no 80-bit load node).
static int16_t try_const_promote_m80(Context& ctx, const IROperand* op) {
    if (!ctx.const_promote) return -1;
    uint64_t addr;
    if (!const_promote_addr(op, &addr)) return -1;
    if (!range_is_readonly(addr, 10)) return -1;

    uint64_t m;
    uint16_t se;
    memcpy(&m, reinterpret_cast<const void*>(addr), 8);
    memcpy(&se, reinterpret_cast<const void*>(addr + 8), 2);
    uint64_t bits;
    if (!f80_to_f64_bits(m, se, &bits)) return -1;
    return const_node_for_bits(ctx, bits);
}

// Build a memory load node. Returns node ID (always f64-typed) or -1 on bail
// (e.g. m80). Identical operands within the run reuse the prior load's value
// (CSE). f32 loads decompose into a raw S-register load + explicit widen so
// the raw access can pair/forward; the CSE entry (kind LoadF32Raw) caches the
// widened view.
static int16_t build_fp_load(Context& ctx, IROperand* op) {
    const bool is_f32 = op->mem.size == IROperandSize::S32;
    if (!is_f32 && op->mem.size != IROperandSize::S64) {
        if (op->mem.size == IROperandSize::S80)
            return try_const_promote_m80(ctx, op);  // m80: const-promote or bail
        return -1;
    }
    const Op load_op = is_f32 ? Op::LoadF32Raw : Op::LoadF64;
    auto promoted = try_const_promote(ctx, op, load_op);
    if (promoted >= 0) return promoted;
    auto hit = mem_cse_lookup(ctx, op, load_op);
    if (hit >= 0) return hit;
    auto id = ctx.add_node(load_op);
    if (id < 0) return -1;
    ctx.nodes[id].mem_operand = op;
    if (is_f32) {
        id = ctx.add_node(Op::CvtF32ToF64, id);
        if (id < 0) return -1;
    }
    mem_cse_insert(ctx, op, load_op, id);
    return id;
}

static int16_t build_int_load(Context& ctx, IROperand* op) {
    Op load_op;
    switch (op->mem.size) {
        case IROperandSize::S16: load_op = Op::LoadI16; break;
        case IROperandSize::S32: load_op = Op::LoadI32; break;
        case IROperandSize::S64: load_op = Op::LoadI64; break;
        default: return -1;
    }
    auto hit = mem_cse_lookup(ctx, op, load_op);
    if (hit >= 0) return hit;
    auto id = ctx.add_node(load_op);
    if (id < 0) return -1;
    ctx.nodes[id].mem_operand = op;
    mem_cse_insert(ctx, op, load_op, id);
    return id;
}

// Build a constant-push (FLDL2E, FLDL2T, etc.), reusing a prior node with
// the same bit pattern.
static int16_t build_const(Context& ctx, uint64_t bits) {
    for (int i = 0; i < ctx.const_f64_count; i++) {
        if (ctx.const_f64_bits[i] == bits) return ctx.const_f64_node[i];
    }
    auto id = ctx.add_node(Op::ConstF64);
    if (id < 0) return -1;
    ctx.nodes[id].imm_bits = bits;
    int slot;
    if (ctx.const_f64_count < Context::kConstF64Slots) {
        slot = ctx.const_f64_count++;
    } else {
        slot = ctx.const_f64_next;
        ctx.const_f64_next =
            static_cast<int8_t>((slot + 1) % Context::kConstF64Slots);
    }
    ctx.const_f64_node[slot] = id;
    ctx.const_f64_bits[slot] = bits;
    return id;
}

// Emit a memory store side-effect node.
static bool build_fp_store(Context& ctx, IROperand* op, int16_t val_node) {
    const bool is_f32 = op->mem.size == IROperandSize::S32;
    if (!is_f32 && op->mem.size != IROperandSize::S64) return false;  // m80 → bail

    int16_t store_val = val_node;
    if (is_f32) {
        if (ctx.nodes[val_node].op == Op::CvtF32ToF64) {
            // Copy elision: narrow(widen(x)) == x — store the raw f32 bits
            // directly; DSE reaps the widen if this was its only use.
            store_val = ctx.nodes[val_node].inputs[0];
        } else if (ctx.last_narrow_input == val_node) {
            // Repeated f32 stores of one value share a single FCVT.
            store_val = ctx.last_narrow_node;
        } else {
            store_val = ctx.add_node(Op::CvtF64ToF32, val_node);
            if (store_val < 0) return false;
            ctx.last_narrow_input = val_node;
            ctx.last_narrow_node = store_val;
        }
    }

    const Op store_op = is_f32 ? Op::StoreF32Raw : Op::StoreF64;
    auto id = ctx.add_node(store_op, store_val);
    if (id < 0) return false;
    ctx.nodes[id].mem_operand = op;
    // Evict cached loads the store may alias (proven-disjoint entries
    // survive). Then forward the stored value to later loads of the same
    // operand. f64 round-trips are bit-exact; for f32
    // a reload returns widen(narrow(val)), so forward the f64 view of the
    // *narrowed* value — the original widen node when the stored value came
    // from one, else a fresh widen of the narrowed bits (DSE reaps it if no
    // later load reads it).
    mem_cse_evict_may_alias(ctx, op);
    if (store_op == Op::StoreF64) {
        mem_cse_insert(ctx, op, Op::LoadF64, val_node);
    } else {
        int16_t fwd = (ctx.nodes[val_node].op == Op::CvtF32ToF64)
                          ? val_node
                          : ctx.add_node(Op::CvtF32ToF64, store_val);
        if (fwd >= 0) mem_cse_insert(ctx, op, Op::LoadF32Raw, fwd);
    }
    return true;
}

// Emit an integer store side-effect node (FISTP/FIST/FISTTP).
static bool build_int_store(Context& ctx, IROperand* op, int16_t val_node, bool truncate) {
    Op store_op;
    switch (op->mem.size) {
        case IROperandSize::S16: store_op = Op::StoreI16; break;
        case IROperandSize::S32: store_op = Op::StoreI32; break;
        case IROperandSize::S64: store_op = Op::StoreI64; break;
        default: return false;
    }
    auto id = ctx.add_node(store_op, val_node);
    if (id < 0) return false;
    ctx.nodes[id].mem_operand = op;
    if (truncate)
        ctx.nodes[id].flags |= kTruncate;
    else if (ctx.known_rc >= 0)
        // OPT-CF: RC is a translate-time constant here — the lowering emits
        // one statically-rounded FCVT instead of the dispatch tree.
        ctx.nodes[id].aux = 0x100u | static_cast<uint32_t>(ctx.known_rc);
    // Evict may-aliasing entries; no forwarding (f64→int isn't invertible).
    mem_cse_evict_may_alias(ctx, op);
    return true;
}

// ── Non-popping binary arithmetic ───────────────────────────────────────────

// Handles FADD/FSUB/FSUBR/FMUL/FDIV/FDIVR (non-popping).
// `base_op` is the IR op (FAdd/FSub/FMul/FDiv).
// `reversed` flips operand order (for FSUBR/FDIVR).
static bool build_arith(Context& ctx, IRInstr* instr, Op base_op, bool reversed) {
    if (instr->operands[0].kind == IROperandKind::Register) {
        // ST-ST path
        int depth_dst = instr->operands[0].reg.reg.index();
        int depth_src = instr->operands[1].reg.reg.index();
        auto dst_val = ctx.resolve(depth_dst);
        auto src_val = ctx.resolve(depth_src);
        if (dst_val < 0 || src_val < 0) return false;
        auto id = reversed
            ? ctx.add_node(base_op, src_val, dst_val)
            : ctx.add_node(base_op, dst_val, src_val);
        if (id < 0) return false;
        ctx.slot_val[depth_dst] = id;
    } else {
        // Memory path: ST(0) op= mem (or ST(0) = mem op ST(0) for reversed)
        auto st0 = ctx.resolve(0);
        if (st0 < 0) return false;
        auto mem_val = build_fp_load(ctx, &instr->operands[0]);
        if (mem_val < 0) return false;
        auto id = reversed
            ? ctx.add_node(base_op, mem_val, st0)
            : ctx.add_node(base_op, st0, mem_val);
        if (id < 0) return false;
        ctx.slot_val[0] = id;
    }
    return true;
}

// Handles FADDP/FSUBP/FSUBRP/FMULP/FDIVP/FDIVRP (popping).
static bool build_arithp(Context& ctx, IRInstr* instr, Op base_op, bool reversed) {
    int depth_dst = instr->operands[0].reg.reg.index();
    auto dst_val = ctx.resolve(depth_dst);
    auto src_val = ctx.resolve(0);
    if (dst_val < 0 || src_val < 0) return false;
    auto id = reversed
        ? ctx.add_node(base_op, src_val, dst_val)
        : ctx.add_node(base_op, dst_val, src_val);
    if (id < 0) return false;
    ctx.slot_val[depth_dst] = id;
    ctx.pop();
    return true;
}

// ── FCOM / FUCOM family ─────────────────────────────────────────────────────

static bool build_fcom(Context& ctx, IRInstr* instr, int num_pops, bool is_fcompp) {
    int16_t lhs = ctx.resolve(0);
    if (lhs < 0) return false;

    int16_t rhs;
    if (is_fcompp) {
        // FCOMPP/FUCOMPP: comparand is always ST(1).
        rhs = ctx.resolve(1);
    } else if (instr->operands[1].kind == IROperandKind::Register) {
        // FCOM/FCOMP ST(i): Rosetta encodes as [ST(0), ST(i)].
        // Comparand depth is in operands[1].
        int src_depth = instr->operands[1].reg.reg.index();
        rhs = ctx.resolve(src_depth);
    } else {
        // FCOM/FCOMP m32fp / m64fp: memory operand is operands[1].
        rhs = build_fp_load(ctx, &instr->operands[1]);
    }
    if (rhs < 0) return false;

    auto id = ctx.add_node(Op::FCmp, lhs, rhs);
    if (id < 0) return false;
    ctx.last_fcmp = id;

    for (int i = 0; i < num_pops; i++) ctx.pop();
    return true;
}

// ── FICOM / FICOMP ──────────────────────────────────────────────────────────

static bool build_ficom(Context& ctx, IRInstr* instr, bool is_popping) {
    int16_t lhs = ctx.resolve(0);
    if (lhs < 0) return false;

    // FICOM/FICOMP: operands[0] = m16int/m32int MemRef (like FIADD).
    int16_t rhs = build_int_load(ctx, &instr->operands[0]);
    if (rhs < 0) return false;

    auto id = ctx.add_node(Op::FCmp, lhs, rhs);
    if (id < 0) return false;
    ctx.last_fcmp = id;

    if (is_popping) ctx.pop();
    return true;
}

// ── FCOMI / FCOMIP / FUCOMI / FUCOMIP ───────────────────────────────────────

static bool build_fcomi(Context& ctx, IRInstr* instr, bool is_popping) {
    int16_t st0 = ctx.resolve(0);
    if (st0 < 0) return false;

    // Comparand is always a register ST(i); Rosetta encodes as [ST(0), ST(i)].
    int src_depth = instr->operands[1].reg.reg.index();
    int16_t src = ctx.resolve(src_depth);
    if (src < 0) return false;

    auto id = ctx.add_node(Op::FComI, st0, src);
    if (id < 0) return false;
    if (is_popping) ctx.nodes[id].flags |= kFcomIPopping;

    // Do NOT update ctx.last_fcmp — FComI sets NZCV directly, not status_word CC.
    ctx.last_fcomi = id;

    if (is_popping) ctx.pop();
    return true;
}

// ── FCMOV family (conditional move to ST(0)) ────────────────────────────────

// Conditions that read PSTATE.C: CS, CC, HI, LS.
static bool cond_reads_carry(int cond) {
    return cond == 2 || cond == 3 || cond == 8 || cond == 9;
}

static bool build_fcmov(Context& ctx, IRInstr* instr, int aarch64_cond) {
    // Safety: FCMOV reads NZCV. Admissible when a prior node in THIS run
    // installed known guest flags — an FComI, or a consumed guest cmp/test
    // (GuestCmpF, whose SUBS/ANDS flags are exactly what x86 fcmovcc tests
    // after cmp). Whichever is later owns the flags; plan_fcomi_raw resolves
    // which convention the FCSel condition reads. No definer → bail.
    if (ctx.last_fcomi < 0 && ctx.last_guest_flagdef < 0) return false;

    // C-reading conditions against a consumed TEST producer need the ¬CF
    // convention state (see build_guest_cmp's CFINV note) — force the bit.
    // Rosetta's flag-liveness only covers integer consumers, so an fcmovcc
    // read may not have made CF live at the test.
    if (ctx.last_guest_flagdef > ctx.last_fcomi &&
        (ctx.nodes[ctx.last_guest_flagdef].aux & 1) != 0 &&
        cond_reads_carry(aarch64_cond))
        ctx.nodes[ctx.last_guest_flagdef].aux |= 0x20u;

    int16_t st0 = ctx.resolve(0);
    if (st0 < 0) return false;

    int src_depth = instr->operands[1].reg.reg.index();
    int16_t src = ctx.resolve(src_depth);
    if (src < 0) return false;

    auto id = ctx.add_node(Op::FCSel, st0, src);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = static_cast<uint64_t>(aarch64_cond);

    ctx.slot_val[0] = id;
    return true;
}

// ── Run-transparent guest integer instructions (opt-in) ────────────────────
//
// ROSETTA_X87_TRANSPARENT_INT=1: consume whitelisted mov/movzx/movsx/movsxd/
// lea/nop mid-run as Guest* IR nodes instead of ending the run — SSA values
// stay in FPRs across them, and one Context (mem-CSE, const dedup, base
// cache) spans the former gap. lookahead only ever counts these inside a run
// when RUN_BRIDGE counted a gap (TRANSPARENT_INT implies RUN_BRIDGE).
//
// v1 accepts only forms exactly representable in 1-2 flag-free A64
// instructions with a register destination:
//   - 8/16-bit destinations (partial-register merge) → decline
//   - memory sources/destinations → decline (stay bridge-only)
//   - mov r64, imm → decline (imm sign-extension semantics not needed for
//     the 32-bit target; keeps the payload at 32 bits)
//   - immediates carrying a fixup (relocated address) → decline: the payload
//     is the fixup target, not the literal
// A declined instruction ends IR consumption there; the run bridge still
// carries the pinned GPRs across it and the IR re-enters mid-run after.
//
// ROSETTA_X87_TRANSPARENT_FLAGS=1 (implies TRANSPARENT_INT) extends the set
// with flag-writing ALU forms — the xor r,r zero idiom, reg-imm
// add/sub/and/or/xor/shl/shr/sar, and {add,sub,and,or,xor} [m],r — gated on
// Rosetta's flag-liveness analysis proving the written flags dead (see
// build_guest_alu).

// The arithmetic EFLAGS — every flag_liveness bit except DF (0x01). The
// binary ALU forms below define all of these (AF at worst architecturally
// undefined, matching Rosetta's 0xfe rows), so their gate is "no arithmetic
// flag live"; DF-liveness (string ops downstream) never blocks consumption
// since none of these forms touch DF.
static constexpr uint8_t kEflagsArith =
    FLAG_AF | FLAG_PF | FLAG_OF | FLAG_CF | FLAG_ZF | FLAG_SF;

// GuestAlu selector for a flag-writing ALU opcode; -1 for anything else.
static int guest_alu_of(uint16_t op) {
    switch (op) {
        case kOpcodeName_add: return static_cast<int>(GuestAlu::Add);
        case kOpcodeName_sub: return static_cast<int>(GuestAlu::Sub);
        case kOpcodeName_and: return static_cast<int>(GuestAlu::And);
        case kOpcodeName_or:  return static_cast<int>(GuestAlu::Or);
        case kOpcodeName_xor: return static_cast<int>(GuestAlu::Xor);
        case kOpcodeName_shl: return static_cast<int>(GuestAlu::Shl);
        case kOpcodeName_shr: return static_cast<int>(GuestAlu::Shr);
        case kOpcodeName_sar: return static_cast<int>(GuestAlu::Sar);
        default: return -1;
    }
}

// Memory operand admissible for a Guest load/store: no segment override
// (compute_operand_address's GS/TLS fallback fixed-allocates pool slot 7 and
// blows the pressure model) and a width the LDR/STR forms cover.
static bool guest_mem_operand_ok(const IROperand& m, bool allow64) {
    if (m.kind == IROperandKind::MemRef) {
        if (m.mem.seg_override != 0) return false;
        switch (m.mem.size) {
            case IROperandSize::S8: case IROperandSize::S16:
            case IROperandSize::S32: return true;
            case IROperandSize::S64: return allow64;
            default: return false;
        }
    }
    if (m.kind == IROperandKind::AbsMem) {
        switch (m.abs_mem.size) {
            case IROperandSize::S8: case IROperandSize::S16:
            case IROperandSize::S32: return true;
            case IROperandSize::S64: return allow64;
            default: return false;
        }
    }
    return false;
}

static IROperandSize guest_mem_size(const IROperand& m) {
    return m.kind == IROperandKind::AbsMem ? m.abs_mem.size : m.mem.size;
}

// ── Flag-writing ALU forms (opt-in TRANSPARENT_FLAGS) ───────────────────────
//
// add/sub/and/or/xor r,imm — shl/shr/sar r,imm — {add,sub,and,or,xor} [m],r —
// and the xor r,r zero idiom.  Every one of these defines the arithmetic
// EFLAGS, so all are gated on Rosetta's backward flag-liveness analysis
// proving the results dead: flag_liveness holds the flags live OUT of this
// instruction (block-fixpoint, conservative all-live at unknown targets),
// so no kEflagsArith bit live means nothing this instruction writes is ever
// read (DF-liveness never blocks: these forms don't touch DF).  Every
// lowering is flag-free on the host (MOVZ / ADD / SUB / AND / ORR / EOR /
// UBFM / SBFM / LDR / STR), so the Guest-node NZCV contract is unchanged.
//
// Form restrictions (everything else declines, ending IR consumption there):
//   - 8/16-bit operands → decline (partial-register / partial-width RMW)
//   - shift by CL, reg-reg ALU (except self-xor), mem-dest shifts → decline
//   - LOCK'd RMW (rep_prefix != 0 selects the exclusive-loop path) → decline
//   - logical immediates must be AArch64-bitmask-encodable; for r64 the
//     imm32 is sign-extended first (x86 semantics), add/sub take any imm32
//   - shift counts are pre-masked (& 31 / & 63); a masked count of 0 is a
//     pure no-op and is consumed without emitting a node
static bool build_guest_alu(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_flags)) return false;
    if (instr->flag_liveness & kEflagsArith) return false;
    if (instr->num_operands < 2) return false;
    const IROperand& dst = instr->operands[0];
    const IROperand& src = instr->operands[1];
    const int alu = guest_alu_of(op);

    // xor r,r zero idiom → GuestMovRI 0 (the W-write zero-extend covers r64).
    if (op == kOpcodeName_xor && dst.kind == IROperandKind::Register &&
        src.kind == IROperandKind::Register) {
        if (!dst.reg.reg.is_gpr() || !src.reg.reg.is_gpr()) return false;
        if (dst.reg.size != IROperandSize::S32 &&
            dst.reg.size != IROperandSize::S64)
            return false;
        if (src.reg.size != dst.reg.size) return false;
        if (src.reg.reg.value != dst.reg.reg.value) return false;
        GuestPayload p = {};
        p.dst = dst.reg.reg.index();
        p.imm = 0;
        auto id = ctx.add_node(Op::GuestMovRI);
        if (id < 0) return false;
        ctx.nodes[id].imm_bits = guest_pack(p);
        ctx.guest_written_mask |= static_cast<uint16_t>(1u << p.dst);
        mem_cse_evict_reg(ctx, p.dst);
        return true;
    }

    // Memory-destination RMW: {add,sub,and,or,xor} [m32/m64], r.
    if (dst.kind == IROperandKind::MemRef || dst.kind == IROperandKind::AbsMem) {
        if (alu > static_cast<int>(GuestAlu::Xor)) return false;  // no mem shifts
        if (instr->rep_prefix != 0) return false;  // LOCK → exclusive path
        if (src.kind != IROperandKind::Register || !src.reg.reg.is_gpr())
            return false;
        const IROperandSize msz = guest_mem_size(dst);
        if (msz != IROperandSize::S32 && msz != IROperandSize::S64) return false;
        if (src.reg.size != msz) return false;
        if (!guest_mem_operand_ok(dst, /*allow64=*/msz == IROperandSize::S64))
            return false;
        auto id = ctx.add_node(Op::GuestRmwR);
        if (id < 0) return false;
        ctx.nodes[id].mem_operand = &instr->operands[0];
        ctx.nodes[id].aux = static_cast<uint64_t>(src.reg.reg.index()) |
                            (static_cast<uint64_t>(alu) << 4);
        // Reads then writes [m]: cached loads it may alias are stale.
        mem_cse_evict_may_alias(ctx, &instr->operands[0]);
        return true;
    }

    // Register-destination immediate forms.
    if (dst.kind != IROperandKind::Register || !dst.reg.reg.is_gpr()) return false;
    const bool is64 = dst.reg.size == IROperandSize::S64;
    if (!is64 && dst.reg.size != IROperandSize::S32) return false;
    if (src.kind == IROperandKind::Register || src.kind == IROperandKind::MemRef ||
        src.kind == IROperandKind::AbsMem)
        return false;  // shift-by-CL / reg-reg ALU / mem source
    if (src.kind == IROperandKind::Immediate && src.imm.mem_flags != 0)
        return false;  // fixup: the payload is the target, not the literal
    uint32_t imm = static_cast<uint32_t>(src.imm.value);

    switch (static_cast<GuestAlu>(alu)) {
        case GuestAlu::Shl:
        case GuestAlu::Shr:
        case GuestAlu::Sar:
            imm &= is64 ? 63 : 31;
            if (imm == 0) return true;  // masked count 0: architectural no-op
            break;
        case GuestAlu::And:
        case GuestAlu::Or:
        case GuestAlu::Xor: {
            const uint64_t v =
                is64 ? static_cast<uint64_t>(static_cast<int64_t>(
                           static_cast<int32_t>(imm)))
                     : imm;
            LogicalImmEncoding enc;
            if (!is_bitmask_immediate(is64, v, enc)) return false;
            break;
        }
        default:
            break;  // Add/Sub: emit_add_disp covers any imm32
    }

    GuestPayload p = {};
    p.dst = dst.reg.reg.index();
    p.is64 = is64;
    p.imm = imm;
    auto id = ctx.add_node(Op::GuestAluRI);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    ctx.nodes[id].aux = static_cast<uint64_t>(alu);
    ctx.guest_written_mask |= static_cast<uint16_t>(1u << p.dst);
    mem_cse_evict_reg(ctx, p.dst);
    return true;
}

// ── Unary ALU forms: inc/dec/neg r (TRANSPARENT_FLAGS), not r (INT tier) ────
//
// Register-destination forms of the alu-unary family only (mem/abs/RIP-RMW
// destinations decline and stay bridge-only — the family is audited for
// bridging). Per-form liveness gates:
//   inc/dec — define OF/SF/ZF/AF/PF but PRESERVE CF, so consumption only
//     needs those five dead; CF may stay live (the flag-free ADD/SUB
//     lowering leaves guest CF in host NZCV untouched, exactly matching
//     x86 inc/dec semantics — Rosetta's own translation makes the same
//     bet, emitting flag-clobbering SUBS when fl & FLAG_CF == 0).
//   neg — defines all arithmetic flags (CF = src != 0) → kEflagsArith gate.
//   not — writes NO flags: no gate at all, and only TRANSPARENT_INT
//     (flag-neutral like mov/lea, no reason to require the FLAGS tier).
// 8/16-bit forms decline (partial-register merge). LOCK (rep_prefix) can
// only reach the mem forms, which decline anyway.
static bool build_guest_unary(Context& ctx, IRInstr* instr, uint16_t op) {
    const bool is_not = (op == kOpcodeName_not);
    if (is_not) {
        if (!(g_rosetta_config && g_rosetta_config->transparent_int))
            return false;
    } else {
        if (!(g_rosetta_config && g_rosetta_config->transparent_flags))
            return false;
        const uint8_t defined =
            (op == kOpcodeName_neg)
                ? kEflagsArith
                : static_cast<uint8_t>(kEflagsArith & ~FLAG_CF);
        if (instr->flag_liveness & defined) return false;
    }
    if (instr->num_operands < 1) return false;
    const IROperand& dst = instr->operands[0];
    if (dst.kind != IROperandKind::Register || !dst.reg.reg.is_gpr())
        return false;
    const bool is64 = dst.reg.size == IROperandSize::S64;
    if (!is64 && dst.reg.size != IROperandSize::S32) return false;

    GuestPayload p = {};
    p.dst = dst.reg.reg.index();
    p.is64 = is64;
    GuestAlu alu;
    switch (op) {
        case kOpcodeName_inc: alu = GuestAlu::Add; p.imm = 1; break;
        case kOpcodeName_dec: alu = GuestAlu::Sub; p.imm = 1; break;
        case kOpcodeName_neg: alu = GuestAlu::Neg; break;
        default:              alu = GuestAlu::Not; break;
    }
    auto id = ctx.add_node(Op::GuestAluRI);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    ctx.nodes[id].aux = static_cast<uint64_t>(alu);
    ctx.guest_written_mask |= static_cast<uint16_t>(1u << p.dst);
    mem_cse_evict_reg(ctx, p.dst);
    return true;
}

// ── push/pop transparency (opt-in TRANSPARENT_PUSHPOP) ──────────────────────
//
// push r / push imm / pop r consumed mid-run. Flag-neutral, so no liveness
// gate; the lowering mirrors Rosetta's own translation exactly (STR pre-index
// / LDR post-index writeback on guest RSP = x4, 64-bit address arithmetic).
// Declines: RSP as the data register (x86 push esp stores the OLD value and
// pop esp discards the increment — plus Rt==Rn writeback is CONSTRAINED
// UNPREDICTABLE), 8/16-bit operand sizes (pushw/popw), memory forms, and
// immediates carrying a fixup. The slot size for immediate pushes comes from
// the opcode (push = 64-bit mode, pushd = 32-bit); register forms use the
// register's own size.
//
// Memory model: a push writes [rsp-slot] with no decoder operand to prove
// disjointness against, so it conservatively clears the whole mem-CSE table.
// A pop reads memory (no eviction) but redefines its destination register.
// Both redefine RSP, so both evict RSP-addressed CSE entries and set the
// written mask (which also bars RSP-based operands from the base-address
// cache and staleness-checks carried bases).
static bool build_guest_pushpop(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_pushpop))
        return false;
    if (instr->num_operands < 1) return false;
    const IROperand& o = instr->operands[0];
    const bool is_push = (op == kOpcodeName_push || op == kOpcodeName_pushd);

    if (o.kind == IROperandKind::Register) {
        if (!o.reg.reg.is_gpr()) return false;
        const bool is64 = o.reg.size == IROperandSize::S64;
        if (!is64 && o.reg.size != IROperandSize::S32) return false;
        const int r = o.reg.reg.index();
        if (r == 4) return false;  // RSP data register — see above
        GuestPayload p = {};
        p.dst = static_cast<uint8_t>(r);
        p.is64 = is64;
        auto id = ctx.add_node(is_push ? Op::GuestPushR : Op::GuestPop);
        if (id < 0) return false;
        ctx.nodes[id].imm_bits = guest_pack(p);
        if (is_push) {
            ctx.mem_cse_count = 0;  // writes [rsp-slot]: drop all cached loads
            ctx.mem_cse_next = 0;
        } else {
            ctx.guest_written_mask |= static_cast<uint16_t>(1u << r);
            mem_cse_evict_reg(ctx, r);
        }
        ctx.guest_written_mask |= static_cast<uint16_t>(1u << 4);
        mem_cse_evict_reg(ctx, 4);
        return true;
    }

    // Immediate-like push (kinds Immediate and BranchOffset share the value
    // offset — the bridge-demand audit routes `push $imm` as BranchOffset).
    if (!is_push) return false;  // pop m — decline
    if (o.kind == IROperandKind::MemRef || o.kind == IROperandKind::AbsMem)
        return false;  // push m — decline
    if (o.kind == IROperandKind::Immediate && o.imm.mem_flags != 0)
        return false;  // fixup: payload is the relocation target
    GuestPayload p = {};
    p.is64 = (op == kOpcodeName_push);  // 64-bit mode push: 8-byte slot
    p.imm = static_cast<uint32_t>(o.imm.value);
    auto id = ctx.add_node(Op::GuestPushI);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    ctx.mem_cse_count = 0;
    ctx.mem_cse_next = 0;
    ctx.guest_written_mask |= static_cast<uint16_t>(1u << 4);
    mem_cse_evict_reg(ctx, 4);
    return true;
}

// ── Guest flag definers: cmp/test r32/r64 (TRANSPARENT_FLAGS tier) ─────────
//
// Unlike every other Guest* form these DEFINE live guest flags — that is
// their entire architectural effect. The SUBS/ANDS lowering leaves the exact
// NZCV Rosetta's own translation of cmp/test leaves, so downstream readers
// (an in-run FCSel via build_fcmov's relaxed gate, or post-run jcc/setcc)
// see correct guest state. What NZCV cannot carry is gated dead via
// flag_liveness: PF always (no NZCV slot), AF for cmp (cmp defines AF
// architecturally; test leaves it undefined, so no correct reader exists),
// and CF for test (ANDS leaves C=0 where the ¬CF convention wants 1 — see
// the gate below).
//
// Form restrictions: register lhs, register or non-fixup immediate rhs,
// 32/64-bit only (8/16-bit flags come from partial-width results — the
// W-form SUBS/ANDS would put SF/ZF in the wrong bits). Memory forms decline.
static bool build_guest_cmp(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_flags)) return false;
    if (g_rosetta_config->disable_guest_cmp) return false;
    if (instr->num_operands < 2) return false;
    const bool is_test = (op == kOpcodeName_test);
    const uint8_t unmaterialized =
        is_test ? FLAG_PF : static_cast<uint8_t>(FLAG_PF | FLAG_AF);
    if (instr->flag_liveness & unmaterialized) return false;
    // CF convention fix for test: Rosetta's stored guest convention keeps
    // C = ¬CF (SUBS leaves it naturally; its ADDS translations append
    // CFINV). x86 TEST defines CF=0, but ANDS leaves C=0 — the INVERTED
    // convention value. Rosetta's own `tst` leaves the same state and gets
    // away with it by statically resolving every C-reader against the
    // producer; a consumed test hides the producer, so a post-run C-reader
    // (setb/jb) would read inverted carry. When CF is live out of the test,
    // the lowering appends one CFINV (aux bit 5) — C becomes 1 = ¬CF,
    // convention-true. In-run C-readers (fcmovcc, consumed setcc) force the
    // same bit regardless of liveness, which Rosetta computes only for
    // integer consumers.
    const bool cf_fix = is_test && (instr->flag_liveness & FLAG_CF) != 0;

    const IROperand& lhs = instr->operands[0];
    const IROperand& rhs = instr->operands[1];
    if (lhs.kind != IROperandKind::Register || !lhs.reg.reg.is_gpr())
        return false;

    GuestPayload p = {};
    p.dst = lhs.reg.reg.index();
    bool reg_rhs = false;
    uint32_t wclass = 0;  // aux[3:2]: 0 = 32/64 (p.is64), 1 = r16, 2/3 = r8 lo/hi

    if (lhs.reg.size == IROperandSize::S64 ||
        lhs.reg.size == IROperandSize::S32) {
        p.is64 = lhs.reg.size == IROperandSize::S64;
        if (rhs.kind == IROperandKind::Register) {
            if (!rhs.reg.reg.is_gpr() || rhs.reg.size != lhs.reg.size)
                return false;
            p.src = rhs.reg.reg.index();
            reg_rhs = true;
        } else if (rhs.kind == IROperandKind::MemRef ||
                   rhs.kind == IROperandKind::AbsMem) {
            return false;
        } else {
            if (rhs.kind == IROperandKind::Immediate && rhs.imm.mem_flags != 0)
                return false;  // fixup: payload is the relocation target
            p.imm = static_cast<uint32_t>(rhs.imm.value);
        }
    } else if (is_test && rhs.kind != IROperandKind::Register &&
               rhs.kind != IROperandKind::MemRef &&
               rhs.kind != IROperandKind::AbsMem) {
        // Sub-32 TEST with an immediate — the fnstsw idiom's
        // `test ax/ah/al, imm`. Flags come from an ANDS of both operands
        // shifted to the top of the W register (see the lowering), which is
        // flag-exact for the partial width: Z matches, N is the partial
        // result's sign bit, C=V=0 as x86 demands. cmp stays 32/64-only
        // (both operands would need pre-shifting — three instructions).
        if (rhs.kind == IROperandKind::Immediate && rhs.imm.mem_flags != 0)
            return false;
        if (lhs.reg.size == IROperandSize::S16) {
            wclass = 1;
            p.imm = static_cast<uint32_t>(rhs.imm.value) & 0xFFFF;
        } else if (lhs.reg.size == IROperandSize::S8) {
            // Register-byte class nibble: 0x0X = low byte, 0x1X = AH/CH/DH/BH.
            if ((lhs.reg.reg.value & 0xF0) > 0x10) return false;
            wclass = ((lhs.reg.reg.value & 0xF0) == 0x10) ? 3u : 2u;
            p.imm = static_cast<uint32_t>(rhs.imm.value) & 0xFF;
        } else {
            return false;
        }
    } else {
        return false;
    }

    auto id = ctx.add_node(Op::GuestCmpF);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    ctx.nodes[id].aux = (is_test ? 1u : 0u) | (reg_rhs ? 2u : 0u) |
                        (wclass << 2) | (cf_fix ? 0x20u : 0u);
    ctx.last_guest_flagdef = id;
    return true;
}

// ── Guest flag consumer: setcc r8 (TRANSPARENT_FLAGS tier, R3-11) ──────────
//
// Consumes the x86 condition against the in-run GuestCmpF's NZCV — one CSET
// instead of Rosetta's packed materialization, and (for the fnstsw idiom)
// the predicate rides the OPT-PS shortcut straight off the raw FCMP.
//
// The AArch64 condition is resolved against the PRODUCER at build time,
// mirroring how a per-producer static translator resolves flag consumers:
//   cmp  (SUBS — C is the inverted x86 borrow, Rosetta's own convention):
//        full map; p/np decline (parity has no NZCV slot).
//   test (ANDS [+CFINV], V=0 while x86 defines CF=0, OF=0): Z/N/V-based
//        conditions map directly (the tested width's sign bit lands in N via
//        the shifted ANDS forms, and V=0=OF makes the signed ones exact);
//        the C-reading b/ae/be/a map through the convention (C=¬CF=1) and
//        REQUIRE the producer's CFINV bit — build_guest_setcc forces it.
//        The OPT-PS shortcut state (Z=predicate, N=C=V=0, same CFINV
//        treatment) equals the real ANDS state for every supported mask
//        (sign bit outside the mask), so a build-resolved condition stays
//        correct whether or not the shortcut fires at lowering.
static constexpr int8_t kSetccCondCmp[16] = {
    //  o   no   b   ae   e   ne   be   a    s   ns   p   np    l   ge   le   g
        6,   7,  3,   2,  0,   1,   9,  8,   4,   5, -1,  -1,  11,  10,  13, 12};
static constexpr int8_t kSetccCondTest[16] = {
        6,   7,  3,   2,  0,   1,   9,  8,   4,   5, -1,  -1,  11,  10,  13, 12};

static int guest_setcc_cond(uint8_t cc, bool producer_is_test) {
    if (cc >= 16) return -1;
    return producer_is_test ? kSetccCondTest[cc] : kSetccCondCmp[cc];
}

// Form + condition admissibility. Shared with the trailing-tail absorb,
// which must validate the setcc BEFORE consuming its test (a bare absorbed
// test is the measured-regression shape the lookahead note warns about).
static bool guest_setcc_admissible(const IRInstr* instr, bool producer_is_test) {
    if (instr->num_operands < 2) return false;
    const IROperand& c = instr->operands[0];
    const IROperand& d = instr->operands[1];
    if (c.kind != IROperandKind::ConditionCode) return false;
    if (d.kind != IROperandKind::Register || !d.reg.reg.is_gpr()) return false;
    if (d.reg.size != IROperandSize::S8) return false;
    // Register-byte class nibble: 0x0X = low byte, 0x1X = AH/CH/DH/BH.
    if ((d.reg.reg.value & 0xF0) > 0x10) return false;
    return guest_setcc_cond(c.cc.cc, producer_is_test) >= 0;
}

static bool build_guest_setcc(Context& ctx, IRInstr* instr) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_flags)) return false;
    if (g_rosetta_config->disable_guest_setcc) return false;
    // Producer discipline: every node after the GuestCmpF must be another
    // GuestSetcc (setcc chains off one test are common) — CSET writes no
    // flags and nothing else may sit between, so the producer's NZCV is
    // physically current when this one reads it.
    const int fd = ctx.last_guest_flagdef;
    if (fd < 0) return false;
    for (int i = fd + 1; i < ctx.num_nodes; i++)
        if (ctx.nodes[i].op != Op::GuestSetcc) return false;
    const bool producer_is_test = (ctx.nodes[fd].aux & 1) != 0;
    if (!guest_setcc_admissible(instr, producer_is_test)) return false;

    const IROperand& d = instr->operands[1];
    GuestPayload p = {};
    p.dst = d.reg.reg.index();
    p.cls = ((d.reg.reg.value & 0xF0) == 0x10) ? 1 : 0;
    p.imm = static_cast<uint32_t>(
        guest_setcc_cond(instr->operands[0].cc.cc, producer_is_test));
    // C-reading conditions after a test are resolved against the ¬CF
    // convention — force the producer's CFINV regardless of liveness.
    if (producer_is_test && cond_reads_carry(static_cast<int>(p.imm)))
        ctx.nodes[fd].aux |= 0x20u;
    auto id = ctx.add_node(Op::GuestSetcc);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    // The dst register is redefined: cached loads addressed through it now
    // point at a different location, and it may not serve as a cached base.
    ctx.guest_written_mask |= static_cast<uint16_t>(1u << p.dst);
    mem_cse_evict_reg(ctx, p.dst);
    return true;
}

static bool build_guest_int(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_int)) return false;
    // nop consumes nothing; fwait checks pending FP exceptions, which this
    // JIT does not model anywhere — Rosetta itself translates `wait` to
    // nothing at all (translate_insn default case, binary-verified).
    if (op == kOpcodeName_nop || op == kOpcodeName_wait) return true;

    if (instr->num_operands < 2) return false;
    const IROperand& dst = instr->operands[0];
    const IROperand& src = instr->operands[1];

    // ── Memory-destination forms: mov m←r / mov m←i ────────────────────
    if (op == kOpcodeName_mov && (dst.kind == IROperandKind::MemRef ||
                                  dst.kind == IROperandKind::AbsMem)) {
        int16_t id;
        if (src.kind == IROperandKind::Register) {
            if (!src.reg.reg.is_gpr()) return false;
            // High-byte sources (AH/CH/DH/BH, class nibble 0x1X) would need
            // an extra shift — decline; low 8/16/32/64 store the low bits
            // of the guest register directly (no partial-register merge on
            // the register side for stores).
            if ((src.reg.reg.value & 0xF0) == 0x10) return false;
            if (!guest_mem_operand_ok(dst, /*allow64=*/true)) return false;
            id = ctx.add_node(Op::GuestStoreR);
            if (id < 0) return false;
            ctx.nodes[id].aux = src.reg.reg.index();
        } else if (src.kind == IROperandKind::MemRef ||
                   src.kind == IROperandKind::AbsMem) {
            return false;
        } else {
            if (src.kind == IROperandKind::Immediate && src.imm.mem_flags != 0)
                return false;
            // mov m64, imm32 sign-extends — decline 64-bit imm stores.
            if (!guest_mem_operand_ok(dst, /*allow64=*/false)) return false;
            id = ctx.add_node(Op::GuestStoreI);
            if (id < 0) return false;
            ctx.nodes[id].aux = static_cast<uint32_t>(src.imm.value);
        }
        ctx.nodes[id].mem_operand = &instr->operands[0];
        // Memory write: cached loads it may alias are stale.
        mem_cse_evict_may_alias(ctx, &instr->operands[0]);
        // OPT-CF: a 16-bit immediate store is a constant-CW candidate for a
        // following FLDCW of the same operand (MSVC ftol) — record it in the
        // CSE table (evictions keep it honest; the value rides in node aux).
        if (ctx.nodes[id].op == Op::GuestStoreI &&
            guest_mem_size(dst) == IROperandSize::S16)
            mem_cse_insert(ctx, &instr->operands[0], Op::GuestStoreI, id);
        return true;
    }

    if (dst.kind != IROperandKind::Register || !dst.reg.reg.is_gpr()) return false;
    const bool dst64 = dst.reg.size == IROperandSize::S64;
    if (!dst64 && dst.reg.size != IROperandSize::S32) return false;

    // ── Memory-source forms: mov r←m, movzx/movsx r32←m ────────────────
    if ((src.kind == IROperandKind::MemRef || src.kind == IROperandKind::AbsMem) &&
        (op == kOpcodeName_mov || op == kOpcodeName_movzx ||
         op == kOpcodeName_movsx)) {
        // Widths: plain mov loads exactly the dst width (mem size == reg
        // size); movzx/movsx load a narrower mem size into r32. 64-bit
        // loads only for plain mov r64←m64.
        if (!guest_mem_operand_ok(src, /*allow64=*/op == kOpcodeName_mov && dst64))
            return false;
        if (op != kOpcodeName_mov && dst64) return false;
        auto id = ctx.add_node(Op::GuestLoad);
        if (id < 0) return false;
        ctx.nodes[id].mem_operand = &instr->operands[1];
        ctx.nodes[id].aux = static_cast<uint64_t>(dst.reg.reg.index()) |
                            (op == kOpcodeName_movsx ? (1u << 4) : 0);
        ctx.guest_written_mask |= static_cast<uint16_t>(1u << dst.reg.reg.index());
        mem_cse_evict_reg(ctx, dst.reg.reg.index());
        return true;
    }

    GuestPayload p = {};
    p.dst = dst.reg.reg.index();
    p.is64 = dst64;
    Op node_op;

    switch (op) {
        case kOpcodeName_mov: {
            if (src.kind == IROperandKind::Register) {
                if (!src.reg.reg.is_gpr() || src.reg.size != dst.reg.size)
                    return false;
                p.src = src.reg.reg.index();
                node_op = Op::GuestMovRR;
            } else {
                // Immediate-like kinds share the payload offset (verified
                // against Rosetta's IR); kind Immediate may carry a fixup.
                if (src.kind == IROperandKind::Immediate && src.imm.mem_flags != 0)
                    return false;
                if (dst64) return false;
                p.imm = static_cast<uint32_t>(src.imm.value);
                node_op = Op::GuestMovRI;
            }
            break;
        }
        case kOpcodeName_movzx:
        case kOpcodeName_movsx:
        case kOpcodeName_movsxd: {
            if (src.kind != IROperandKind::Register || !src.reg.reg.is_gpr())
                return false;
            p.sign = (op != kOpcodeName_movzx);
            switch (src.reg.size) {
                case IROperandSize::S8:
                    // Register-byte high nibble: 0x0X = low byte, 0x1X = high
                    // byte (AH/CH/DH/BH); anything else is unexpected.
                    if ((src.reg.reg.value & 0xF0) > 0x10) return false;
                    p.cls = ((src.reg.reg.value & 0xF0) == 0x10) ? 1 : 0;
                    break;
                case IROperandSize::S16:
                    p.cls = 2;
                    break;
                case IROperandSize::S32:
                    if (op != kOpcodeName_movsxd) return false;
                    p.cls = 3;
                    break;
                default:
                    return false;
            }
            p.src = src.reg.reg.index();
            node_op = Op::GuestExt;
            break;
        }
        case kOpcodeName_lea: {
            if (src.kind != IROperandKind::MemRef) return false;
            if (src.mem.seg_override != 0) return false;
            const int64_t d = src.mem.disp;
            if (d < INT32_MIN || d > INT32_MAX) return false;
            if (src.mem.shift_amount > 3) return false;
            p.imm = static_cast<uint32_t>(d);
            p.has_base = (src.mem.mem_flags & 1) != 0;
            p.has_index = (src.mem.mem_flags & 2) != 0;
            p.src = src.mem.base_reg & 0xF;
            p.idx = src.mem.index_reg & 0xF;
            p.cls = src.mem.shift_amount;
            p.addr32 = src.mem.addr_size == IROperandSize::S32;
            node_op = Op::GuestLea;
            break;
        }
        default:
            return false;
    }

    auto id = ctx.add_node(node_op);
    if (id < 0) return false;
    ctx.nodes[id].imm_bits = guest_pack(p);
    // The dst register is redefined: cached loads addressed through it now
    // point at a different location, and it may not serve as a cached base.
    ctx.guest_written_mask |= static_cast<uint16_t>(1u << p.dst);
    mem_cse_evict_reg(ctx, p.dst);
    return true;
}

// ── Main build loop ─────────────────────────────────────────────────────────

// ── Scalar-SSE moves (opt-in TRANSPARENT_SSE, OPT-A3) ───────────────────────
//
// movsd/movss between a plain XMM register and memory. Guest xmmN lives in
// host vN permanently (disjoint from the FPR pool; the runtime BLs preserve
// v0-15), so consumption exchanges values by register instead of round-
// tripping through memory: a load whose operand hits mem-CSE becomes one
// FMOV (which zeroes the upper bits exactly like the x86 load form), and a
// store from an xmm with a known value registers the store-forward entry so
// a later fld of the same operand forwards. AVX-class registers (YMM/ZMM)
// decline — Rosetta models their upper halves via flush bookkeeping this
// pipeline doesn't replicate — as does the reg<->reg merge form.

// The size of the memory side of an SSE move (any operand kind).
static IROperandSize sse_mem_size(const IROperand& m) {
    switch (m.kind) {
        case IROperandKind::MemRef: return m.mem.size;
        case IROperandKind::AbsMem: return m.abs_mem.size;
        case IROperandKind::Immediate: return m.imm.size;
        default: return IROperandSize::S8;
    }
}

// Overwriting guest xmm `k` invalidates mem-CSE entries whose value node is
// RESIDENT in that register (an SseLoad that actually loaded — a forwarded
// node lives in a pool FPR and survives).
static void sse_overwrite_xmm(Context& ctx, int k) {
    const int16_t v = ctx.xmm_val[k];
    if (v >= 0 && ctx.nodes[v].op == Op::SseLoad) {
        int kept = 0;
        for (int i = 0; i < ctx.mem_cse_count; i++) {
            if (ctx.mem_cse_val[i] != v) {
                ctx.mem_cse_op[kept] = ctx.mem_cse_op[i];
                ctx.mem_cse_kind[kept] = ctx.mem_cse_kind[i];
                ctx.mem_cse_val[kept] = ctx.mem_cse_val[i];
                kept++;
            }
        }
        ctx.mem_cse_count = static_cast<int8_t>(kept);
        ctx.mem_cse_next = 0;
    }
    ctx.xmm_val[k] = -1;
    ctx.xmm_f32_mask &= static_cast<uint16_t>(~(1u << k));
}

static bool build_sse_mov(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_sse)) return false;
    if (instr->num_operands < 2) return false;
    const bool is_f32 = (op == kOpcodeName_movss);
    IROperand& dst = instr->operands[0];
    IROperand& src = instr->operands[1];
    const IROperandSize want = is_f32 ? IROperandSize::S32 : IROperandSize::S64;
    const Op load_kind = is_f32 ? Op::LoadF32Raw : Op::LoadF64;

    if (dst.kind == IROperandKind::Register &&
        src.kind != IROperandKind::Register) {
        // ── Load form: xmm = [mem], zeroing the upper bits ──────────────
        if (!dst.reg.reg.is_xmm()) return false;
        if (src.kind == IROperandKind::MemRef && src.mem.seg_override != 0)
            return false;
        if (sse_mem_size(src) != want) return false;
        const int xmm = dst.reg.reg.index();

        int16_t fwd = -1;
        const int16_t hit = mem_cse_lookup(ctx, &src, load_kind);
        if (hit >= 0) {
            // f32 entries hold the WIDENED f64 view by convention — take the
            // raw input back out; anything else falls back to the load.
            if (!is_f32)
                fwd = hit;
            else if (ctx.nodes[hit].op == Op::CvtF32ToF64)
                fwd = ctx.nodes[hit].inputs[0];
        }
        const int16_t id = ctx.add_node(Op::SseLoad, fwd);
        if (id < 0) return false;
        ctx.nodes[id].mem_operand = &src;
        ctx.nodes[id].aux = static_cast<uint32_t>(xmm) | (is_f32 ? 0x10u : 0u);
        sse_overwrite_xmm(ctx, xmm);
        if (fwd >= 0) {
            ctx.xmm_val[xmm] = fwd;
        } else {
            // The loaded value is xmm-resident; let later loads of the same
            // operand (fld included) forward from the register. f32 entries
            // store the widened view (DSE reaps the widen if never used).
            ctx.xmm_val[xmm] = id;
            if (!is_f32) {
                mem_cse_insert(ctx, &src, Op::LoadF64, id);
            } else {
                const int16_t w = ctx.add_node(Op::CvtF32ToF64, id);
                if (w >= 0) mem_cse_insert(ctx, &src, Op::LoadF32Raw, w);
            }
        }
        if (is_f32) ctx.xmm_f32_mask |= static_cast<uint16_t>(1u << xmm);
        return true;
    }

    if (src.kind == IROperandKind::Register &&
        dst.kind != IROperandKind::Register) {
        // ── Store form: [mem] = xmm low bits ────────────────────────────
        if (!src.reg.reg.is_xmm()) return false;
        if (dst.kind == IROperandKind::MemRef && dst.mem.seg_override != 0)
            return false;
        if (sse_mem_size(dst) != want) return false;
        const int xmm = src.reg.reg.index();

        const int16_t id = ctx.add_node(Op::SseStore);
        if (id < 0) return false;
        ctx.nodes[id].mem_operand = &dst;
        ctx.nodes[id].aux = static_cast<uint32_t>(xmm) | (is_f32 ? 0x10u : 0u);
        mem_cse_evict_may_alias(ctx, &dst);
        // Store-forward: when the xmm's current low bits are a known node of
        // the matching width, a later load of this operand forwards to it.
        const int16_t v = ctx.xmm_val[xmm];
        const bool vf32 = (ctx.xmm_f32_mask >> xmm) & 1;
        if (v >= 0 && vf32 == is_f32) {
            if (!is_f32) {
                mem_cse_insert(ctx, &dst, Op::LoadF64, v);
            } else {
                const int16_t w = ctx.add_node(Op::CvtF32ToF64, v);
                if (w >= 0) mem_cse_insert(ctx, &dst, Op::LoadF32Raw, w);
            }
        }
        return true;
    }

    return false;  // reg<->reg merge form (or malformed) — not consumed
}

bool build(Context& ctx, IRInstr* instr_array, int64_t num_instrs, int64_t start_idx,
           int run_length, const int8_t* perm, bool const_promote) {
    ctx.init();
    ctx.const_promote = const_promote ? 1 : 0;

    // Fold a carried-in deferred-FXCH permutation: logical depth d initially
    // lives at physical depth perm[d].  Swapped slots are force-resolved so
    // the epilogue materializes the permutation (the caller resets the perm
    // to identity after lowering).
    if (perm) {
        for (int d = 0; d < 8; d++)
            ctx.slot_val[d] = static_cast<int16_t>(-(perm[d] + 1));
        for (int d = 0; d < 8; d++) {
            if (perm[d] != d && ctx.resolve(d) < 0)
                return false;
        }
    }

    for (int i = 0; i < run_length && (start_idx + i) < num_instrs; i++) {
        auto* instr = &instr_array[start_idx + i];
        const auto op = instr->opcode();
        bool ok = true;

        switch (op) {
            // ── Loads / pushes ──────────────────────────────────────────
            case kOpcodeName_fldz: {
                auto id = ctx.const_zero_node;
                if (id < 0) {
                    id = ctx.add_node(Op::ConstZero);
                    if (id < 0) { ok = false; break; }
                    ctx.const_zero_node = id;
                }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fld1: {
                auto id = ctx.const_one_node;
                if (id < 0) {
                    id = ctx.add_node(Op::ConstOne);
                    if (id < 0) { ok = false; break; }
                    ctx.const_one_node = id;
                }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fldl2e: {
                auto id = build_const(ctx, 0x3FF71547652B82FEULL);
                if (id < 0) { ok = false; break; }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fldl2t: {
                auto id = build_const(ctx, 0x400A934F0979A371ULL);
                if (id < 0) { ok = false; break; }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fldlg2: {
                auto id = build_const(ctx, 0x3FD34413509F79FFULL);
                if (id < 0) { ok = false; break; }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fldln2: {
                auto id = build_const(ctx, 0x3FE62E42FEFA39EFULL);
                if (id < 0) { ok = false; break; }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fldpi: {
                auto id = build_const(ctx, 0x400921FB54442D18ULL);
                if (id < 0) { ok = false; break; }
                ctx.push(id);
                break;
            }
            case kOpcodeName_fld: {
                if (instr->operands[0].kind == IROperandKind::Register) {
                    int depth = instr->operands[1].reg.reg.index();
                    auto val = ctx.resolve(depth);
                    if (val < 0) { ok = false; break; }
                    ctx.push(val);
                } else {
                    auto val = build_fp_load(ctx, &instr->operands[0]);
                    if (val < 0) { ok = false; break; }
                    ctx.push(val);
                }
                break;
            }
            case kOpcodeName_fild: {
                auto val = build_int_load(ctx, &instr->operands[0]);
                if (val < 0) { ok = false; break; }
                ctx.push(val);
                break;
            }

            // ── Stores ──────────────────────────────────────────────────
            case kOpcodeName_fst:
            case kOpcodeName_fst_stack:
            case kOpcodeName_fstp:
            case kOpcodeName_fstp_stack: {
                bool is_pop = (op == kOpcodeName_fstp || op == kOpcodeName_fstp_stack);
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }

                if (instr->operands[0].kind == IROperandKind::Register) {
                    // Register path: copy ST(0) → ST(i)
                    int dst_depth = instr->operands[0].reg.reg.index();
                    if (dst_depth != 0)
                        ctx.slot_val[dst_depth] = st0;
                } else {
                    // Memory path
                    if (!build_fp_store(ctx, &instr->operands[0], st0)) {
                        ok = false; break;
                    }
                }
                if (is_pop) ctx.pop();
                break;
            }

            // ── Integer stores ──────────────────────────────────────────
            case kOpcodeName_fistp:
            case kOpcodeName_fist:
            case kOpcodeName_fisttp: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                if (!build_int_store(ctx, &instr->operands[0], st0,
                                     op == kOpcodeName_fisttp)) {
                    ok = false; break;
                }
                if (op != kOpcodeName_fist) ctx.pop();
                break;
            }

            // ── Non-popping arithmetic ──────────────────────────────────
            case kOpcodeName_fadd:
                ok = build_arith(ctx, instr, Op::FAdd, false);
                break;
            case kOpcodeName_fsub:
                ok = build_arith(ctx, instr, Op::FSub, false);
                break;
            case kOpcodeName_fsubr:
                ok = build_arith(ctx, instr, Op::FSub, true);
                break;
            case kOpcodeName_fmul:
                ok = build_arith(ctx, instr, Op::FMul, false);
                break;
            case kOpcodeName_fdiv:
                ok = build_arith(ctx, instr, Op::FDiv, false);
                break;
            case kOpcodeName_fdivr:
                ok = build_arith(ctx, instr, Op::FDiv, true);
                break;

            // ── Integer arithmetic (memory-only, ST(0) op= mem) ────────
            case kOpcodeName_fiadd:
            case kOpcodeName_fisub:
            case kOpcodeName_fisubr:
            case kOpcodeName_fimul:
            case kOpcodeName_fidiv:
            case kOpcodeName_fidivr: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto mem_val = build_int_load(ctx, &instr->operands[0]);
                if (mem_val < 0) { ok = false; break; }
                Op arith_op;
                bool reversed;
                switch (op) {
                    case kOpcodeName_fiadd:  arith_op = Op::FAdd; reversed = false; break;
                    case kOpcodeName_fisub:  arith_op = Op::FSub; reversed = false; break;
                    case kOpcodeName_fisubr: arith_op = Op::FSub; reversed = true;  break;
                    case kOpcodeName_fimul:  arith_op = Op::FMul; reversed = false; break;
                    case kOpcodeName_fidiv:  arith_op = Op::FDiv; reversed = false; break;
                    case kOpcodeName_fidivr: arith_op = Op::FDiv; reversed = true;  break;
                    default: __builtin_unreachable();
                }
                auto id = reversed
                    ? ctx.add_node(arith_op, mem_val, st0)
                    : ctx.add_node(arith_op, st0, mem_val);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }

            // ── Popping arithmetic ──────────────────────────────────────
            case kOpcodeName_faddp:
                ok = build_arithp(ctx, instr, Op::FAdd, false);
                break;
            case kOpcodeName_fsubp:
                ok = build_arithp(ctx, instr, Op::FSub, false);
                break;
            case kOpcodeName_fsubrp:
                ok = build_arithp(ctx, instr, Op::FSub, true);
                break;
            case kOpcodeName_fmulp:
                ok = build_arithp(ctx, instr, Op::FMul, false);
                break;
            case kOpcodeName_fdivp:
                ok = build_arithp(ctx, instr, Op::FDiv, false);
                break;
            case kOpcodeName_fdivrp:
                ok = build_arithp(ctx, instr, Op::FDiv, true);
                break;

            // ── Unary ───────────────────────────────────────────────────
            case kOpcodeName_fchs: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                // Double negation: reuse the FNeg's input directly (exact,
                // incl. NaN sign). DSE reaps the orphan FNeg if unused.
                if (ctx.nodes[st0].op == Op::FNeg) {
                    ctx.slot_val[0] = ctx.nodes[st0].inputs[0];
                    break;
                }
                auto id = ctx.add_node(Op::FNeg, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fabs: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FAbs, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fsqrt: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FSqrt, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fcos: {
                // OPT-TI value call. Only a member when the predicate holds
                // (lookahead applies the same gate; this is belt-and-braces
                // for direct build() callers).
                if (!(g_rosetta_config && trig_ir_fcos_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FCosCall, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fsin: {
                if (!(g_rosetta_config && trig_ir_fsin_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FSinCall, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fptan: {
                // OPT-TI value call yielding the tangent; the architectural
                // push of 1.0 is a plain ConstOne node — the IR epilogue
                // handles TOP and tags exactly as for fld1.
                if (!(g_rosetta_config && trig_ir_fptan_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                // All failable allocations BEFORE any semantic mutation: a
                // failure after slot_val/push would leave a half-applied
                // fptan in a run that then lowers without consuming it.  (A
                // stray ConstOne on the failure path is pure and DSE-able.)
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto one = ctx.const_one_node;
                if (one < 0) {
                    one = ctx.add_node(Op::ConstOne);
                    if (one < 0) { ok = false; break; }
                    ctx.const_one_node = one;
                }
                auto id = ctx.add_node(Op::FPtanCall, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                ctx.push(one);
                break;
            }
            case kOpcodeName_fsincos: {
                // OPT-TI Phase C, option (a): ONE value call returning both
                // results (d16=sin, d17=cos) plus a projection node for the
                // cosine — the two-call decomposition (option b) measured
                // fully serialized, ~2x a single call.  ST(0) becomes the
                // sine, the cosine is pushed.  The projection is added
                // IMMEDIATELY after the call (lowering adjacency contract).
                // All failable add_node calls before any slot_val/push
                // mutation (fptan's rule); stray nodes on the failure path
                // are pure and DSE-able.
                if (!(g_rosetta_config && trig_ir_fsincos_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto call = ctx.add_node(Op::FSinCosCall, st0);
                if (call < 0) { ok = false; break; }
                auto proj = ctx.add_node(Op::FSinCosProjCos, call);
                if (proj < 0) { ok = false; break; }
                ctx.slot_val[0] = call;
                ctx.push(proj);
                break;
            }
            case kOpcodeName_f2xm1: {
                // OPT-TI pow-trio value call: ST(0) = 2^ST(0) - 1, no
                // status-word effect (the classic helper touches none).
                if (!(g_rosetta_config && trig_ir_f2xm1_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::F2XM1Call, st0);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fscale: {
                // OPT-TI pow-trio value call: ST(0) = fscale(ST(0), ST(1));
                // ST(1) is read but unchanged, no push/pop.
                if (!(g_rosetta_config && trig_ir_fscale_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto st1 = ctx.resolve(1);
                if (st1 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FScaleCall, st0, st1);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[0] = id;
                break;
            }
            case kOpcodeName_fyl2x:
            case kOpcodeName_fyl2xp1: {
                // OPT-TI pow-trio completion value calls:
                // ST(1) = ST(1) * log2(ST(0) [+ 1]), pop.  All failable
                // add_node calls happen before the slot_val/pop mutations.
                const bool p1 = (op == kOpcodeName_fyl2xp1);
                if (!(g_rosetta_config &&
                      (p1 ? trig_ir_fyl2xp1_enabled(*g_rosetta_config)
                          : trig_ir_fyl2x_enabled(*g_rosetta_config)))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto st1 = ctx.resolve(1);
                if (st1 < 0) { ok = false; break; }
                auto id = ctx.add_node(p1 ? Op::FYl2xp1Call : Op::FYl2xCall, st0, st1);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[1] = id;
                ctx.pop();
                break;
            }
            case kOpcodeName_fpatan: {
                // Value call: ST(1) = atan2(ST(1), ST(0)), pop.
                if (!(g_rosetta_config && trig_ir_fpatan_enabled(*g_rosetta_config))) {
                    ok = false;
                    break;
                }
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto st1 = ctx.resolve(1);
                if (st1 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FPatanCall, st0, st1);
                if (id < 0) { ok = false; break; }
                ctx.slot_val[1] = id;
                ctx.pop();
                break;
            }
            case kOpcodeName_frndint: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FRndInt, st0);
                if (id < 0) { ok = false; break; }
                if (ctx.known_rc >= 0)  // OPT-CF: single static FRINT
                    ctx.nodes[id].aux =
                        0x100u | static_cast<uint32_t>(ctx.known_rc);
                ctx.slot_val[0] = id;
                break;
            }

            // ── FXCH — compile-time swap ────────────────────────────────
            case kOpcodeName_fxch: {
                // Rosetta encodes FXCH as [ST(0), ST(i)] — target depth is operands[1].
                int depth = instr->operands[1].reg.reg.index();
                if (depth <= 0 || depth >= 8) { ok = false; break; }
                // Force-resolve both slots so the epilogue can track the swap.
                // Without this, two unresolved initial slots (val < 0) would be
                // swapped symbolically but the epilogue would skip both stores.
                ctx.resolve(0);
                ctx.resolve(depth);
                auto tmp = ctx.slot_val[0];
                ctx.slot_val[0] = ctx.slot_val[depth];
                ctx.slot_val[depth] = tmp;
                break;
            }

            // ── Compare ─────────────────────────────────────────────────
            case kOpcodeName_fcom:
            case kOpcodeName_fucom:
                ok = build_fcom(ctx, instr, 0, false);
                break;
            case kOpcodeName_fcomp:
            case kOpcodeName_fucomp:
                ok = build_fcom(ctx, instr, 1, false);
                break;
            case kOpcodeName_fcompp:
            case kOpcodeName_fucompp:
                ok = build_fcom(ctx, instr, 2, true);
                break;

            case kOpcodeName_ficom:
                ok = build_ficom(ctx, instr, false);
                break;
            case kOpcodeName_ficomp:
                ok = build_ficom(ctx, instr, true);
                break;

            case kOpcodeName_fcomi:
            case kOpcodeName_fucomi:
                ok = build_fcomi(ctx, instr, false);
                break;
            case kOpcodeName_fcomip:
            case kOpcodeName_fucomip:
                ok = build_fcomi(ctx, instr, true);
                break;

            // ── FCMOV ──────────────────────────────────────────────────
            case kOpcodeName_fcmovb:
                ok = build_fcmov(ctx, instr, 3);   // CC
                break;
            case kOpcodeName_fcmovbe:
                ok = build_fcmov(ctx, instr, 9);   // LS
                break;
            case kOpcodeName_fcmove:
                ok = build_fcmov(ctx, instr, 0);   // EQ
                break;
            case kOpcodeName_fcmovnb:
                ok = build_fcmov(ctx, instr, 2);   // CS
                break;
            case kOpcodeName_fcmovnbe:
                ok = build_fcmov(ctx, instr, 8);   // HI
                break;
            case kOpcodeName_fcmovne:
                ok = build_fcmov(ctx, instr, 1);   // NE
                break;
            case kOpcodeName_fcmovu:
                ok = build_fcmov(ctx, instr, 6);   // VS
                break;
            case kOpcodeName_fcmovnu:
                ok = build_fcmov(ctx, instr, 7);   // VC
                break;

            case kOpcodeName_ftst: {
                auto st0 = ctx.resolve(0);
                if (st0 < 0) { ok = false; break; }
                auto id = ctx.add_node(Op::FTst, st0);
                if (id < 0) { ok = false; break; }
                ctx.last_fcmp = id;
                break;
            }

            // ── FSTSW AX ───────────────────────────────────────────────
            case kOpcodeName_fstsw: {
                // Bail on memory form (extremely rare); only handle FSTSW AX.
                if (instr->operands[0].kind != IROperandKind::Register) {
                    ok = false; break;
                }
                auto id = ctx.add_node(Op::FStsw);
                if (id < 0) { ok = false; break; }
                // inputs[0] = prior FCmp/FTst node (for fusion detection).
                // The register index and top_delta snapshot are metadata, not
                // node references — they live in aux (see Node), or the
                // optimizer's input-rewrite/use-count loops would treat them
                // as uses of nodes 0..2 (and fold_to could rewrite them).
                ctx.nodes[id].inputs[0] = ctx.last_fcmp;
                ctx.nodes[id].aux =
                    static_cast<uint64_t>(instr->operands[0].reg.reg.index()) |
                    (static_cast<uint64_t>(
                         static_cast<uint16_t>(ctx.top_delta)) << 16);
                // The AX write may change a cached operand's address — evict
                // only entries whose address uses RAX/EAX as base/index;
                // entries through other registers (and AbsMem) stay valid.
                mem_cse_evict_reg(ctx, 0);
                break;
            }

            // ── Control word ────────────────────────────────────────────
            case kOpcodeName_fldcw: {
                // Load u16 from mem, write to X87State.control_word.
                auto id = ctx.add_node(Op::StoreCW);
                if (id < 0) { ok = false; break; }
                ctx.nodes[id].mem_operand = &instr->operands[0];
                // OPT-CF: when the operand provably holds an in-run immediate
                // store's value (MSVC ftol: `mov m16,#CW; fldcw m16`), the
                // control word — and so RC — is a translate-time constant
                // until the next unknown FLDCW. aux bit16 flags it; the CW
                // value rides in aux[15:0] (lowering skips the guest LDRH).
                const int16_t src =
                    mem_cse_lookup(ctx, &instr->operands[0], Op::GuestStoreI);
                if (src >= 0) {
                    const uint32_t cw =
                        static_cast<uint32_t>(ctx.nodes[src].aux) & 0xFFFFu;
                    ctx.nodes[id].aux = 0x10000u | cw;
                    ctx.known_rc = static_cast<int8_t>((cw >> 10) & 3);
                } else {
                    ctx.known_rc = -1;
                }
                break;
            }
            case kOpcodeName_fnstcw: {
                // Read X87State.control_word, store u16 to mem.
                auto id = ctx.add_node(Op::LoadCW);
                if (id < 0) { ok = false; break; }
                ctx.nodes[id].mem_operand = &instr->operands[0];
                // Writes guest memory — evict may-aliasing cached loads.
                mem_cse_evict_may_alias(ctx, &instr->operands[0]);
                break;
            }

            // ── FNOP ────────────────────────────────────────────────────
            case kOpcodeName_fnop:
                // No operation; just let the run continue.
                break;

            // ── Run-transparent guest integer instructions (opt-in) ─────
            case kOpcodeName_mov:
            case kOpcodeName_movzx:
            case kOpcodeName_movsx:
            case kOpcodeName_movsxd:
            case kOpcodeName_lea:
            case kOpcodeName_nop:
            case kOpcodeName_wait:
                ok = build_guest_int(ctx, instr, op);
                break;

            // ── Scalar-SSE moves (opt-in TRANSPARENT_SSE, OPT-A3) ───────
            case kOpcodeName_movsd:
            case kOpcodeName_movss:
                ok = build_sse_mov(ctx, instr, op);
                break;

            // ── Flag-writing ALU forms (opt-in TRANSPARENT_FLAGS) ───────
            case kOpcodeName_add:
            case kOpcodeName_sub:
            case kOpcodeName_and:
            case kOpcodeName_or:
            case kOpcodeName_xor:
            case kOpcodeName_shl:
            case kOpcodeName_shr:
            case kOpcodeName_sar:
                ok = build_guest_alu(ctx, instr, op);
                break;

            // ── Unary ALU forms (inc/dec/neg: FLAGS tier; not: INT tier) ─
            case kOpcodeName_inc:
            case kOpcodeName_dec:
            case kOpcodeName_neg:
            case kOpcodeName_not:
                ok = build_guest_unary(ctx, instr, op);
                break;

            // ── Guest flag definers: cmp/test (FLAGS tier) ──────────────
            case kOpcodeName_cmp:
            case kOpcodeName_test:
                ok = build_guest_cmp(ctx, instr, op);
                break;

            // ── Guest flag consumer: setcc r8 (FLAGS tier, R3-11) ───────
            case kOpcodeName_setcc:
                ok = build_guest_setcc(ctx, instr);
                break;

            // ── push/pop (opt-in TRANSPARENT_PUSHPOP) ───────────────────
            case kOpcodeName_push:
            case kOpcodeName_pushd:
            case kOpcodeName_pop:
            case kOpcodeName_popd:
                ok = build_guest_pushpop(ctx, instr, op);
                break;

            // ── Bail on everything else ─────────────────────────────────
            default:
                ok = false;
                break;
        }

        if (!ok) break;
        ctx.consumed = static_cast<int16_t>(i + 1);
    }

    // OPT-A3: absorb TRAILING scalar-SSE moves. The canonical seam idiom
    // (`fstp m; movsd xmm, m` / `movsd m2, xmm`) trails the last x87 member,
    // where lookahead never counts a gap — a run always ends on an x87
    // member from the WINDOW's perspective. Consuming them here keeps that
    // contract intact (the window bookkeeping is untouched; the extra
    // instructions are IR-internal and only extend ctx.consumed), and the
    // decline path is unchanged: if the run itself failed to build, nothing
    // is absorbed.
    const bool run_complete = ctx.consumed == run_length;
    if (run_complete) {
        constexpr int kMaxTrailingSse = 4;
        for (int t = 0; t < kMaxTrailingSse; t++) {
            const int64_t idx = start_idx + ctx.consumed;
            if (idx >= num_instrs) break;
            auto* tail = &instr_array[idx];
            const auto top = tail->opcode();
            if (top != kOpcodeName_movsd && top != kOpcodeName_movss) break;
            if (!build_sse_mov(ctx, tail, top)) break;
            ctx.consumed++;
        }
    }

    // R3-11: absorb a TRAILING `test/cmp; setcc [; movzx]` compare tail.
    // X87Cache::lookahead never counts a trailing cmp/test, and consuming
    // the test ALONE was measured a regression (duplicated into both dual
    // bodies for zero structural gain — see the lookahead note). A setcc
    // consumer flips the economics: the predicate resolves as one CSET off
    // the producer's NZCV instead of Rosetta's packed-AX materialization
    // (mov+tst+cset+bfxil+uxtb+bfxil), and for the fnstsw idiom the OPT-PS
    // shortcut drops the whole pack→AX→TST dependency from the critical
    // path. So the tail is absorbed only when BOTH halves consume — the
    // setcc is validated before the test is touched.
    if (run_complete &&
        !(g_rosetta_config && g_rosetta_config->disable_guest_setcc)) {
        const int64_t ti = start_idx + ctx.consumed;
        if (ti + 1 < num_instrs) {
            auto* tcmp = &instr_array[ti];
            auto* tset = &instr_array[ti + 1];
            const auto tcop = tcmp->opcode();
            if ((tcop == kOpcodeName_test || tcop == kOpcodeName_cmp) &&
                tset->opcode() == kOpcodeName_setcc &&
                guest_setcc_admissible(tset, tcop == kOpcodeName_test) &&
                build_guest_cmp(ctx, tcmp, tcop)) {
                ctx.consumed++;
                if (build_guest_setcc(ctx, tset)) {
                    const int16_t sid =
                        static_cast<int16_t>(ctx.num_nodes - 1);
                    ctx.consumed++;
                    // Fold a same-register widening (`setz al;
                    // movzx {ax,eax,rax}, al`) into the setcc write: the
                    // CSET value is already zero-extended, so the movzx is
                    // one width field, not a uxtb+bfxil pair.
                    const int64_t mi = start_idx + ctx.consumed;
                    GuestPayload sp = guest_unpack(ctx.nodes[sid].imm_bits);
                    if (mi < num_instrs && sp.cls == 0) {
                        auto* mext = &instr_array[mi];
                        if (mext->opcode() == kOpcodeName_movzx &&
                            mext->num_operands >= 2) {
                            const IROperand& md = mext->operands[0];
                            const IROperand& ms = mext->operands[1];
                            if (md.kind == IROperandKind::Register &&
                                ms.kind == IROperandKind::Register &&
                                md.reg.reg.is_gpr() && ms.reg.reg.is_gpr() &&
                                ms.reg.size == IROperandSize::S8 &&
                                (ms.reg.reg.value & 0xF0) == 0 &&
                                ms.reg.reg.index() == sp.dst &&
                                md.reg.reg.index() == sp.dst &&
                                (md.reg.size == IROperandSize::S16 ||
                                 md.reg.size == IROperandSize::S32 ||
                                 md.reg.size == IROperandSize::S64)) {
                                sp.cls = (md.reg.size == IROperandSize::S16)
                                             ? 2 : 3;
                                ctx.nodes[sid].imm_bits = guest_pack(sp);
                                ctx.consumed++;
                            }
                        }
                    }
                }
            }
        }
    }

    // Only worthwhile if we consumed 2+ instructions — except when the caller
    // deliberately asked for a single (OPT-SEAM: a 1-instruction run at a
    // seam folds/defers TOP+tag state the legacy path would flush).
    return ctx.consumed >= (run_length == 1 ? 1 : 2);
}

}  // namespace X87IR
