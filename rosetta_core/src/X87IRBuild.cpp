#include "rosetta_core/X87IR.h"

#include <cstring>

#include "rosetta_config/Config.h"
#include "rosetta_core/CoreConfig.h"
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
    if (op->kind != IROperandKind::MemRef && op->kind != IROperandKind::AbsMem)
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
    if (truncate) ctx.nodes[id].flags |= kTruncate;
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

static bool build_fcmov(Context& ctx, IRInstr* instr, int aarch64_cond) {
    // Safety: FCMOV reads NZCV set by a prior FCOMI. If no FComI
    // was built in this run, we cannot guarantee NZCV state → bail.
    if (ctx.last_fcomi < 0) return false;

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
// with the xor r,r zero idiom, gated on Rosetta's flag-liveness analysis
// proving the written flags dead (see the xor block in build_guest_int).

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

static bool build_guest_int(Context& ctx, IRInstr* instr, uint16_t op) {
    if (!(g_rosetta_config && g_rosetta_config->transparent_int)) return false;
    // nop consumes nothing; fwait checks pending FP exceptions, which this
    // JIT does not model anywhere — Rosetta itself translates `wait` to
    // nothing at all (translate_insn default case, binary-verified).
    if (op == kOpcodeName_nop || op == kOpcodeName_wait) return true;

    if (instr->num_operands < 2) return false;
    const IROperand& dst = instr->operands[0];
    const IROperand& src = instr->operands[1];

    // ── xor r,r zero idiom (opt-in TRANSPARENT_FLAGS) ──────────────────
    // xor defines all six arithmetic flags, so it is only transparent when
    // Rosetta's backward flag-liveness analysis proves its flag results
    // dead: flag_liveness holds the flags live OUT of this instruction
    // (block-fixpoint, conservative all-live at unknown targets), so 0
    // means nothing the xor writes is ever read.  Lowered as the existing
    // GuestMovRI 0 — a plain MOVZ Wd, #0: flag-free on the host (the
    // Guest-node NZCV contract is unchanged), and the W-write zero-extends,
    // covering the r64 form.  Non-self forms and 8/16-bit destinations
    // (partial-register merge) decline as usual.
    if (op == kOpcodeName_xor) {
        if (!g_rosetta_config->transparent_flags) return false;
        if (instr->flag_liveness != 0) return false;
        if (dst.kind != IROperandKind::Register || !dst.reg.reg.is_gpr() ||
            src.kind != IROperandKind::Register || !src.reg.reg.is_gpr())
            return false;
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
            case kOpcodeName_xor:
                ok = build_guest_int(ctx, instr, op);
                break;

            // ── Bail on everything else ─────────────────────────────────
            default:
                ok = false;
                break;
        }

        if (!ok) break;
        ctx.consumed = static_cast<int16_t>(i + 1);
    }

    return ctx.consumed >= 2;  // only worthwhile if we consumed 2+ instructions
}

}  // namespace X87IR
