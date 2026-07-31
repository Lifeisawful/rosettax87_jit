#include "rosetta_core/X87BackEdge.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/IRBlock.h"
#include "rosetta_core/Register.h"
#include "rosetta_core/TranslationResult.h"
#include <rosetta_config/Config.h>

static inline bool backedge_enabled(const RosettaConfig* cfg) {
    return cfg && !cfg->disable_backedge;
}

static inline bool is_self_loop_block(const IRBlock* block) {
    const IRTerminator& t = block->terminator;
    return t.kind == TK_JCC && t.data.target.block.kind == BasicBlock &&
           t.data.target.block.block == block;
}

// ── OPT-BE stage 0 spike ────────────────────────────────────────────────────
// Goal: prove the post-block patch point (design_b_2026-07-31.md §4.0).
//   G0.1  the hook fires for every translation (log counter, both paths)
//   G0.2  the emitted buffer is writable here and a same-value rewrite of
//         branch words is a byte-identical no-op (BACKEDGE_NOOP_PROBE)
//   G0.3  backward conditional branches (the back-edge form) are present and
//         decodable at this point — logged per module, with the resolved/
//         placeholder distinction that separates JIT mode (internal fixups
//         committed inside translate_block) from AOT mode (applied later on
//         the published copy).
//
// The scan reads through a volatile pointer: this TU is built with
// -fvectorize in the runtime configuration, and translation-time code must
// never emit NEON (live guest FP state) — volatile keeps every access scalar.

static uint64_t g_backedge_module_count = 0;

// ── Stage 1: per-module block records ───────────────────────────────────────
// Filled by x87_backedge_note_block (translation is serialized under the
// runtime's heap/translation locks — same assumption as the existing global
// X87Cache state). Owner-keyed so a module that never reaches the post-pass
// (error path) can't leak stale records into the next module's analysis.

namespace {

struct BlockRec {
    uint32_t arm_off;   // insn_buf.end when the block's first insn translates
    uint32_t start_pc;  // guest pc of the block head
    uint8_t self_loop;  // terminator is JCC targeting this block
};

constexpr uint32_t kMaxBlockRecs = 8192;

}  // namespace

static TranslationResult* g_rec_owner = nullptr;
static BlockRec g_block_recs[kMaxBlockRecs];
static uint32_t g_num_block_recs = 0;
static bool g_block_recs_overflow = false;

void x87_backedge_note_block(TranslationResult* result, IRBlock* block) {
    const RosettaConfig* cfg = g_rosetta_config;
    if (!cfg || (!cfg->log_backedge && !backedge_enabled(cfg)))
        return;
    if (result != g_rec_owner) {
        g_rec_owner = result;
        g_num_block_recs = 0;
        g_block_recs_overflow = false;
    }
    if (g_num_block_recs >= kMaxBlockRecs) {
        g_block_recs_overflow = true;
        return;
    }
    g_block_recs[g_num_block_recs++] = {
        (uint32_t)result->insn_buf.end, block->start_pc,
        (uint8_t)(is_self_loop_block(block) ? 1 : 0)};
}

namespace {

struct BranchScan {
    uint64_t backward_cond = 0;  // B.cond / CBZ / CBNZ with negative offset
    uint64_t zero_off_cond = 0;  // same forms with offset 0 (unresolved placeholder)
};

// B.cond (0101_0100 imm19 0 cond) and CBZ/CBNZ (x011_010x imm19 Rt).
// TBZ/TBNZ (imm14) deliberately excluded — different field, not the
// self-loop terminator form Rosetta emits for these shapes.
bool is_cond_branch(uint32_t insn) {
    if ((insn & 0xFF000010u) == 0x54000000u)
        return true;
    if ((insn & 0x7E000000u) == 0x34000000u)
        return true;
    return false;
}

int32_t cond_branch_offset_words(uint32_t insn) {
    // imm19 at bits [23:5], sign-extended, in words.
    int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
    if (imm19 & 0x40000)
        imm19 -= 0x80000;
    return imm19;
}

// ── Stage 1: self-loop candidate analysis, entirely by decode ───────────────
//
// The load-skip transform (retarget the back edge past the priming st[] load)
// is sound iff, at the moment the back edge is taken:
//   (a) every register the SKIPPED region defines would be recomputed to the
//       value it already holds — guaranteed when each skipped word computes
//       deterministically from x18, X87State memory, or earlier region defs
//       (all loop-invariant here: no state store survives the checks below),
//       AND no body/gap word writes a region-defined GPR;
//   (b) the pinned FPR equals mem[slot] — guaranteed by store-through: the
//       body's single st[] store writes that FPR to the SAME address the
//       skipped load reads (same base reg, same key reg, key unmodified),
//       and nothing writes the FPR after that store.
// Everything is checked against the actual emitted words with default-deny:
// any unrecognized instruction, extra branch, BL, or state-word store
// declines the block. A decline costs nothing (stock code).

inline int rd_of(uint32_t w) { return (int)(w & 31); }
inline int rn_of(uint32_t w) { return (int)((w >> 5) & 31); }
inline int rm_of(uint32_t w) { return (int)((w >> 16) & 31); }

// ADD Xd, Xn, #imm12 (64-bit, shift 0)
inline bool is_add_x_imm(uint32_t w) { return (w & 0xFFC00000u) == 0x91000000u; }
// LDRH Wt, [Xn, #imm12*2]
inline bool is_ldrh_imm(uint32_t w) { return (w & 0xFFC00000u) == 0x79400000u; }
// STRH Wt, [Xn, #imm12*2]
inline bool is_strh_imm(uint32_t w) { return (w & 0xFFC00000u) == 0x79000000u; }
// UBFM/alias (ubfx / lsl-imm / lsr-imm, 32-bit)
inline bool is_ubfm_w(uint32_t w) { return (w & 0xFFC00000u) == 0x53000000u; }
// ORR Wd, Wn, Wm (shifted-register, includes MOV Wd,Wm)
inline bool is_orr_w_reg(uint32_t w) { return (w & 0xFF200000u) == 0x2A000000u; }
// ADD/SUB Wd, Wn, #imm12 (32-bit, no flags)
inline bool is_addsub_w_imm(uint32_t w) { return (w & 0xBF800000u) == 0x11000000u; }
// LSLV/LSRV/ASRV/RORV Wd, Wn, Wm (dp-2src shift-by-register)
inline bool is_shiftv_w(uint32_t w) { return (w & 0xFFE0F000u) == 0x1AC02000u; }
// MOVZ/MOVN/MOVK (32/64)
inline bool is_movwide(uint32_t w) { return (w & 0x1F800000u) == 0x12800000u; }
// Body-side integer ALU classes (reads don't matter there — only the Rd
// write is checked against the pins): ADD/SUB[S] imm any width, add/sub reg,
// logical reg, logical imm, dp-2src/cond-select, dp-3src, bitfield.
inline bool is_int_alu_rd(uint32_t w) {
    const uint32_t cls = w & 0x1F000000u;
    return cls == 0x11000000u ||  // ADD/SUB[S] imm (32/64)
           cls == 0x0B000000u ||  // ADD/SUB[S] shifted/extended reg
           cls == 0x0A000000u ||  // AND/ORR/EOR/ANDS shifted reg
           cls == 0x12000000u ||  // logical imm / movwide
           cls == 0x1A000000u ||  // dp-2src, CSEL family, ADC
           cls == 0x1B000000u ||  // MADD/MSUB
           cls == 0x13000000u;    // SBFM/BFM/UBFM/extract
}
// LDR Dt, [Xn, Xm] (option LSL, S=0 or S=1)
inline bool is_ldr_d_regoff(uint32_t w) { return (w & 0xFFE0EC00u) == 0xFC606800u; }
// STR Dt, [Xn, Xm] (option LSL, S=0 or S=1)
inline bool is_str_d_regoff(uint32_t w) { return (w & 0xFFE0EC00u) == 0xFC206800u; }
// Any load/store class touching memory (used to sort remaining mem ops):
// top-level op0 x1x0 at bits 28-25.
inline bool is_ldst_class(uint32_t w) { return (w & 0x0A000000u) == 0x08000000u; }
// Loads write a register; bit 22 distinguishes load within most ldst classes
// we accept below (unsigned-imm, unscaled, reg-offset, literal excluded).
inline bool ldst_is_load(uint32_t w) { return (w & 0x00400000u) != 0; }
// SIMD/FP register file destination? (V bit 26 in the ldst classes)
inline bool ldst_is_fpr(uint32_t w) { return (w & 0x04000000u) != 0; }
// Scalar FP data-processing (1-src/2-src/3-src/convert): op0 pattern
// x111_1010..x111_1110 → accept 0x1E/0x1F/0x5E/0x7E leading bytes plus SIMD
// 0x0E/0x2E/0x4E/0x6E. All write Vd = w&31.
inline bool is_fp_simd_dp(uint32_t w) {
    const uint32_t hi = w >> 24;
    switch (hi & 0xDFu) {  // fold bit 29 (0x20)
        case 0x1E: case 0x1F: case 0x5E: case 0x0E: case 0x4E:
            return true;
        default:
            return false;
    }
}
// Unconditional branch-class or system-class word (BL/BLR/B/RET/TBZ/etc.):
// op0 101x at bits 28-25 (branches, exception, system).
inline bool is_branch_or_sys(uint32_t w) { return (w & 0x1C000000u) == 0x14000000u; }
inline bool is_nop_hint(uint32_t w) { return (w & 0xFFFFF01Fu) == 0xD503201Fu; }

struct SelfLoopVerdict {
    bool qualify = false;
    const char* reason = "";  // decline reason (or "" on qualify)
    uint32_t detail_word = 0;
    uint32_t detail_off = 0;  // byte offset within the region
    uint32_t skip_off = 0;    // byte offset of the skip target within region
    int fpr = -1;
    int base_gpr = -1;
    int key_gpr = -1;
};

// The skipped-region walk, shared between the full post-pass analysis and
// the translate-time gap-pin extractor (which runs it over the partially
// emitted block). Every word must derive only from x18 / X87State memory /
// earlier region defs; the walk ends at the first st[] load (reg-offset D
// form based on the x18-derived state base). Returns nullptr on success or
// the decline reason (fail_idx = offending word).
struct PrefixInfo {
    uint32_t region_gpr_defs = 0;  // bit per GPR defined in the region
    int base_gpr = -1;
    int key_gpr = -1;
    int fpr = -1;
    uint64_t ldr_idx = 0;
    uint64_t fail_idx = 0;
};

const char* walk_prefix(volatile uint32_t* words, uint64_t limit, PrefixInfo* out) {
    PrefixInfo& p = *out;
    auto reads_ok = [&](int r) {
        return r == 18 || r == 31 || (p.region_gpr_defs >> r) & 1u;
    };
    for (uint64_t i = 0; i < limit; i++) {
        const uint32_t w = words[i];
        p.fail_idx = i;
        if (is_add_x_imm(w) && rn_of(w) == 18) {
            p.region_gpr_defs |= 1u << rd_of(w);
            p.base_gpr = rd_of(w);  // latest x18-derived base
        } else if (is_ldrh_imm(w) &&
                   (rn_of(w) == 18 || (p.base_gpr >= 0 && rn_of(w) == p.base_gpr))) {
            p.region_gpr_defs |= 1u << rd_of(w);
        } else if (is_ubfm_w(w)) {
            if (!reads_ok(rn_of(w)))
                return "prefix-reads-outside";
            p.region_gpr_defs |= 1u << rd_of(w);
        } else if (is_orr_w_reg(w)) {
            if (!reads_ok(rn_of(w)) || !reads_ok(rm_of(w)))
                return "prefix-reads-outside";
            p.region_gpr_defs |= 1u << rd_of(w);
        } else if (is_addsub_w_imm(w)) {
            if (!reads_ok(rn_of(w)))
                return "prefix-reads-outside";
            p.region_gpr_defs |= 1u << rd_of(w);
        } else if (is_shiftv_w(w)) {
            if (!reads_ok(rn_of(w)) || !reads_ok(rm_of(w)))
                return "prefix-reads-outside";
            p.region_gpr_defs |= 1u << rd_of(w);
        } else if (is_ldr_d_regoff(w)) {
            if (p.base_gpr < 0 || rn_of(w) != p.base_gpr)
                return "prime-load-base";
            if (!((p.region_gpr_defs >> rm_of(w)) & 1u))
                return "prime-load-key";
            p.ldr_idx = i;
            p.fpr = rd_of(w);
            p.key_gpr = rm_of(w);
            return nullptr;
        } else {
            return "prefix-unrecognized";
        }
    }
    p.fail_idx = 0;
    return "no-priming-load";
}

// words[0..n_words) = the block region [head .. next block head); the block's
// terminator back edge must be the region's last word.
SelfLoopVerdict analyze_self_loop(volatile uint32_t* words, uint64_t n_words) {
    SelfLoopVerdict v;
    auto decline = [&](const char* r, uint64_t idx) {
        v.qualify = false;
        v.reason = r;
        v.detail_off = (uint32_t)(idx * 4);
        v.detail_word = (idx < n_words) ? words[idx] : 0;
        return v;
    };
    if (n_words < 4)
        return decline("too-short", 0);

    // 1. Terminator: last word must be a conditional branch back to word 0.
    const uint64_t be = n_words - 1;
    const uint32_t be_w = words[be];
    if (!is_cond_branch(be_w))
        return decline("terminator-not-cond", be);
    if ((int64_t)be + cond_branch_offset_words(be_w) != 0)
        return decline("backedge-target-not-head", be);

    // 2. Skipped region: walk from the head through the priming load.
    PrefixInfo pfx;
    const char* pfx_reason = walk_prefix(words, be, &pfx);
    if (pfx_reason)
        return decline(pfx_reason, pfx.fail_idx);

    const uint32_t region_gpr_defs = pfx.region_gpr_defs;
    const int base_gpr = pfx.base_gpr;
    const uint64_t ldr_idx = pfx.ldr_idx;
    const int fpr = pfx.fpr;
    const int key_gpr = pfx.key_gpr;

    // 3. Body + gap: [ldr_idx+1 .. be). One st[] store of the same FPR to the
    //    same base+key; no writes to region-defined GPRs; no FPR write after
    //    the store; no other state access; default-deny.
    bool store_seen = false;
    for (uint64_t i = ldr_idx + 1; i < be; i++) {
        const uint32_t w = words[i];
        if (is_str_d_regoff(w)) {
            if (rn_of(w) != base_gpr)
                return decline("stray-state-store", i);
            if (rd_of(w) != fpr || rm_of(w) != key_gpr)
                return decline("writeback-mismatch", i);
            if (store_seen)
                return decline("double-writeback", i);
            store_seen = true;
        } else if (is_strh_imm(w) &&
                   (rn_of(w) == 18 || rn_of(w) == base_gpr)) {
            return decline("state-halfword-store", i);  // TOP/tag writeback
        } else if (is_fp_simd_dp(w)) {
            if (rd_of(w) == fpr && store_seen)
                return decline("fpr-write-after-store", i);
        } else if (is_nop_hint(w)) {
            // fine
        } else if (is_branch_or_sys(w) || is_cond_branch(w)) {
            return decline("branch-in-body", i);
        } else if (is_ldst_class(w)) {
            if (rn_of(w) == base_gpr || rn_of(w) == 18)
                return decline("state-access-in-body", i);
            if (ldst_is_load(w)) {
                const int t = rd_of(w);
                if (ldst_is_fpr(w)) {
                    if (t == fpr)
                        return decline("pin-fpr-load", i);
                } else {
                    if ((region_gpr_defs >> t) & 1u)
                        return decline("pin-gpr-load", i);
                }
            }
            // Stores to non-state bases are guest memory — cannot alias
            // X87State (it lives in the runtime thread context).
        } else if (is_int_alu_rd(w)) {
            // Rd==31 is WZR/XZR (or SP for ADD imm — Rosetta never retargets
            // SP mid-block through this path); never a pin.
            if (rd_of(w) != 31 && ((region_gpr_defs >> rd_of(w)) & 1u))
                return decline("pin-gpr-write", i);
        } else {
            return decline("body-unrecognized", i);
        }
    }
    if (!store_seen)
        return decline("no-writeback", 0);

    v.qualify = true;
    v.skip_off = (uint32_t)((ldr_idx + 1) * 4);
    v.fpr = fpr;
    v.base_gpr = base_gpr;
    v.key_gpr = key_gpr;
    return v;
}

}  // namespace

void x87_backedge_gap_pins(TranslationResult* result, IRBlock* block,
                           uint32_t* gpr_pins, uint32_t* fpr_pins) {
    *gpr_pins = 0;
    *fpr_pins = 0;
    const RosettaConfig* cfg = g_rosetta_config;
    if (!backedge_enabled(cfg))
        return;
    if (result != g_rec_owner || g_num_block_recs == 0 || g_block_recs_overflow)
        return;
    if (!is_self_loop_block(block))
        return;
    // The current block is always the most recent record (note_block fires at
    // the block-change edge before any of its instructions translate).
    const BlockRec& rec = g_block_recs[g_num_block_recs - 1];
    if (rec.start_pc != block->start_pc || (rec.arm_off & 3))
        return;
    const uint64_t end = result->insn_buf.end;
    if (rec.arm_off >= end)
        return;
    volatile uint32_t* words = result->insn_buf.data + rec.arm_off / 4;
    PrefixInfo pfx;
    if (walk_prefix(words, (end - rec.arm_off) / 4, &pfx) != nullptr)
        return;
    // Only scratch GPRs can (and need to) be withheld from Rosetta's
    // allocator; the post-pass decode check stays the enforcement if
    // anything writes a pin regardless.
    *gpr_pins = pfx.region_gpr_defs & kGprScratchMask;
    *fpr_pins = 1u << pfx.fpr;
}

void x87_backedge_module_post(TranslationResult* result) {
    const RosettaConfig* cfg = g_rosetta_config;
    const bool log = cfg && cfg->log_backedge;
    const bool probe = cfg && cfg->backedge_noop_probe;
    const bool patch = backedge_enabled(cfg);
    if (!log && !probe && !patch)
        return;
    if (!result) {
        g_rec_owner = nullptr;
        return;
    }

    g_backedge_module_count++;

    // JIT mode: code accumulates in insn_buf. AOT mode: the finished code has
    // been moved to data_/data_size by the time translator_translate returns;
    // block offsets recorded during translation are congruent (stage-1
    // verified).
    volatile uint32_t* words = result->insn_buf.data;
    uint64_t n_words = result->insn_buf.end / 4;
    const char* src = "insn_buf";
    if (n_words == 0 && result->data_ && result->data_size) {
        words = (volatile uint32_t*)result->data_;
        n_words = result->data_size / 4;
        src = "data_";
    }

    // Stage-0 evidence scan (debug only — a full-buffer walk per module).
    if (log || probe) {
        BranchScan scan;
        for (uint64_t i = 0; i < n_words; i++) {
            const uint32_t w = words[i];
            if (!is_cond_branch(w))
                continue;
            const int32_t off = cond_branch_offset_words(w);
            if (off < 0) {
                scan.backward_cond++;
                if (probe)
                    words[i] = w;  // G0.2: same-value write — must change nothing
            } else if (off == 0) {
                scan.zero_off_cond++;
            }
        }
        if (log)
            CORE_LOG("backedge: module=%llu mode=%d src=%s words=%llu "
                     "backward_cond=%llu placeholder_cond=%llu%s",
                     (unsigned long long)g_backedge_module_count,
                     (int)result->_mode, src, (unsigned long long)n_words,
                     (unsigned long long)scan.backward_cond,
                     (unsigned long long)scan.zero_off_cond,
                     probe ? " probe=on" : "");
    }

    // ── Analyze recorded self-loop blocks; patch the qualifying ones ───────
    if ((log || patch) && result == g_rec_owner) {
        if (g_block_recs_overflow) {
            if (log)
                CORE_LOG("backedge-cand: block records overflowed, module skipped");
        } else {
            for (uint32_t bi = 0; bi < g_num_block_recs; bi++) {
                const BlockRec& rec = g_block_recs[bi];
                if (!rec.self_loop)
                    continue;
                const uint32_t end_off = (bi + 1 < g_num_block_recs)
                                             ? g_block_recs[bi + 1].arm_off
                                             : (uint32_t)(n_words * 4);
                if (rec.arm_off >= end_off || (rec.arm_off & 3) ||
                    end_off > n_words * 4) {
                    if (log)
                        CORE_LOG("backedge-cand: pc=0x%x arm=+0x%x DECLINE "
                                 "reason=bad-region",
                                 rec.start_pc, rec.arm_off);
                    continue;
                }
                SelfLoopVerdict v = analyze_self_loop(
                    words + rec.arm_off / 4, (end_off - rec.arm_off) / 4);
                if (!v.qualify) {
                    if (log)
                        CORE_LOG("backedge-cand: pc=0x%x arm=+0x%x DECLINE "
                                 "reason=%s at=+0x%x word=0x%08x",
                                 rec.start_pc, rec.arm_off, v.reason,
                                 v.detail_off, v.detail_word);
                    continue;
                }
                if (log)
                    CORE_LOG("backedge-cand: pc=0x%x arm=+0x%x QUALIFY "
                             "skip=+0x%x fpr=d%d base=x%d key=x%d%s",
                             rec.start_pc, rec.arm_off, v.skip_off, v.fpr,
                             v.base_gpr, v.key_gpr, patch ? " PATCH" : "");
                // The transform: retarget the back edge past the priming
                // load. Single-step mode plants a BRK after the terminator,
                // so its region never ends in the branch — the decode check
                // already excludes it; the mode gate is belt-and-suspenders.
                if (patch && result->_mode != 2) {
                    const uint64_t be_idx = end_off / 4 - 1;
                    const uint64_t tgt_idx = (rec.arm_off + v.skip_off) / 4;
                    const uint32_t bw = words[be_idx];
                    const int32_t imm19 = (int32_t)tgt_idx - (int32_t)be_idx;
                    words[be_idx] =
                        (bw & ~0x00FFFFE0u) | (((uint32_t)imm19 & 0x7FFFF) << 5);
                }
            }
        }
    }
    // Consume the records — a module that skips its post-pass must not leak
    // records into the next module's analysis.
    if (result == g_rec_owner)
        g_rec_owner = nullptr;
}

void x87_backedge_apply_fixups_audit(TranslationResult* result,
                                     unsigned char* dest) {
    const RosettaConfig* cfg = g_rosetta_config;
    if (!cfg || !cfg->log_backedge)
        return;
    if (!result || !dest)
        return;

    volatile uint32_t* pre = result->insn_buf.data;
    uint64_t n_words = result->insn_buf.end / 4;
    if (n_words == 0 && result->data_ && result->data_size) {
        pre = (volatile uint32_t*)result->data_;
        n_words = result->data_size / 4;
    }

    volatile uint32_t* post = (volatile uint32_t*)dest;
    uint64_t changed = 0;
    uint64_t changed_backward_cond = 0;
    for (uint64_t i = 0; i < n_words; i++) {
        const uint32_t a = pre[i];
        const uint32_t b = post[i];
        if (a == b)
            continue;
        changed++;
        if ((is_cond_branch(a) && cond_branch_offset_words(a) < 0) ||
            (is_cond_branch(b) && cond_branch_offset_words(b) < 0))
            changed_backward_cond++;
    }
    CORE_LOG("backedge-fixups: mode=%d words=%llu changed=%llu "
             "changed_backward_cond=%llu",
             (int)result->_mode, (unsigned long long)n_words,
             (unsigned long long)changed,
             (unsigned long long)changed_backward_cond);
}
