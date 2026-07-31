#include "rosetta_core/X87BackEdge.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/CoreLog.h"
#include "rosetta_core/TranslationResult.h"
#include <rosetta_config/Config.h>

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

}  // namespace

void x87_backedge_module_post(TranslationResult* result) {
    const RosettaConfig* cfg = g_rosetta_config;
    if (!cfg || (!cfg->log_backedge && !cfg->backedge_noop_probe))
        return;
    if (!result)
        return;

    g_backedge_module_count++;

    // JIT mode: code accumulates in insn_buf. AOT mode: characterize where it
    // actually lives at this point (stage-0 question — insn_buf vs data_).
    volatile uint32_t* words = result->insn_buf.data;
    uint64_t n_words = result->insn_buf.end / 4;
    const char* src = "insn_buf";
    if (n_words == 0 && result->data_ && result->data_size) {
        words = (volatile uint32_t*)result->data_;
        n_words = result->data_size / 4;
        src = "data_";
    }

    BranchScan scan;
    for (uint64_t i = 0; i < n_words; i++) {
        const uint32_t w = words[i];
        if (!is_cond_branch(w))
            continue;
        const int32_t off = cond_branch_offset_words(w);
        if (off < 0) {
            scan.backward_cond++;
            if (cfg->backedge_noop_probe)
                words[i] = w;  // G0.2: same-value write — must change nothing
        } else if (off == 0) {
            scan.zero_off_cond++;
        }
    }

    if (cfg->log_backedge)
        CORE_LOG("backedge: module=%llu mode=%d src=%s words=%llu "
                 "backward_cond=%llu placeholder_cond=%llu%s",
                 (unsigned long long)g_backedge_module_count, (int)result->_mode,
                 src, (unsigned long long)n_words,
                 (unsigned long long)scan.backward_cond,
                 (unsigned long long)scan.zero_off_cond,
                 cfg->backedge_noop_probe ? " probe=on" : "");
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
