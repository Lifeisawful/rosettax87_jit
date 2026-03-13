#pragma once

// Internal helpers shared between TranslatorX87.cpp and TranslatorX87Fusion.cpp.
// These are inline so both translation units get their own copy without ODR issues.

#include <utility>

#include "rosetta_core/TranslationResult.h"
#include "rosetta_core/TranslatorHelpers.hpp"
#include "rosetta_core/TranslatorX87Helpers.hpp"

namespace TranslatorX87 {

// ── Preamble / epilogue used by every translate_* and try_fuse_* function ────

inline auto x87_begin(TranslationResult& a1, AssemblerBuffer& buf) -> std::pair<int, int> {
    if (a1.x87_cache.run_remaining > 0 && a1.x87_cache.gprs_valid) {
        return {a1.x87_cache.base_gpr, a1.x87_cache.top_gpr};
    }

    const int Xbase = alloc_gpr(a1, 0);
    const int Wd_top = alloc_gpr(a1, 1);
    emit_x87_base(buf, a1, Xbase);
    emit_load_top(buf, a1, Xbase, Wd_top);

    if (a1.x87_cache.run_remaining > 0) {
        a1.x87_cache.base_gpr = static_cast<int8_t>(Xbase);
        a1.x87_cache.top_gpr = static_cast<int8_t>(Wd_top);

        const int Xst_base = alloc_gpr(a1, 6);
        emit_add_imm(buf, /*is_64bit=*/1, /*is_sub=*/0, /*is_set_flags=*/0,
                     /*shift=*/0, kX87RegFileOff, Xbase, Xst_base);
        a1.x87_cache.st_base_gpr = static_cast<int8_t>(Xst_base);
        a1.x87_cache.gprs_valid = 1;
    }

    return {Xbase, Wd_top};
}

inline int x87_get_st_base(TranslationResult& a1) {
    return a1.x87_cache.gprs_valid ? a1.x87_cache.st_base_gpr : -1;
}

inline void x87_end(TranslationResult& a1, AssemblerBuffer& buf, int Xbase, int Wd_top,
                    int Wd_tmp) {
    if (a1.x87_cache.top_dirty && a1.x87_cache.run_remaining <= 1) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
        a1.x87_cache.top_dirty = 0;
    }

    if (a1.x87_cache.run_remaining > 0) {
        return;
    }
    free_gpr(a1, Wd_top);
    free_gpr(a1, Xbase);
}

inline void x87_cache_force_release(TranslationResult& a1, AssemblerBuffer& buf) {
    if (a1.x87_cache.top_dirty && a1.x87_cache.gprs_valid) {
        const int tmp = alloc_gpr(a1, 2);
        emit_store_top(buf, a1.x87_cache.base_gpr, a1.x87_cache.top_gpr, tmp);
        free_gpr(a1, tmp);
        a1.x87_cache.top_dirty = 0;
    }
    if (a1.x87_cache.gprs_valid) {
        a1.free_gpr_mask |= (1u << a1.x87_cache.base_gpr);
        a1.free_gpr_mask |= (1u << a1.x87_cache.top_gpr);
        a1.free_gpr_mask |= (1u << a1.x87_cache.st_base_gpr);
    }
    a1.x87_cache.invalidate();
}

// ── OPT-C: Push/pop wrappers that manage the deferred writeback flag ─────────

inline void x87_push(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top, int Wd_tmp,
                     int Wd_tmp2) {
    if (a1.x87_cache.run_remaining > 0) {
        emit_x87_push_deferred(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        a1.x87_cache.top_dirty = 1;
    } else {
        emit_x87_push(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
    }
}

inline void x87_pop(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                    int Wd_tmp) {
    const int Wd_tmp2 = alloc_free_gpr(a1);
    if (a1.x87_cache.run_remaining > 0) {
        emit_x87_pop_deferred(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        a1.x87_cache.top_dirty = 1;
    } else {
        emit_x87_pop(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2);
        a1.x87_cache.top_dirty = 0;
    }
    free_gpr(a1, Wd_tmp2);
}

inline void x87_pop_n(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                      int Wd_tmp, int n) {
    const int Wd_tmp2 = alloc_free_gpr(a1);
    if (a1.x87_cache.run_remaining > 0) {
        emit_x87_pop_n_deferred(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2, n);
        a1.x87_cache.top_dirty = 1;
    } else {
        emit_x87_pop_n(buf, Xbase, Wd_top, Wd_tmp, Wd_tmp2, n);
        a1.x87_cache.top_dirty = 0;
    }
    free_gpr(a1, Wd_tmp2);
}

inline void x87_flush_top(AssemblerBuffer& buf, TranslationResult& a1, int Xbase, int Wd_top,
                          int Wd_tmp) {
    if (a1.x87_cache.top_dirty) {
        emit_store_top(buf, Xbase, Wd_top, Wd_tmp);
        a1.x87_cache.top_dirty = 0;
    }
}

}  // namespace TranslatorX87
