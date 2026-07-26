#pragma once

#include <cstdint>

// TranslationCacheJit.cpp — JIT-side translation cache maintenance.
// Named by its own assertion strings ("TranslationCacheJit.cpp"), which also
// give us remove_fragment, remove_arm_tree_only_translation,
// iterate_fragments_in_x86_interval_holding_lock, jit_translation_for_x86_address
// and handle_jit_breakpoint.

// Nothing here is recovered yet — the only entry point we had a use for was
// gc_jit_free_list, and its sole caller was ExecutableHeap::allocate (0x79D4),
// which is off the allocate_chunk path.
//
// gc_jit_free_list (0xCD6C) drains ExecutableHeap::jit_free_list: for every
// InvalidJit fragment whose retire_epoch is older than the current global epoch,
// it unlinks the fragment from the arm tree, returns its code span to
// BestFitAllocator and frees the metadata node.  Asserts
// "entry->kind == CodeFragmentKind::InvalidJit" on each entry.
