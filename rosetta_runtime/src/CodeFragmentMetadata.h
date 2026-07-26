#pragma once

#include <cstddef>
#include <cstdint>

// Stored as uint8_t at offset 0x40 in CodeFragmentMetadata.
//
// Evidence:
//   STRING  "CodeFragmentKind::Aot"              — assertion in TranslationCacheAot.cpp
//   STRING  "CodeFragmentKind::Jit"              — assertion in TranslationCacheJit.cpp
//   STRING  "CodeFragmentKind::InvalidJit"       — assertion in TranslationCacheJit.cpp
//   STRING  "CodeFragmentKind::RuntimeRoutines"  — assertion in TranslationCacheAot.cpp
//   CODE    register_aot_cache_metadata sets kind=1 for shared-cache AOT entries
//   CODE    remove_fragment transitions 0/1 → 2, 3 → 4
//   CODE    sub_BF4C transitions 6 → 7 during AOT image removal
//   CODE    main calls register_code_fragment(..., 5) for runtime/libRosettaRuntime
//   CODE    ExecutableHeap::allocate_chunk calls register_code_fragment(..., 6) for stub page
//   CODE    gc_jit_free_list asserts kind==4 ("entry->kind == CodeFragmentKind::InvalidJit")
//   CODE    AOT free list GC (sub_16AB8) accepts kind==2 or kind==7
//
// Lifecycle:  Aot(0) ──remove_fragment──▸ InvalidAot(2) ──aot_gc──▸ freed
//             AotSharedCache(1) ─────────▸ InvalidAot(2) ──aot_gc──▸ freed
//             Jit(3) ──remove_fragment──▸ InvalidJit(4) ──jit_gc──▸ freed
//             RuntimeRoutines(6) ───────▸ InvalidRuntimeRoutines(7) ──aot_gc──▸ freed
//             RuntimeBinary(5) — never removed
enum CodeFragmentKind : uint8_t {
    Aot                     = 0, // per-image AOT translation
    AotSharedCache          = 1, // dyld shared-cache AOT translation (no segment processing on removal)
    InvalidAot              = 2, // invalidated AOT (terminal; sits in AOT free list)
    Jit                     = 3, // JIT-compiled translation
    InvalidJit              = 4, // invalidated JIT (terminal; sits in JIT free list)
    RuntimeBinary           = 5, // translator binary image (/usr/libexec/rosetta/runtime, libRosettaRuntime)
    RuntimeRoutines         = 6, // runtime stubs page (0x4000-byte entry stubs)
    InvalidRuntimeRoutines  = 7, // invalidated runtime routines (terminal; sits in AOT free list)
};

// Metadata for one translated code fragment, allocated from
// ExecutableHeap::code_fragment_allocator (node_stride 0x120, 14 per page; the
// struct itself is 0x118 — gc_jit_free_list memsets exactly 0x118 bytes).
//
// The name is the binary's own: STRING "CodeFragmentMetadata.cpp", and its
// asserts call the object fragment / code_fragment / fragment_metadata.
//
// A fragment is filed in up to two red-black trees using ONE link set:
//   arm_tree      (heap+0x4F0)         keyed on arm_base — remove_arm_tree_only_translation
//   aot/jit_x86_tree (heap+0x4C8/4D8)  keyed on x86_base — find_translation_in_tree_x86
// register_code_fragment fills in kind/arm_base/arm_size only (the runtime
// binary and the stub page have no x86 counterpart) and zeroes the rest.
struct CodeFragmentMetadata
{
  uint64_t reserved_00[4];              // 0x00
  uint8_t bst_color;                    // 0x20
  char pad_21[7];
  CodeFragmentMetadata *bst_parent;     // 0x28
  CodeFragmentMetadata *bst_left;       // 0x30
  CodeFragmentMetadata *bst_right;      // 0x38
  CodeFragmentKind kind;                // 0x40
  char pad_41[7];
  uint64_t x86_base;                    // 0x48  x86 (guest) range start
  uint64_t reserved_50;                 // 0x50
  uint64_t arm_base;                    // 0x58  arm (host) range start — arm_tree key
  uint64_t reserved_60[7];              // 0x60
  uint32_t x86_size;                    // 0x98
  uint32_t arm_size;                    // 0x9C
  uint32_t num_branch_slots;            // 0xA0
  char pad_A4[4];
  uint64_t reserved_A8[4];              // 0xA8
  uint32_t reserved_C8;                 // 0xC8
  char pad_CC[4];
  uint64_t reserved_D0[5];              // 0xD0
  uint16_t reserved_F8;                 // 0xF8
  char pad_FA[6];
  uint64_t retire_epoch;                // 0x100  stamped from the global epoch on retire
  CodeFragmentMetadata *next_free_fragment; // 0x108  CodeFragmentFreeList link
  uint64_t reserved_110;                // 0x110
};

static_assert(sizeof(CodeFragmentMetadata) == 0x118);
static_assert(offsetof(CodeFragmentMetadata, bst_color) == 0x20);
static_assert(offsetof(CodeFragmentMetadata, bst_parent) == 0x28);
static_assert(offsetof(CodeFragmentMetadata, bst_left) == 0x30);
static_assert(offsetof(CodeFragmentMetadata, bst_right) == 0x38);
static_assert(offsetof(CodeFragmentMetadata, kind) == 0x40);
static_assert(offsetof(CodeFragmentMetadata, x86_base) == 0x48);
static_assert(offsetof(CodeFragmentMetadata, arm_base) == 0x58);
static_assert(offsetof(CodeFragmentMetadata, x86_size) == 0x98);
static_assert(offsetof(CodeFragmentMetadata, arm_size) == 0x9C);
static_assert(offsetof(CodeFragmentMetadata, num_branch_slots) == 0xA0);
static_assert(offsetof(CodeFragmentMetadata, reserved_C8) == 0xC8);
static_assert(offsetof(CodeFragmentMetadata, reserved_F8) == 0xF8);
static_assert(offsetof(CodeFragmentMetadata, retire_epoch) == 0x100);
static_assert(offsetof(CodeFragmentMetadata, next_free_fragment) == 0x108);

// RedBlackTree<CodeFragmentMetadata> key for ExecutableHeap::arm_tree.  The x86
// trees sort the same node type by x86_base and need their own instantiation.
inline uint64_t rb_key(const CodeFragmentMetadata* n) {
    return n->arm_base;
}
