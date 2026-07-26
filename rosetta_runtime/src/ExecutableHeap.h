#pragma once

#include <cstddef>
#include <cstdint>

#include "BestFitAllocator.h"
#include "CodeFragmentMetadata.h"
#include "FreeBlock.h"
#include "CodeFragmentFreeList.h"
#include "Chunk.h"
#include "Lock.h"
#include "RedBlackTree.h"
#include "SlabAllocator.h"
#include "TranslationCache.h"

// The runtime's single global heap object (__bss, 0x3B390 in the reference
// binary).  It owns the 128 MB RWX code heap plus every allocator, tree, cache
// and lock the translator needs.  Constituent types live in their own headers:
//
//   Chunk.h                 Chunk (a heap span; chained from chunk_list)
//   FreeBlock.h             FreeBlock
//   BestFitAllocator.h      free_by_size / free_by_addr tree operations (static class)
//   RedBlackTree.h          RedBlackTree<Node>
//   SlabAllocator.h         SlabAllocator, LockedSlabAllocator
//   CodeFragmentMetadata.h  CodeFragmentKind, CodeFragmentMetadata
//   TranslationCache.h      TranslationCache (+ HashTableDesc.h)
//   CodeFragmentFreeList.h  CodeFragmentFreeList
//   Lock.h                  os_unfair_lock
#pragma pack(push, 2)
struct ExecutableHeap
{
  SlabAllocator allocator;
  Chunk *chunk_list;
  RedBlackTree<FreeBlock> free_by_size;
  RedBlackTree<FreeBlock> free_by_addr;
  os_unfair_lock allocator_lock;
  uint32_t initialized;
  uint32_t heap_count;
  uint32_t pad_064;
  void *heap_base;
  uint8_t aot_cache_initialized;
  uint8_t pad_071[15];
  TranslationCache aot_cache;
  TranslationCache jit_cache;
  os_unfair_lock translation_cache_lock;
  uint32_t translation_cache_lock_pad;
  RedBlackTree<CodeFragmentMetadata> aot_x86_tree;
  RedBlackTree<CodeFragmentMetadata> jit_x86_tree;
  os_unfair_lock x86_tree_lock;
  uint32_t x86_tree_lock_pad;
  RedBlackTree<CodeFragmentMetadata> arm_tree;
  os_unfair_lock arm_tree_lock;
  uint32_t arm_tree_lock_pad;
  LockedSlabAllocator code_fragment_allocator;
  CodeFragmentFreeList jit_free_list;
  CodeFragmentFreeList aot_free_list;
  void *jit_gc_list_tail;
  uint64_t thread_apc_lock;
  uint64_t thread_apc_lock_pad;
  void *thread_apc_list;
  uint64_t field_568;
  uint64_t field_570;
  os_unfair_lock jit_region_lock;
  uint32_t jit_region_lock_pad;
  uint64_t aot_cache_lock;
  uint64_t aot_cache_lock_pad;
  uint64_t field_588;
  uint64_t field_590;
  uint64_t field_598;
  uint32_t stat_translations;
  uint32_t stat_retranslations;
  uint32_t stat_invalidations;
  uint32_t pad_5ac;
  uint64_t mach_port;
  uint8_t pad_5b8[8];
  uint64_t field_5c0;
  uint64_t field_5c8;
  uint32_t field_5d0;
  uint8_t pad_5d4[12];
  uint32_t mach_task_self;

  // Recovered methods.  `allocate_chunk` and `runtime_routines_for_address` both
  // take an ExecutableHeap* first argument, i.e. `this`.
  //
  // allocate_chunk: NAME INFERRED (this function uses ERROR(), not ASSERT(), so no
  // function-name argument exists to recover).  It mmaps another 128 MB span,
  // registers its stub page, prepends a Chunk to chunk_list and returns the
  // FreeBlock covering it.  Called from main once at startup and again from
  // ExecutableHeap::allocate (0x79D4) whenever the heap is exhausted — which is
  // why "init" is a poor fit.  Its own log line calls the work "allocating
  // ExecutableHeap chunk".
  //
  // allocate (0x79D4) is not recovered: it is a *caller* of allocate_chunk, sitting
  // on the translation path (translate_code_region, sub_17640).  It is PROVEN static
  // by its own assert (ExecutableHeap.cpp:0x77 "allocate") and by taking no `this`.
  FreeBlock* allocate_chunk(uint32_t lock_owner);

  // runtime_routines_for_address (0x8C40) takes THREE arguments, not two:
  //   X0 = heap, X1 = lock_owner, X2 = addr
  // IDA's decompiler renders it as (heap, addr) and then reads an "uninitialized"
  // x2 — its prototype is simply wrong.  Verified at the call site in
  // remove_fragment (0xC654-0xC660): `MOV X0,X21(heap); MOV X1,X20(addr-typed but
  // actually lock_owner); MOV X2,X23; BL`, and inside the callee at 0x8C54-0x8C5C:
  // `MOV X19,X2` (the searched address), `MOV X20,X1` (passed to
  // os_unfair_lock_unlock_no_tsd as `self`), `MOV X21,X0` (the heap).
  void* runtime_routines_for_address(uint32_t lock_owner, uint64_t addr);
};
#pragma pack(pop)

static_assert(sizeof(ExecutableHeap) == 0x614);
static_assert(offsetof(ExecutableHeap, allocator) == 0x000);
static_assert(offsetof(ExecutableHeap, chunk_list) == 0x030);
static_assert(offsetof(ExecutableHeap, free_by_size) == 0x038);
static_assert(offsetof(ExecutableHeap, free_by_addr) == 0x048);
static_assert(offsetof(ExecutableHeap, allocator_lock) == 0x058);
static_assert(offsetof(ExecutableHeap, initialized) == 0x05C);
static_assert(offsetof(ExecutableHeap, heap_count) == 0x060);
static_assert(offsetof(ExecutableHeap, pad_064) == 0x064);
static_assert(offsetof(ExecutableHeap, heap_base) == 0x068);
static_assert(offsetof(ExecutableHeap, aot_cache_initialized) == 0x070);
static_assert(offsetof(ExecutableHeap, pad_071) == 0x071);
static_assert(offsetof(ExecutableHeap, aot_cache) == 0x080);
static_assert(offsetof(ExecutableHeap, jit_cache) == 0x2A0);
static_assert(offsetof(ExecutableHeap, translation_cache_lock) == 0x4C0);
static_assert(offsetof(ExecutableHeap, translation_cache_lock_pad) == 0x4C4);
static_assert(offsetof(ExecutableHeap, aot_x86_tree) == 0x4C8);
static_assert(offsetof(ExecutableHeap, jit_x86_tree) == 0x4D8);
static_assert(offsetof(ExecutableHeap, x86_tree_lock) == 0x4E8);
static_assert(offsetof(ExecutableHeap, x86_tree_lock_pad) == 0x4EC);
static_assert(offsetof(ExecutableHeap, arm_tree) == 0x4F0);
static_assert(offsetof(ExecutableHeap, arm_tree_lock) == 0x500);
static_assert(offsetof(ExecutableHeap, arm_tree_lock_pad) == 0x504);
static_assert(offsetof(ExecutableHeap, code_fragment_allocator) == 0x508);
static_assert(offsetof(ExecutableHeap, code_fragment_allocator) +
                  offsetof(LockedSlabAllocator, lock) ==
              0x538);
static_assert(offsetof(ExecutableHeap, jit_free_list) == 0x540);
static_assert(offsetof(ExecutableHeap, aot_free_list) == 0x558);
static_assert(offsetof(ExecutableHeap, jit_gc_list_tail) == 0x570);
static_assert(offsetof(ExecutableHeap, thread_apc_lock) == 0x578);
static_assert(offsetof(ExecutableHeap, thread_apc_lock_pad) == 0x580);
static_assert(offsetof(ExecutableHeap, thread_apc_list) == 0x588);
static_assert(offsetof(ExecutableHeap, field_568) == 0x590);
static_assert(offsetof(ExecutableHeap, field_570) == 0x598);
static_assert(offsetof(ExecutableHeap, jit_region_lock) == 0x5A0);
static_assert(offsetof(ExecutableHeap, jit_region_lock_pad) == 0x5A4);
static_assert(offsetof(ExecutableHeap, aot_cache_lock) == 0x5A8);
static_assert(offsetof(ExecutableHeap, aot_cache_lock_pad) == 0x5B0);
static_assert(offsetof(ExecutableHeap, field_588) == 0x5B8);
static_assert(offsetof(ExecutableHeap, field_590) == 0x5C0);
static_assert(offsetof(ExecutableHeap, field_598) == 0x5C8);
static_assert(offsetof(ExecutableHeap, stat_translations) == 0x5D0);
static_assert(offsetof(ExecutableHeap, stat_retranslations) == 0x5D4);
static_assert(offsetof(ExecutableHeap, stat_invalidations) == 0x5D8);
static_assert(offsetof(ExecutableHeap, pad_5ac) == 0x5DC);
static_assert(offsetof(ExecutableHeap, mach_port) == 0x5E0);
static_assert(offsetof(ExecutableHeap, pad_5b8) == 0x5E8);
static_assert(offsetof(ExecutableHeap, field_5c0) == 0x5F0);
static_assert(offsetof(ExecutableHeap, field_5c8) == 0x5F8);
static_assert(offsetof(ExecutableHeap, field_5d0) == 0x600);
static_assert(offsetof(ExecutableHeap, pad_5d4) == 0x604);
static_assert(offsetof(ExecutableHeap, mach_task_self) == 0x610);

extern ExecutableHeap* g_executable_heap;

// Installs our replacements over the reference ExecutableHeap::allocate_chunk and
// ExecutableHeap::runtime_routines_for_address.  Both addresses are absolute
// (kOffsets.runtime_base + the respective rva); a zero address skips that hook.
// Called from runtime_early_init, before the original runs — allocate_chunk is invoked
// from the reference `main`, which has not reached the heap setup yet at that
// point, so the hook is in place for the very first chunk.
// trace_write_mapping_record_addr is not hooked — it is the reference function,
// called directly from our map_runtime_routines to emit the type-5
// (RuntimeRoutinesMapped) trace record that our replacement would otherwise skip.
// Pass 0 to disable that record.
void init_executable_heap_hooks(uintptr_t allocate_chunk_addr,
                                uintptr_t runtime_routines_for_address_addr,
                                uintptr_t trace_write_mapping_record_addr);

void map_runtime_routines(uintptr_t dest, uint32_t task_port);
CodeFragmentMetadata* register_code_fragment(uint32_t lock_owner, uint64_t arm_base,
                                             uint32_t arm_size, CodeFragmentKind kind);

// 00000000 #pragma pack(push, 2)
// 00000000 struct ExecutableHeap // sizeof=0x614
// 00000000 {                                       // XREF: __bss:g_executable_heap/r
// 00000000     SlabAllocator allocator;            // XREF: main+82C/w main+834/w ...
// 00000030     Chunk *chunk_list;            // XREF: handle_exception+4B0/o
// 00000030                                         // handle_exception+4C4/r
// 00000038     RedBlackTree free_by_size;          // BestFitAllocator size tree (static class methods)
// 00000038                                         // XREF: BestFitAllocator::try_allocate+4/r ...
// 00000048     RedBlackTree free_by_addr;          // BestFitAllocator addr tree
// 00000048                                         // XREF: BestFitAllocator::free+24/r ...
// 00000058     os_unfair_lock allocator_lock;      // XREF: executable_heap_allocate+20/o
// 00000058                                         // executable_heap_allocate+58/o ...
// 0000005C     uint32_t initialized;
// 00000060     uint32_t heap_count;
// 00000064     uint32_t pad_064;
// 00000068     void *heap_base;
// 00000070     uint8_t aot_cache_initialized;      // lazy-init guard for the AOT translation cache
// 00000070                                         // XREF: ensure_aot_cache_initialized (0x9DD0) sets it to 1
// 00000070                                         // create_from_mach_thread+D8: skips AOT cache upkeep unless ==1
// 00000071     uint8_t pad_071[15];
// 00000080     TranslationCache aot_cache;         // XREF: ThreadContext_init+128/o
// 00000080                                         // sub_9ABC+24/o ...
// 000002A0     TranslationCache jit_cache;         // XREF: ThreadContext_init+134/o
// 000002A0                                         // sub_9ABC+2C/o ...
// 000004C0     os_unfair_lock translation_cache_lock;  // XREF: handle_exception+554/o, +578/o
// 000004C4     uint32_t translation_cache_lock_pad;
// 000004C8     RedBlackTree aot_rb_tree;           // root @ 0x4D0
// 000004C8                                         // XREF: find_translation_entry+4C (W21=0x4C8, LDR [X8,#8])
// 000004D8     RedBlackTree jit_rb_tree;           // root @ 0x4E0
// 000004D8                                         // XREF: find_translation_entry+38 (W21=0x4D8)
// 000004E8     os_unfair_lock x86_tree_lock;   // guards BOTH trees above
// 000004E8                                         // XREF: find_translation_entry+5C/o, +808/o
// 000004EC     uint32_t x86_tree_lock_pad;
// 000004F0     RedBlackTree arm_tree;      // XREF: register_code_fragment → RedBlackTree::insert
// 000004F0                                         // sub_BF4C tree traversal ...
// 00000500     os_unfair_lock arm_tree_lock;    // XREF: register_code_fragment+98/o
// 00000504     uint32_t arm_tree_lock_pad;
// 00000508     LockedSlabAllocator code_fragment_allocator; // node_stride=0x120 (CodeFragmentMetadata)
// 00000508                                         // XREF: main+7DC..7F8/w (init)
// 00000538     os_unfair_lock .lock;               // reached as this+0x30 by locked_alloc/free
// 0000053C     uint32_t .pad_34;
// 00000540     CodeFragmentFreeList jit_free_list; // XREF: gc_jit_free_list+30/o
// 00000540                                         // remove_fragment pushes InvalidJit here
// 00000558     CodeFragmentFreeList aot_free_list; // XREF: invalidate_translations_in_range+150/o
// 00000558                                         // remove_fragment pushes InvalidAot here
// 00000570     void *jit_gc_list_tail;             // XREF: main+8E0/w
// 00000570                                         // sub_19420+2C/r
// 00000578     uint64_t thread_apc_lock;           // XREF: translate_code_region+1B4/o
// 00000578                                         // translate_code_region+1B8/r ...
// 00000580     uint64_t thread_apc_lock_pad;       // XREF: sub_1C678+EC/o
// 00000588     void *thread_apc_list;              // XREF: translate_code_region+220/r
// 00000588                                         // sub_1C678+FC/o ...
// 00000590     uint64_t field_568;                 // XREF: sub_1C678+170/w
// 00000598     uint64_t field_570;                 // XREF: translate_code_region+22C/r
// 00000598                                         // sub_1C678+120/r ...
// 000005A0     os_unfair_lock jit_region_lock;     // XREF: vtable_register_jit_region (ADR heap+0x5A0)
// 000005A0                                         // translate_code_region+58/o ...
// 000005A4     uint32_t jit_region_lock_pad;
// 000005A8     uint64_t aot_cache_lock;            // XREF: vtable_register_jit_region+68/r
// 000005A8                                         // vtable_register_jit_region+84/o ...
// 000005B0     uint64_t aot_cache_lock_pad;        // XREF: translate_code_region+3EC/r
// 000005B0                                         // vtable_register_jit_region+5C/r ...
// 000005B8     uint64_t field_588;
// 000005C0     uint64_t field_590;                 // XREF: sub_47B4+4C/r
// 000005C0                                         // translate_code_region+4C4/o ...
// 000005C8     uint64_t field_598;                 // XREF: sub_1CB50+40/o
// 000005C8                                         // sub_1CB50+44/r ...
// 000005D0     uint32_t stat_translations;         // XREF: vtable_fork_handler+18C/o
// 000005D0                                         // vtable_fork_handler+190/w ...
// 000005D4     uint32_t stat_retranslations;
// 000005D8     uint32_t stat_invalidations;
// 000005DC     uint32_t pad_5ac;
// 000005E0     uint64_t mach_port;                 // XREF: sub_9390+F0/r
// 000005E0                                         // ThreadContext_init+E4/o ...
// 000005E8     uint8_t pad_5b8[8];
// 000005F0     uint64_t field_5c0;
// 000005F8     uint64_t field_5c8;
// 00000600     uint32_t field_5d0;
// 00000604     uint8_t pad_5d4[12];
// 00000610     uint32_t mach_task_self;
// 00000614 };
// 00000614 #pragma pack(pop)
