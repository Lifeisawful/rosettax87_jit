#pragma once

#include <cstddef>
#include <cstdint>

#include "Lock.h"

// Per-slab page header (0x20 bytes at the start of each mmap'd 4K page).
// Nodes start at offset first_node_offset (== sizeof(SlabPage)).
struct SlabPage {
  SlabPage *next;
  SlabPage *prev;
  void *free_head;
  uint32_t free_count;
  uint32_t pad;
};

static_assert(sizeof(SlabPage) == 0x20);
static_assert(offsetof(SlabPage, next) == 0x00);
static_assert(offsetof(SlabPage, prev) == 0x08);
static_assert(offsetof(SlabPage, free_head) == 0x10);
static_assert(offsetof(SlabPage, free_count) == 0x18);

// Fixed-size slab allocator.  Three doubly-linked lists of SlabPage:
//   empty_slabs   — all nodes free, cached for reuse (at most 1 kept; extras munmap'd)
//   partial_slabs — some nodes allocated, some free (allocation pulls from here first)
//   full_slabs    — all nodes allocated
//
// Lifecycle:
//   new page (mmap 4K) ──▸ partial_slabs
//   last free entry taken ──▸ full_slabs
//   first node freed back ──▸ partial_slabs
//   all nodes freed ──▸ empty_slabs (or munmap'd if one already cached)
//   empty slab reused ──▸ partial_slabs
#pragma pack(push, 2)
struct SlabAllocator {
  void *empty_slabs;
  void *partial_slabs;
  void *full_slabs;
  uint64_t page_mask;
  uint32_t node_stride;
  uint32_t first_node_offset;
  uint32_t nodes_per_page;
  uint32_t pad_2c;

  void *alloc();
  void free(void *node);
};
#pragma pack(pop)

static_assert(sizeof(SlabAllocator) == 0x30);
static_assert(offsetof(SlabAllocator, empty_slabs) == 0x00);
static_assert(offsetof(SlabAllocator, partial_slabs) == 0x08);
static_assert(offsetof(SlabAllocator, full_slabs) == 0x10);
static_assert(offsetof(SlabAllocator, page_mask) == 0x18);
static_assert(offsetof(SlabAllocator, node_stride) == 0x20);
static_assert(offsetof(SlabAllocator, first_node_offset) == 0x24);
static_assert(offsetof(SlabAllocator, nodes_per_page) == 0x28);

// SlabAllocator paired with the os_unfair_lock that guards it.  locked_alloc /
// locked_free are members of *this* type, not of SlabAllocator: they reach the
// lock at +0x30, which is one past the end of a bare 0x30-byte SlabAllocator.
//
//   0xAA28  SlabAllocator::locked_alloc  ADD X0, X0, #0x30 -> &alloc->lock
//   0xAE38  SlabAllocator::locked_free   ADD X0, X0, #0x30
//
// Two instances in the runtime:
//   g_executable_heap.code_fragment_allocator (heap+0x508, node_stride 0x120)
//   qword_326C0 / dword_326F0               (node_stride 0xA60) — its users
//                                            inline lock/alloc/unlock instead
//                                            of calling the helpers
//
// The heap's other two allocators are bare SlabAllocators: ExecutableHeap
// ::allocator (heap+0x00) is guarded by allocator_lock at heap+0x58, and
// qword_32988 has a plain pointer at +0x30.
#pragma pack(push, 2)
struct LockedSlabAllocator {
  SlabAllocator allocator;
  os_unfair_lock lock;
  uint32_t pad_34;

  void *locked_alloc(uint32_t self);
  void locked_free(void *node, uint32_t self);
};
#pragma pack(pop)

static_assert(sizeof(LockedSlabAllocator) == 0x38);
static_assert(offsetof(LockedSlabAllocator, allocator) == 0x00);
static_assert(offsetof(LockedSlabAllocator, lock) == 0x30);
static_assert(offsetof(LockedSlabAllocator, pad_34) == 0x34);
