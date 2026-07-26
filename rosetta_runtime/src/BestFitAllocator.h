#pragma once

#include <cstdint>

#include "FreeBlock.h"
#include "RedBlackTree.h"

// Best-fit allocator for the JIT code heap.  The runtime has its own
// BestFitAllocator.h (assertion string at 0x25E20) and it is a *static* class:
// nothing here holds state, so the two red-black trees live as plain members of
// ExecutableHeap (free_by_size / free_by_addr) and the methods either take the
// tree explicitly or reach g_executable_heap directly.
//
// Why this doesn't use RedBlackTree<FreeBlock>::insert: a FreeBlock is in BOTH
// trees at once and therefore carries TWO link sets —
//
//   size tree — ordered by FreeBlock::size,           links at 0x00/0x08/0x10/0x18
//   addr tree — ordered by FreeBlock::allocation_base, links at 0x20/0x28/0x30/0x38
//
// so BestFitAllocator reimplements insert/remove/fixup over the same 0x10-byte
// RedBlackTree header, hardcoding the link offsets per tree (insert_by_size
// walks children at 0x10/0x18, insert_by_addr at 0x30/0x38).
//
// The full surface in the binary, of which only the insert/fixup half is
// recovered — the rest belongs to the allocate and free paths, neither of which
// allocate_chunk reaches:
//
//   0x7AB8  try_allocate         static; best-fit search of free_by_size
//   0x7C4C  allocate_from_node   carve an allocation out of one FreeBlock
//   0x7D5C  remove_by_size       operates on g_executable_heap.free_by_size
//   0x8144  insert_by_size       ── recovered
//   0x81B8  remove_by_addr       operates on g_executable_heap.free_by_addr
//   0x85AC  fixup_size           ── recovered
//   0x879C  insert_by_addr       ── recovered
//   0x8824  fixup_addr           ── recovered
//   0x8A14  free                 coalesce and return a span to both trees
struct BestFitAllocator {
    // insert_* are what allocate_chunk calls; each tail-calls its fixup_*, which
    // is a separate function in the binary and so is kept at the same visibility.
    static void insert_by_size(RedBlackTree<FreeBlock>* tree, FreeBlock* node);
    static void insert_by_addr(RedBlackTree<FreeBlock>* tree, FreeBlock* node);
    static void fixup_size(RedBlackTree<FreeBlock>* tree, FreeBlock* node);
    static void fixup_addr(RedBlackTree<FreeBlock>* tree, FreeBlock* node);
};
