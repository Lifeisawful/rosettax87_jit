#pragma once

#include <cstddef>
#include <cstdint>

// A free span of the JIT heap, simultaneously a member of BOTH of
// BestFitAllocator's red-black trees: it carries two independent link sets, so
// it cannot use RedBlackTree<Node> (which expects one bst_* set).  See
// BestFitAllocator.h.
//
// TYPE NAME UNATTESTED.  Nothing in the binary says "FreeBlock" — every assert
// in BestFitAllocator.h calls the object `node` / `right_node`, and the method
// is allocate_from_node, so the original is more likely a (probably nested)
// `Node`.  Kept as FreeBlock because it reads better and `node` is also just the
// natural variable name for a tree element.
//
// base_address IS attested, and settles an earlier disagreement with the IDB
// (which had it as allocation_base):
//   ASSERT "right_node == nullptr || right_node->base_address >= end_address"
//                                                       ^ a real field access
//   ASSERT "is_aligned(allocation_base, kAlignmentPower)"
//                       ^ only a local in allocate_from_node, copied from the field
// kAlignmentPower is 3 — the check is `base_address & 7`.
#pragma pack(push, 2)
struct FreeBlock
{
  uint8_t size_color;
  char pad_01[7];
  FreeBlock *size_parent;
  FreeBlock *size_left;
  FreeBlock *size_right;
  uint8_t addr_color;
  char pad_21[7];
  FreeBlock *addr_parent;
  FreeBlock *addr_left;
  FreeBlock *addr_right;
  uint64_t base_address;
  uint32_t size;
  uint32_t pad;
};
#pragma pack(pop)

static_assert(sizeof(FreeBlock) == 0x50);
static_assert(offsetof(FreeBlock, size_color) == 0x00);
static_assert(offsetof(FreeBlock, size_parent) == 0x08);
static_assert(offsetof(FreeBlock, size_left) == 0x10);
static_assert(offsetof(FreeBlock, size_right) == 0x18);
static_assert(offsetof(FreeBlock, addr_color) == 0x20);
static_assert(offsetof(FreeBlock, addr_parent) == 0x28);
static_assert(offsetof(FreeBlock, addr_left) == 0x30);
static_assert(offsetof(FreeBlock, addr_right) == 0x38);
static_assert(offsetof(FreeBlock, base_address) == 0x40);
static_assert(offsetof(FreeBlock, size) == 0x48);
static_assert(offsetof(FreeBlock, pad) == 0x4C);

// 00000000 #pragma pack(push, 2)
// 00000000 struct FreeBlock // sizeof=0x50
// 00000000 {
// 00000000     uint8_t size_color;                 // size-tree RB color (RED=1, BLACK=0)
// 00000001     char pad_01[7];
// 00000008     FreeBlock *size_parent;
// 00000010     FreeBlock *size_left;
// 00000018     FreeBlock *size_right;
// 00000020     uint8_t addr_color;                 // addr-tree RB color (RED=1, BLACK=0)
// 00000021     char pad_21[7];
// 00000028     FreeBlock *addr_parent;
// 00000030     FreeBlock *addr_left;
// 00000038     FreeBlock *addr_right;
// 00000040     uint64_t base_address;
// 00000048     uint32_t size;
// 0000004C     uint32_t pad;
// 00000050 };
// 00000050 #pragma pack(pop)
