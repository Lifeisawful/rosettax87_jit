#pragma once

#include <cstddef>
#include <cstdint>

#include "CodeFragmentMetadata.h"
#include "Lock.h"

// Intrusive head/tail list of invalidated code fragments awaiting GC.
// ExecutableHeap has two: jit_free_list (heap+0x540) and aot_free_list
// (heap+0x558).  remove_fragment pushes InvalidJit/InvalidAot entries here;
// gc_jit_free_list and sub_16AB8 drain them once no thread can still be
// executing the code.  Entries are chained through
// CodeFragmentMetadata::next_free_fragment; member names are the binary's own
// (asserts "_tail == nullptr", "_tail->next_free_fragment == nullptr" in
// CodeFragmentMetadata.cpp push_back).
//
// The class name is attested: 0x78F4 is CodeFragmentFreeList::push_back.
//
// Nothing on the allocate_chunk path uses this type beyond its size — it is here
// so ExecutableHeap's later fields land at the right offsets.  register_code_fragment
// only *nulls* next_free_fragment while zeroing a recycled slab node; it never
// links a fragment onto a list.
struct CodeFragmentFreeList
{
  os_unfair_lock lock;
  uint32_t lock_pad;
  CodeFragmentMetadata *_head;
  CodeFragmentMetadata *_tail;

  // The original also has CodeFragmentFreeList::push_back (0x78F4), defined in
  // CodeFragmentMetadata.cpp — where its asserts report it.  Not recovered:
  // nothing on the allocate_chunk path calls it.
};

static_assert(sizeof(CodeFragmentFreeList) == 0x18);
static_assert(offsetof(CodeFragmentFreeList, lock) == 0x00);
static_assert(offsetof(CodeFragmentFreeList, lock_pad) == 0x04);
static_assert(offsetof(CodeFragmentFreeList, _head) == 0x08);
static_assert(offsetof(CodeFragmentFreeList, _tail) == 0x10);
