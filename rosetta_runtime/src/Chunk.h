#pragma once

#include <cstddef>
#include <cstdint>

// One contiguous span of the executable heap, singly linked through `next`.
// Chained from ExecutableHeap::chunk_list.
// ExecutableHeap::allocate_chunk creates one covering [heap_base+0x4000, heap_base+0x8000000)
// and prepends it to chunk_list; ExecutableHeap::allocate calls it again on
// exhaustion, so the list can hold several.  runtime_routines_for_address walks
// it to map an address back to its span.
//
// The original calls these "chunk"s:
//   STRING "allocating ExecutableHeap chunk:\n"   (logged by ExecutableHeap::allocate_chunk)
//   ASSERT "chunk != nullptr"                     (walking this list in
//                                                  ExecutableHeap::runtime_routines_for_address)
// Both name the *variable* rather than the type, so `Chunk` is the best available
// reading rather than a recovered type name.
#pragma pack(push, 2)
struct Chunk
{
  uint64_t base;
  uint32_t size;
  uint32_t pad;
  Chunk *next;
};
#pragma pack(pop)

static_assert(sizeof(Chunk) == 0x18);
static_assert(offsetof(Chunk, base) == 0x00);
static_assert(offsetof(Chunk, size) == 0x08);
static_assert(offsetof(Chunk, pad) == 0x0C);
static_assert(offsetof(Chunk, next) == 0x10);
