#pragma once

#include <cstddef>
#include <cstdint>

// Descriptor for one open-addressed translation hash table: `entries` points at
// 0x10 << log2_capacity bytes of 0x10-byte slots.  Threads cache the current
// descriptor in ThreadContext+0x198, so a resize can publish a new table
// without walking every thread.
#pragma pack(push, 2)
struct HashTableDesc
{
  void *entries;
  uint32_t log2_capacity;
  uint32_t config_hi;
};
#pragma pack(pop)

static_assert(sizeof(HashTableDesc) == 0x10);
static_assert(offsetof(HashTableDesc, entries) == 0x00);
static_assert(offsetof(HashTableDesc, log2_capacity) == 0x08);
static_assert(offsetof(HashTableDesc, config_hi) == 0x0C);

// 00000000 #pragma pack(push, 2)
// 00000000 struct HashTableDesc // sizeof=0x10
// 00000000 {                                       // XREF: TranslationCache.inline_desc/r
// 00000000     void *entries;                      // XREF: ensure_aot_cache_initialized+38/w
// 00000000                                         // main+814/w
// 00000008     uint32_t log2_capacity;
// 0000000C     uint32_t config_hi;
// 00000010 };
// 00000010 #pragma pack(pop)
