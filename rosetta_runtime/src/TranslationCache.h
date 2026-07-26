#pragma once

#include <cstddef>
#include <cstdint>

#include "HashTableDesc.h"
#include "Lock.h"

// Guest-PC → translation hash table.  ExecutableHeap holds two: aot_cache
// (heap+0x80, built lazily by ensure_aot_cache_initialized) and jit_cache
// (heap+0x2A0, built eagerly in main).  Both start at log2_capacity 0xB
// (2048 slots x 0x10 bytes = 0x8000).
//
// UNVERIFIED — reclaim_retired_hash_tables (0x92FC) contradicts the field names
// below.  It walks a ring: index [+0x04] up to [+0x08], munmapping
// desc[i].entries (0x10 << log2_capacity) while the u64 at +0x170 + 8*i is
// older than the passed epoch.  That implies +0x04/+0x08 are ring head/tail
// indices rather than lock_pad/state, that +0x20 is an array of HashTableDesc
// (inline_desc == desc[0]) rather than a single one, and that +0x170 is a
// parallel epoch array carved out of inline_entries.  Left as-is pending a
// dedicated pass; only the size and the fields used so far are trustworthy.
#pragma pack(push, 2)
struct TranslationCache
{
  os_unfair_lock lock;
  uint32_t lock_pad;
  uint32_t state;
  uint32_t state_pad;
  HashTableDesc *current_desc;
  uint64_t field_18;
  HashTableDesc inline_desc;
  uint8_t inline_entries[496];
};
#pragma pack(pop)

static_assert(sizeof(TranslationCache) == 0x220);
static_assert(offsetof(TranslationCache, lock) == 0x00);
static_assert(offsetof(TranslationCache, lock_pad) == 0x04);
static_assert(offsetof(TranslationCache, state) == 0x08);
static_assert(offsetof(TranslationCache, state_pad) == 0x0C);
static_assert(offsetof(TranslationCache, current_desc) == 0x10);
static_assert(offsetof(TranslationCache, field_18) == 0x18);
static_assert(offsetof(TranslationCache, inline_desc) == 0x20);
static_assert(offsetof(TranslationCache, inline_entries) == 0x30);

// 00000000 #pragma pack(push, 2)
// 00000000 struct TranslationCache // sizeof=0x220
// 00000000 {                                       // XREF: ExecutableHeap.aot_cache/r
// 00000000                                         // ExecutableHeap.jit_cache/r
// 00000000     os_unfair_lock lock;                // XREF: ensure_aot_cache_initialized+3C/w
// 00000000                                         // main+818/w
// 00000004     uint32_t lock_pad;                  // (ring head? see note above)
// 00000008     uint32_t state;                     // XREF: ensure_aot_cache_initialized+40/w
// 00000008                                         // main+81C/w   (ring tail? see note above)
// 0000000C     uint32_t state_pad;
// 00000010     HashTableDesc *current_desc;        // XREF: ThreadContext_init+128/o
// 00000010                                         // ThreadContext_init+134/o ...
// 00000018     uint64_t field_18;
// 00000020     HashTableDesc inline_desc;          // XREF: ensure_aot_cache_initialized+2C/o
// 00000020                                         // ensure_aot_cache_initialized+38/w ...
// 00000030     uint8_t inline_entries[496];
// 00000220 };
// 00000220 #pragma pack(pop)
