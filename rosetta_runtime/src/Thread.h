#pragma once

#include <cstddef>
#include <cstdint>

// Thread.cpp — the runtime's global thread registry.
//
// The file name and the three named fields below are the binary's own: every
// assert in register_mach_thread (0x1319C), register_runtime_mach_thread
// (0x132C0), create_from_mach_thread (0x133F4) and is_valid_x86_thread (0x9680)
// cites "Thread.cpp" and spells the fields "thread->thread_id",
// "thread->context", "thread->is_runtime_thread".  The remaining three are
// [inferred] from control flow.
//
// We do not own any of this.  The one entry point we call is
// thread_entry_for_port (0x96E4), through a pointer supplied by the loader; the
// layout is documented here because its out-parameter contract depends on it.

struct ThreadContext;

// One registry entry.  Entries are never removed — a reclaimed slot is zeroed
// and reused, and the count only grows.
struct Thread {
    uint32_t thread_id;         // 0x00  mach_port_t; 0 marks a free slot
    uint32_t pad_04;            // 0x04  never read
    ThreadContext* context;     // 0x08  nullptr for runtime threads
    uint8_t is_runtime_thread;  // 0x10  [confirmed] "!thread->is_runtime_thread"
    uint8_t is_dead_name;       // 0x11  [inferred] port became a dead name, awaiting reclaim
    uint8_t suspended_by_stw;   // 0x12  [inferred] suspended by the current stop-the-world
    uint8_t pad_13[5];          // 0x13
    uint64_t retire_epoch;      // 0x18  [inferred] global epoch stamped when marked dead
};

static_assert(sizeof(Thread) == 0x20);
static_assert(offsetof(Thread, context) == 0x08);
static_assert(offsetof(Thread, is_runtime_thread) == 0x10);
static_assert(offsetof(Thread, retire_epoch) == 0x18);

// thread_entry_for_port's out-parameter.  It writes 0x21 bytes:
//
//   hit  — the whole 0x20-byte Thread is copied, then found = 1
//   miss — ONLY thread.thread_id = 0 and found = 0 are written
//
// So `found` must be tested before any other field: on a miss
// thread.is_runtime_thread is left exactly as the caller left it.  The reference
// tests both together at 0x16128 for precisely this reason.
struct ThreadLookupResult {
    Thread thread;  // 0x00
    uint8_t found;  // 0x20
};

static_assert(offsetof(ThreadLookupResult, found) == 0x20);

// The container, `g_threads` at 0x3B240 (0x38 bytes), for reference only — we
// never touch it, because thread_entry_for_port does all the locking and the
// scan for us.  IDA had it typed as a LockedSlabAllocator, which is wrong: that
// type puts the lock at +0x30, and the real object locks at +0x00.
//
//   +0x00  os_unfair_lock lock           protects entries/count/capacity and every entry field
//   +0x08  Thread*        entries        mmap_anonymous_rw, VM tag 0xE6
//   +0x10  uint64         count          grows only; freed slots are reused, never removed
//   +0x18  uint64         capacity       init 0x80 (0x1000/0x20), doubles via mmap+memmove+munmap
//   +0x20  os_unfair_lock stw_lock       held for the duration of a stop-the-world
//   +0x24  uint8          stw_depth      nesting count; 0->1 suspends, 1->0 resumes
//   +0x28  uint64         epoch          atomic relaxed fetch_add; ERROR("epoch overflow")
//   +0x30  uint64         reclaim_epoch  min over live x86 threads of ThreadContext[+0x1B8]
//
// All six are initialised as one block in main at 0x1291C-0x1293C.
