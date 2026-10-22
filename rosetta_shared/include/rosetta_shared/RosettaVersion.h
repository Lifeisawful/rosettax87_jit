#pragma once

#include <cstdint>

// libRosettaRuntime's Exports.version (field 0 of its __DATA,exports struct),
// which the loader reads off disk and seeds into our kImports.version. It is the
// one version token both halves agree on, and rosetta_core_runtime_version()
// returns it.
//
// Observed values:
//   macOS 15.8.1 (24H32)   0x15D0000000000   /usr/libexec/rosetta/runtime sha1 4320d492
//   macOS 26.4             > kVersion_15     runtime sha1 1d40e18e
//   macOS 26.5b4           > kVersion_15     runtime sha1 95336828
//   macOS 27 beta3 / 27.0  > kVersion_15     runtime sha1 cac83ff2 / a251fe54
//
// The 15-era runtime is the odd one out, not 27: two ExecutableHeap ABI changes
// landed by 26.4 at the latest and have been stable since (verified in IDA across
// 26.4, 26.5b4 and 27.b3 — same `allocate_chunk` signature, same heap global
// address, same field offsets). So every version split we need here is a single
// two-way test against this constant, not a per-release ladder:
//
//   1. ExecutableHeap::allocate_chunk lost its `this`.
//        <= kVersion_15:  x0 = ExecutableHeap*, w1 = lock_owner
//        >  kVersion_15:  x0 = lock_owner, and the heap is a global whose address
//                         the loader decodes out of allocate_chunk's body and
//                         passes in Offsets::executable_heap_rva.
//   2. ExecutableHeap gained an 8-byte slot at offset 0x5C0, shifting every field
//      from there on by +8 — so mach_port moved 0x5E0 -> 0x5E8 (see
//      ExecutableHeap.h).
inline constexpr uint64_t kVersion_15 = 0x15D0000000000;

// True when the runtime is 26.4-or-newer, i.e. uses the global-heap
// allocate_chunk ABI and the +8-shifted tail of ExecutableHeap.
//
// A version of 0 reads as "15": the loader always seeds the real value before our
// _start runs, so 0 can only mean the seeding itself failed, and the 15 layout is
// the conservative guess on the Mac this is developed against.
inline constexpr bool rosetta_heap_is_global(uint64_t runtime_version) {
    return runtime_version > kVersion_15;
}
