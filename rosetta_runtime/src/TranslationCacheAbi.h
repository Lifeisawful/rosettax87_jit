#pragma once

#include <cstddef>
#include <cstdint>

#include "rosetta_core/AbiInfo.h"

// TranslationCacheAbi.cpp — recovers an AbiInfo for an arbitrary ARM pc.
//
// The file name is the binary's own (STRING "TranslationCacheAbi.cpp", cited by
// every assert in classify_arm_pc / abi_info_for_runtime /
// abi_info_for_runtime_routines_address).
//
// CLASS NAME INFERRED.  The asserts pass the function names *unqualified*
// ("classify_arm_pc" at 0xB8CC, "abi_info_for_runtime_routines_address" at
// 0xB6D4) and none of the three takes a `this`, so the binary is equally
// consistent with free functions in this translation unit.  We group them under
// a static class because they share one concern; the grouping is ours.
//
// ── Why we reimplement this at all ────────────────────────────────────────────
//
// The reference classify_arm_pc (0xB6FC) resolves a pc inside the RuntimeRoutines
// fragment by converting it to a *file* address:
//
//     offset = pc - fragment->arm_base          (0xB7B8)
//     ASSERT(offset < kRuntimeRoutinesSize)     (0xB878, hard trap at 0xB8CC)
//     file_pc = stub_far_jmp + offset           (0xB88C)
//
// then classifies file_pc against landmarks in the *reference* runtime_entry
// blob (runtime_savedreg, stub_branch_slot, the six exit trampolines,
// sa_tramp_handler, runtime_syscall...).
//
// We map our OWN runtime_entry.S over that region, so those landmarks describe a
// different binary.  Both failure modes are unacceptable:
//   - a pc past our blob's first 0x4000 bytes traps at 0xB8CC;
//   - a pc inside it silently classifies against the wrong landmark table.
//
// The second is the dangerous one.  AbiKind drives signal delivery: sa_tramp
// (0x1BD74) uses ExitTrampoline0..5 + subkind to decide whether a signal may be
// delivered *now* or must be deferred because a runtime_exit* path is midway
// through restoring guest GPRs.  A misclassification there delivers a signal on
// half-restored state.
//
// So we classify pcs inside our own region against our own labels, and delegate
// everything else — JIT'd guest code, the translator image, library ranges — to
// the original.
class TranslationCacheAbi {
   public:
    // Installs the hook over the reference classify_arm_pc and records the bounds
    // of our own loaded library image.  Called from init_library.
    //
    // No bounds are needed for the *mapped stub page*: that region is found by
    // walking ExecutableHeap::arm_tree, so additional heap chunks (each with
    // their own RuntimeRoutines fragment) are handled automatically.  The
    // rosettax87_* pair describes the separate, dyld-loaded library image.
    static void init(uintptr_t classify_arm_pc_addr, uintptr_t rosettax87_base,
                     size_t rosettax87_size);

    // Replacement for classify_arm_pc (0xB6FC).  Classifies two regions itself —
    // the mapped runtime_entry page (found via arm_tree, kind RuntimeRoutines or
    // InvalidRuntimeRoutines) and our own library image — and forwards everything
    // else to the original.
    static void classify_arm_pc(AbiInfo* result, uint32_t thread_port, uintptr_t arm_pc);

    // Replacement for abi_info_for_runtime_routines_address (0xB230).  Takes an
    // offset into our blob rather than a rebased file address — the rebasing at
    // 0xB88C is exactly what we are removing.
    static void abi_info_for_runtime_routines_address(AbiInfo* result, uintptr_t offset);
};
