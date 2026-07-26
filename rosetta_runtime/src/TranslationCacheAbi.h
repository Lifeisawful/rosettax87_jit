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
//
// Only the init entry point is public.  The classify_arm_pc replacement and its
// abi_info_for_runtime_routines_address helper are file-local (anonymous
// namespace) in TranslationCacheAbi.cpp — nothing outside the hook calls them.

// ── classify_arm_pc_objc ─────────────────────────────────────────────────────
//
// The runtime carries a SECOND copy of the runtime-routines classification, in
// classify_arm_pc_objc (0x15FC0), reached through ThreadContext vtable slot
// +0xF8 rather than by a call to classify_arm_pc.  Hooking classify_arm_pc
// therefore does nothing for it, and it repeats the same
// `ASSERT(offset < kRuntimeRoutinesSize)` at 0x16194 — which our 0x4E7C-byte
// blob fails for everything from runtime_syscall (blob offset 0x4020) onward.
//
// It exists to serve libobjc's restartable ranges: the guest registers x86
// ranges via MIG msgid 0x1F40, the kernel cannot police them under translation,
// so the guest asks Rosetta for a given thread's x86 pc.
//
// Hooked separately from init_translation_cache_abi_hooks because it is reached
// through the vtable rather than found by a byte pattern, and the vtable pointer
// only exists once X18 is live — i.e. from a library export called by main, not
// from our _start.  See RuntimeLibrary.cpp.
struct ThreadContextVTable;

void init_classify_arm_pc_objc_hook(const ThreadContextVTable* vtable);

// Installs the hook over the reference classify_arm_pc and records the bounds of
// our own loaded library image.  Called from runtime_early_init.
//
// No bounds are needed for the *mapped stub page*: that region is found by
// walking ExecutableHeap::arm_tree, so additional heap chunks (each with their
// own RuntimeRoutines fragment) are handled automatically.  The rosettax87_* pair
// describes the separate, dyld-loaded library image.
void init_translation_cache_abi_hooks(uintptr_t classify_arm_pc_addr, uintptr_t rosettax87_base,
                                      size_t rosettax87_size);
