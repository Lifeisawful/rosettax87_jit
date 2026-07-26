#pragma once

#include <cstdint>

// Rewrites the runtime-routine offset table the reference computed for its own
// runtime_entry blob so that every entry points at the corresponding stub in
// OURS.  Called from the register_runtime_routine_offsets hook.
//
// `offsets` is the caller's array and `count` its length — always loop on
// `count`, never on kRuntimeRoutine_MAX (this runtime build passes 0x62, which is
// fewer than the 0x64 routines we have stubs for).
void rewrite_runtime_routine_offsets(intptr_t* offsets, int32_t count);
