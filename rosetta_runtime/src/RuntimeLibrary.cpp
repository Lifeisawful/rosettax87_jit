#include "RuntimeLibrary.h"

#include "Export.h"
#include "RuntimeConfig.h"
#include "RuntimeOffsets.h"
#include "Log.h"

#include "RuntimeRoutineOffsets.h"

#include "rosetta_core/RosettaCore.h"
#include "rosetta_core/RuntimeLibC.h"
#include "rosetta_core/ThreadContextOffsets.h"

void* init_library(SymbolList const* a1, uint64_t stack_cookie, ThreadContextOffsets const* a3) {
    printf("RosettaRuntimex87 built %s - Rosetta Version 0x%llx\n", __DATE__ " " __TIME__, (unsigned long long)kImports.version);

    // The FCOS fast path (runtime_entry.S _stub_fcos_fast) addresses the
    // X87State at a baked-in x18+0xA0.  If a Rosetta update ever moves it,
    // route FCOS back to the classic stub (rewrite_runtime_routine_offsets
    // reads this flag when it builds the offset table, which happens after
    // library init) and say so loudly — a silently wrong offset would corrupt
    // guest floats.
    if (a3 && a3->x87_state_offset != 0xA0) {
        printf(
            "RosettaRuntimex87: WARNING x87_state_offset is 0x%x, expected 0xA0 — "
            "disabling the FCOS fast path\n",
            a3->x87_state_offset);
        kConfig.disable_fcos_fast = 1;
    }

    uintptr_t runtime_library_base =
        reinterpret_cast<uintptr_t>(orig_init_library) - kOffsets.init_library_rva;
    uintptr_t translation_ptr = runtime_library_base + kOffsets.translate_insn_addr;
    uintptr_t transaction_result_size_addr =
        runtime_library_base + kOffsets.transaction_result_size_addr;
    uintptr_t decode_opcode_ptr = runtime_library_base + kOffsets.decode_opcode_rva;

    rosetta_core_init({
        .runtime_version = kImports.version,
        .translate_insn_addr = translation_ptr,
        .transaction_result_size_addr = transaction_result_size_addr,
        .decode_opcode_addr = decode_opcode_ptr,
        .default_free_gpr_mask_addr = 0,
    });

    return orig_init_library(a1, stack_cookie, a3);
}

void register_runtime_routine_offsets(intptr_t* runtime_routine_offsets, const char** runtime_routine_names, int32_t count) {
    // main() (0x1299C-0x129C4) has already filled this array with offsets into
    // the REFERENCE blob:
    //   for (i = 0; i != 0x62; ++i)
    //       g_runtime_routine_offsets[i] = g_rt_branch_slot[i] - stub_far_jmp;
    //
    // We map our own runtime_entry over the stub page, so those deltas all point
    // at the wrong stub.  Recompute them against our labels before handing the
    // array on — this is what makes our stubs actually reachable.
    rewrite_runtime_routine_offsets(runtime_routine_offsets, count);

    orig_register_runtime_routine_offsets(runtime_routine_offsets, runtime_routine_names, count);
}
