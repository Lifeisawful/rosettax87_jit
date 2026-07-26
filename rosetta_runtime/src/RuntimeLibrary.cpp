#include "RuntimeLibrary.h"

#include "Export.h"
#include "RuntimeOffsets.h"
#include "Log.h"
#include "RuntimeConfig.h"

#include "ExecutableHeap.h"
#include "RuntimeRoutineOffsets.h"
#include "TranslationCacheAbi.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/RosettaCore.h"
#include "rosetta_core/RuntimeLibC.h"

// Early init, called by the loader on the stopped thread BEFORE the Rosetta
// runtime's main() runs — see the "Early phase" comment in rosetta_loader.
//
// Only work that depends on loader-written __DATA belongs here.  kImports is
// still zeroed at this point (libRosettaRuntime is not mapped until main()
// reaches 0x12708), so anything reading it — exportsInit, orig_*, the version
// banner, rosetta_core_init — must stay in init_library below.
//
// The payoff is executable_heap_init: main() builds the first heap chunk at
// 0x12620, well before exports_fetch, so hooking allocate_chunk from
// init_library was always too late and chunk 0 belonged to the reference.
void runtime_early_init() {
    rosetta_set_config(&kConfig);

    uintptr_t classify_arm_pc_ptr = kOffsets.runtime_base + kOffsets.classify_arm_pc_rva;
    // Both live in the runtime image (/usr/libexec/rosetta/runtime), not in
    // libRosettaRuntime — same base as classify_arm_pc above.
    uintptr_t runtime_routines_for_address_ptr =
        kOffsets.runtime_base + kOffsets.runtime_routines_for_address_rva;
    uintptr_t allocate_chunk_ptr = kOffsets.runtime_base + kOffsets.allocate_chunk_rva;
    // Guard the zero case explicitly: a 0 rva would otherwise yield runtime_base,
    // i.e. a valid-looking but wrong function pointer.
    uintptr_t trace_write_mapping_record_ptr =
        kOffsets.trace_write_mapping_record_rva
            ? kOffsets.runtime_base + kOffsets.trace_write_mapping_record_rva
            : 0;

    // Install the classify_arm_pc replacement.  The mapped stub page is located
    // via arm_tree at classify time, so only our library image's bounds are
    // passed here.
    TranslationCacheAbi::init(classify_arm_pc_ptr, kOffsets.rosettax87_base,
                              kOffsets.rosettax87_size);

    // Take over heap chunk allocation and the runtime-routines base lookup,
    // before the first chunk exists.
    executable_heap_init(allocate_chunk_ptr, runtime_routines_for_address_ptr,
                         trace_write_mapping_record_ptr);
}

void* init_library(SymbolList const* a1, uint64_t stack_cookie, ThreadContextOffsets const* a3) {
    exportsInit();

    printf("RosettaRuntimex87 built %s - Rosetta Version 0x%llx\n", __DATE__ " " __TIME__, (unsigned long long)kImports.version);

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
