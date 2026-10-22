#pragma once

#include <cstdint>

// Layout shared between rosetta_loader (which writes these offsets into
// libRosettaRuntime at runtime) and rosetta_runtime (which reads them). Keep the
// layout in sync — the static_assert guards the ABI.
struct Offsets {
    uint64_t init_library_rva;  // used to calculate base address of libRosettaRuntime from exports
                                // address
    uint64_t translate_insn_addr;
    uint64_t transaction_result_size_addr;
    uint64_t runtime_base;
    uint64_t rosettax87_base;
    uint64_t rosettax87_size;
    uint64_t classify_arm_pc_rva;  // classify_arm_pc offset within libRosettaRuntime
    uint64_t decode_opcode_rva;    // decode_opcode offset within libRosettaRuntime
    uint64_t runtime_routines_for_address_rva;  // ExecutableHeap::runtime_routines_for_address,
                                                // offset within the runtime image
    uint64_t allocate_chunk_rva;   // ExecutableHeap::allocate_chunk, offset within the runtime image
    uint64_t trace_write_mapping_record_rva;  // trace_write_mapping_record, offset within the
                                              // runtime image
    uint64_t bind_library_stubs_rva;  // bind_library_stubs, offset within the runtime image

    // The three helpers the full classify_arm_pc_objc replacement calls. All are
    // internal (non-exported) functions in the RUNTIME image, so these are
    // offsets from runtime_base — not from the libRosettaRuntime base that
    // init_library_rva is relative to. See TranslationCacheAbi.h.
    uint64_t abi_info_for_runtime_rva;
    uint64_t thread_entry_for_port_rva;
    uint64_t instruction_extents_for_arm_address_rva;

    // Address of the runtime's ExecutableHeap global, as an offset within the
    // runtime image (0x3B510 on every 26.4+ build seen so far). Needed only when
    // rosetta_heap_is_global(version): on those runtimes allocate_chunk no longer
    // receives the heap as an argument, so this is the only way to reach it. The
    // loader decodes it from the ADRP/ADD pair inside allocate_chunk itself; 0 on
    // a <= 15 runtime, where it is unused. See RosettaVersion.h.
    uint64_t executable_heap_rva;
};

static_assert(sizeof(Offsets) == 0x80, "Invalid size for Offsets");
