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
};

static_assert(sizeof(Offsets) == 0x58, "Invalid size for Offsets");
