#pragma once

#include <cstdint>

// rosetta_loader writes these offsets into the library at runtime
struct Offsets {
    uint64_t init_library_rva;  // used to calculate base address of libRosettaRuntime from exports
                                // address
    uint64_t translate_insn_addr;
    uint64_t transaction_result_size_addr;
};

static_assert(sizeof(Offsets) == 0x18, "Invalid size for Offsets");

extern Offsets kOffsets;
