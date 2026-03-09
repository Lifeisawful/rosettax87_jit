#pragma once

struct Exports {
    uint64_t version;  // 0x16A0000000000
    uint64_t x87Exports;
    uint64_t x87ExportCount;
    uint64_t runtimeExports;
    uint64_t runtimeExportCount;
};

struct Export {
    uint64_t address;
    uint64_t name;
};

struct Offsets {
    uint64_t init_library_rva;  // used to calculate base address of libRosettaRuntime from exports
                                // address
    uint64_t translate_insn_addr;
    uint64_t transaction_result_size_addr;
};

static_assert(sizeof(Offsets) == 0x18, "Invalid size for Offsets");
