#include "Offsets.h"

__attribute__((section("__DATA,offsets"), used)) Offsets kOffsets = {
    0x0,  // exports_rva (filled in by loader)
    0x0,  // translate_insn_addr (filled in by loader)
    0x0,  // transaction_result_size_addr (filled in by loader)
};
