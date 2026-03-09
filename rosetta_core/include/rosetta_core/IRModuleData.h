#pragma once

#include <cstdint>

struct IRModuleData {
    uint64_t text_vmaddr_range;
    uint64_t max_pc_seen;
    //   IRBlockVec ir_blocks;
    //   IRInstrVec ir_instr;
    //   uint64_t field_40;
};
