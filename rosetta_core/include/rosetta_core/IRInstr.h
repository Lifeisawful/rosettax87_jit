#pragma once

#include <cstdint>

#include "rosetta_core/IROperand.h"

struct IRInstr {
    uint32_t pc;
    uint16_t opcode;
    uint8_t rep_prefix;
    uint8_t flag_liveness;
    uint8_t _pad08;
    uint8_t rex_escape;
    uint8_t num_operands;
    uint8_t ir_kind;
    uint8_t ir_subkind;
    __attribute__((packed)) __attribute__((aligned(1))) uint16_t aux_opcode;
    char field_F;
    IROperand operands[4];
};
