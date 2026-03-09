#pragma once

#include <cstddef>
#include <cstdint>

#pragma pack(push, 1)
struct X87Float80 {
    union {
        struct {
            uint64_t mantissa;
            uint16_t exponent;
        };
        uint8_t bytes[10];
        double ieee754;  // 64 bits
    };
};
#pragma pack(pop)

static_assert(sizeof(X87Float80) == 0x0A, "Invalid size for X87Float80");
static_assert(offsetof(X87Float80, mantissa) == 0, "Invalid offset for X87Float80::mantissa");
static_assert(offsetof(X87Float80, exponent) == 8, "Invalid offset for X87Float80::exponent");
static_assert(offsetof(X87Float80, ieee754) == 0, "Invalid offset for X87Float80::ieee754");
