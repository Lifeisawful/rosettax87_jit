#pragma once

#include <cstddef>
#include <cstdint>

#pragma pack(push, 1)
struct X87StackRegister {
    double ieee754;  // 64 bits
};
#pragma pack(pop)

static_assert(sizeof(X87StackRegister) == 0x08, "Invalid size for X87StackRegister");
static_assert(offsetof(X87StackRegister, ieee754) == 0,
              "Invalid offset for X87StackRegister::ieee754");
