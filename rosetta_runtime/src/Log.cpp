#include "Log.h"

#include <cmath>

auto syscallWrite(int fd, const char* buf, uint64_t count) -> uint64_t {
    register uint64_t x0 __asm__("x0") = fd;
    register uint64_t x1 __asm__("x1") = (uint64_t)buf;
    register uint64_t x2 __asm__("x2") = count;
    register uint64_t x16 __asm__("x16") = 397;  // SYS_write_nocancel

    asm volatile(
        "svc #0x80\n"
        "mov x1, #-1\n"
        "csel x0, x1, x0, cs\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x16)
        : "memory");

    return x0;
}
