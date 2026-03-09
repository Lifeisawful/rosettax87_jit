#pragma once

#include <cstdint>

struct AssemblerBuffer {
    uint32_t* data;     // +0x00: pointer to buffer
    uint64_t end;       // +0x08: byte offset of next write position
    uint64_t end_cap;   // +0x10: byte offset of end of allocated capacity
    uint32_t use_heap;  // +0x18: non-zero = calloc/heap, zero = mmap

    void emit(uint32_t value) {
        if (this->end + 4 >= this->end_cap)
            grow();
        *(uint32_t*)((uint8_t*)this->data + this->end) = value;
        this->end += 4;
    }

    void grow();
};