#include "rosetta_core/AssemblerBuffer.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

void* mmap_anonymous_rw(size_t size, int tag) {
    void* result;  // x0

    result = mmap((void*)0x100000000LL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                  tag << 0x18, 0);
    return result;
}

void AssemblerBuffer::grow() {
    // Double capacity, or start at 0x4000 bytes if currently empty
    uint64_t new_cap = (this->end_cap == 0) ? 0x4000 : this->end_cap * 2;

    uint32_t* new_data;
    if (this->use_heap) {
        new_data = (uint32_t*)calloc(1, new_cap);
    } else {
        // Original uses flags 0xE6 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT (macOS)
        new_data = (uint32_t*)mmap_anonymous_rw(new_cap, 0xE6);
        if (new_data == MAP_FAILED)
            return;
    }

    // Copy existing contents (memcpy size is end_cap, not end)
    if (this->data)
        memcpy(new_data, this->data, this->end_cap);

    // Free old buffer only if mmap-backed
    if (!this->use_heap && this->data)
        munmap(this->data, this->end_cap);

    this->data = new_data;
    this->end_cap = new_cap;
}