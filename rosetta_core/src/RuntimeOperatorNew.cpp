#ifdef ROSETTA_RUNTIME

#include <cstddef>

#include "rosetta_core/RuntimeLibC.h"

void* operator new(size_t size) {
    size_t total = size + sizeof(size_t);
    auto* p = static_cast<size_t*>(rt_calloc(1, total));
    if (!p)
        rt_assert_fail("operator new: allocation failed", __FILE__, __LINE__);
    *p = total;
    return p + 1;
}

void* operator new[](size_t size) {
    size_t total = size + sizeof(size_t);
    auto* p = static_cast<size_t*>(rt_calloc(1, total));
    if (!p)
        rt_assert_fail("operator new[]: allocation failed", __FILE__, __LINE__);
    *p = total;
    return p + 1;
}

void operator delete(void* ptr) noexcept {
    if (!ptr)
        return;
    size_t* p = static_cast<size_t*>(ptr) - 1;
    rt_munmap(p, *p);
}

void operator delete[](void* ptr) noexcept {
    if (!ptr)
        return;
    size_t* p = static_cast<size_t*>(ptr) - 1;
    rt_munmap(p, *p);
}

void operator delete(void* ptr, size_t) noexcept {
    if (!ptr)
        return;
    size_t* p = static_cast<size_t*>(ptr) - 1;
    rt_munmap(p, *p);
}

void operator delete[](void* ptr, size_t) noexcept {
    if (!ptr)
        return;
    size_t* p = static_cast<size_t*>(ptr) - 1;
    rt_munmap(p, *p);
}

#endif  // ROSETTA_RUNTIME
