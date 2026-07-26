#include "SlabAllocator.h"

#include <mach/vm_statistics.h>
#include <sys/mman.h>

constexpr uint32_t kSlabPageSize = 0x1000;
constexpr int kSlabVmTag = 0xE6;

static void *mmap_anonymous_rw(uint32_t size, int vm_tag) {
    return mmap(nullptr, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, VM_MAKE_TAG(vm_tag), 0);
}

static void list_remove(SlabPage *page, void **head_ptr) {
    auto *next = page->next;
    auto *prev = page->prev;
    if (prev)
        prev->next = next;
    else
        *head_ptr = next;
    if (next)
        next->prev = prev;
    page->next = nullptr;
    page->prev = nullptr;
}

static void list_prepend(SlabPage *page, void **head_ptr) {
    page->next = nullptr;
    page->prev = nullptr;
    auto *old_head = static_cast<SlabPage *>(*head_ptr);
    page->next = old_head;
    if (old_head)
        old_head->prev = page;
    *head_ptr = page;
}

static void init_slab_page(SlabAllocator *alloc, SlabPage *page) {
    auto *node = reinterpret_cast<char *>(page) + alloc->first_node_offset;
    page->free_head = node;

    uint32_t count = alloc->nodes_per_page;
    for (uint32_t i = 1; i < count; i++) {
        auto *next = node + alloc->node_stride;
        *reinterpret_cast<void **>(node) = next;
        node = next;
    }
    *reinterpret_cast<void **>(node) = nullptr;
    page->free_count = count;
}

static void *allocate_from_partial(SlabAllocator *alloc, SlabPage *slab) {
    auto *result = slab->free_head;
    slab->free_head = *static_cast<void **>(result);
    slab->free_count--;

    if (slab->free_count == 0) {
        list_remove(slab, &alloc->partial_slabs);
        list_prepend(slab, &alloc->full_slabs);
    }

    return result;
}

void *SlabAllocator::alloc() {
    auto *slab = static_cast<SlabPage *>(partial_slabs);

    if (!slab) {
        slab = static_cast<SlabPage *>(empty_slabs);
        if (slab) {
            list_remove(slab, &empty_slabs);
        } else {
            slab = static_cast<SlabPage *>(mmap_anonymous_rw(kSlabPageSize, kSlabVmTag));
            init_slab_page(this, slab);
        }
        list_prepend(slab, &partial_slabs);
    }

    return allocate_from_partial(this, slab);
}

static uint32_t count_list(void *head) {
    uint32_t n = 0;
    for (auto *p = static_cast<SlabPage *>(head); p; p = p->next)
        n++;
    return n;
}

void SlabAllocator::free(void *node) {
    auto *slab = reinterpret_cast<SlabPage *>(
        page_mask & reinterpret_cast<uintptr_t>(node));

    uint32_t old_free_count = slab->free_count;

    *static_cast<void **>(node) = slab->free_head;
    slab->free_head = node;
    slab->free_count = old_free_count + 1;

    if (old_free_count == 0) {
        list_remove(slab, &full_slabs);
        list_prepend(slab, &partial_slabs);
    } else if (old_free_count + 1 == nodes_per_page) {
        list_remove(slab, &partial_slabs);
        if (count_list(empty_slabs) <= 1) {
            list_prepend(slab, &empty_slabs);
        } else {
            munmap(slab, kSlabPageSize);
        }
    }
}

void *LockedSlabAllocator::locked_alloc(uint32_t self) {
    os_unfair_lock_lock_no_tsd(&lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION, self);
    void *node = allocator.alloc();
    os_unfair_lock_unlock_no_tsd(&lock, self);
    return node;
}

void LockedSlabAllocator::locked_free(void *node, uint32_t self) {
    os_unfair_lock_lock_no_tsd(&lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION, self);
    allocator.free(node);
    os_unfair_lock_unlock_no_tsd(&lock, self);
}
