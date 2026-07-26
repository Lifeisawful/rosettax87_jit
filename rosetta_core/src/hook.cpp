#include "rosetta_core/hook.h"

#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/mman.h>

#include <cstdio>
#include <cstring>

#include "rosetta_core/CoreLog.h"

// Must come AFTER system headers so #define aliases override system macros
// without interfering with system header declarations.
#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

#define PATCH_SIZE 16u
#define AARCH64_PAGE_SIZE 16384u

// A Rosetta-translated process has 4 KB VM granularity, not the 16 KB of native
// arm64 — `vmmap` on the guest shows independent 4 KB regions.  So rounding a
// patch target down to 16 KB and vm_protect'ing 16 KB spans up to FOUR unrelated
// VM regions and silently re-protects the three neighbours.
//
// That is exactly how `make_page_executable(tramp)` used to corrupt the
// executable heap: mmap hands back 4 KB-aligned (not 16 KB-aligned) trampolines,
// so the 16 KB blast radius reached backwards into the preceding 4 KB pages —
// which is where ExecutableHeap's SlabAllocator keeps its 4 KB metadata pages
// (kSlabPageSize == 0x1000).  The Chunk and FreeBlock that allocate_chunk puts
// on the first slab page became r-x, and the next JIT allocation that split a
// free block took a write fault on `node->base_address += size` inside
// BestFitAllocator::allocate_from_node.
//
// Always protect exactly the granule-aligned range covering [addr, addr + len).
#define VM_GRANULE 4096u

static kern_return_t protect_covering(const void* addr, size_t len, vm_prot_t prot) {
    const vm_address_t a = (vm_address_t)addr;
    const vm_address_t start = a & ~((vm_address_t)VM_GRANULE - 1);
    const vm_address_t end = (a + len + VM_GRANULE - 1) & ~((vm_address_t)VM_GRANULE - 1);
    return vm_protect(mach_task_self(), start, end - start, FALSE, prot);
}

static void write_abs_jump(void* dst, const void* target) {
    uint32_t ldr_x9 = 0x58000049u;  // LDR X9, #8
    uint32_t br_x9 = 0xD61F0120u;   // BR  X9
    uint8_t* p = (uint8_t*)dst;
    memcpy(p + 0, &ldr_x9, 4);
    memcpy(p + 4, &br_x9, 4);
    memcpy(p + 8, &target, 8);
}

static void flush_cache(void* addr, size_t len) {
    sys_dcache_flush(addr, len);
    sys_icache_invalidate(addr, len);
}

int make_page_executable(void* addr) {
    // One granule only: callers pass an mmap base whose live contents are a few
    // dozen bytes, and widening past that is what reached into foreign pages.
    auto kr = protect_covering(addr, 1, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("make_page_executable: vm_protect failed");
        return -1;
    }
    return 0;
}

int hook_install(void* target, void* hook_fn, void** trampoline) {
    if (!target || !hook_fn || !trampoline) {
        errno = EINVAL;
        return -1;
    }

    // ------------------------------------------------------------------
    // 1. Allocate a JIT page for the trampoline.
    // ------------------------------------------------------------------
#if defined(ROSETTA_RUNTIME)
    void* tramp = mmap((void*)NULL, AARCH64_PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_TRANSLATED_ALLOW_EXECUTE, -1, 0);
#else
    void* tramp = mmap(NULL, AARCH64_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#endif
    if (tramp == MAP_FAILED) {
        CORE_LOG("hook_install: mmap failed");
        return -1;
    }

    // ------------------------------------------------------------------
    // 2. Write the trampoline:
    //      [0 .. PATCH_SIZE-1]           displaced original instructions
    //      [PATCH_SIZE .. PATCH_SIZE+15] abs-jump back to target+PATCH_SIZE
    //
    // NOTE: assumes the first PATCH_SIZE bytes of `target` contain no
    // PC-relative instructions (ADR, ADRP, LDR literal, B/BL, B.cond,
    // CBZ/CBNZ, TBZ/TBNZ). Verify your prologue before use.
    // ------------------------------------------------------------------
    pthread_jit_write_protect_np(0);
    memcpy(tramp, target, PATCH_SIZE);
    write_abs_jump((uint8_t*)tramp + PATCH_SIZE, (uint8_t*)target + PATCH_SIZE);
    pthread_jit_write_protect_np(1);

    flush_cache(tramp, PATCH_SIZE + 16);

#if defined(ROSETTA_RUNTIME)
    if (make_page_executable(tramp) != 0) {
        munmap(tramp, AARCH64_PAGE_SIZE);
        return -1;
    }
#endif

    // ------------------------------------------------------------------
    // 3. Make the target page writable (COW) and patch it.
    // ------------------------------------------------------------------
    kern_return_t kr =
        protect_covering(target, PATCH_SIZE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        munmap(tramp, AARCH64_PAGE_SIZE);
        errno = EPERM;
        CORE_LOG("hook_install: vm_protect failed");
        return -1;
    }

    write_abs_jump(target, hook_fn);

    kr = protect_covering(target, PATCH_SIZE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        munmap(tramp, AARCH64_PAGE_SIZE);
        errno = EPERM;
        CORE_LOG("hook_install: vm_protect (exec) failed");
        return -1;
    }

    flush_cache(target, PATCH_SIZE);

    // ------------------------------------------------------------------
    // 4. Hand the trampoline back to the caller.
    // ------------------------------------------------------------------
    *trampoline = tramp;
    return 0;
}

// ---------------------------------------------------------------------------
// patch_movz_imm
//
// Patch a MOVZ Wd, #imm (sf=0, opc=10, hw=00) instruction in place.
// AArch64 encoding:  [31]=0  [30:29]=10  [28:23]=100101  [22:21]=00
//                    [20:5]=imm16  [4:0]=Rd
// Fixed-bit mask:    0xFFE00000  ==  0x52800000
// Immediate field:   bits [20:5]  =>  mask 0x001FFFE0
// ---------------------------------------------------------------------------
int patch_movz_imm(void* addr, uint16_t new_imm) {
    if (!addr) {
        errno = EINVAL;
        return -1;
    }

    // Read the current instruction.
    uint32_t insn;
    memcpy(&insn, addr, 4);

    // Verify: MOVZ Wd, #imm  (32-bit register, no shift)
    if ((insn & 0xFFE00000u) != 0x52800000u) {
        errno = EINVAL;
        CORE_LOG("patch_movz_imm: instruction at %p is not MOVZ Wd,#imm (got 0x%08X)", addr, insn);
        return -1;
    }

    // Build the patched instruction: keep Rd, replace imm16.
    insn = (insn & ~0x001FFFE0u) | ((uint32_t)new_imm << 5);

    // Make the page writable (COW).
    kern_return_t kr =
        protect_covering(addr, 4, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_movz_imm: vm_protect (write) failed");
        return -1;
    }

    memcpy(addr, &insn, 4);

    // Restore execute permission.
    kr = protect_covering(addr, 4, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_movz_imm: vm_protect (exec) failed");
        return -1;
    }

    flush_cache(addr, 4);
    return 0;
}

// ---------------------------------------------------------------------------
// patch_nop
//
// Overwrite `count` consecutive 4-byte AArch64 instructions at `addr` with
// NOP (0xD503201F). The range may span more than one page, so every page it
// touches is switched to writable (COW) before the write and back to
// executable afterwards.
// ---------------------------------------------------------------------------
int patch_nop(void* addr, unsigned int count) {
    if (!addr || count == 0) {
        errno = EINVAL;
        return -1;
    }

    const uint32_t nop = 0xD503201Fu;
    const size_t len = (size_t)count * 4u;

    // Make the target page(s) writable (COW).
    kern_return_t kr =
        protect_covering(addr, len, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_nop: vm_protect (write) failed");
        return -1;
    }

    uint8_t* p = (uint8_t*)addr;
    for (unsigned int i = 0; i < count; i++) {
        memcpy(p + (size_t)i * 4u, &nop, 4);
    }

    // Restore execute permission.
    kr = protect_covering(addr, len, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_nop: vm_protect (exec) failed");
        return -1;
    }

    flush_cache(addr, len);
    return 0;
}

// ---------------------------------------------------------------------------
// patch_ret
//
// Overwrite the 4-byte AArch64 instruction at `addr` with RET (0xD65F03C0,
// i.e. RET X30), turning the function that starts there into an immediate
// return. Same COW-write / flush dance as patch_nop, single instruction.
// ---------------------------------------------------------------------------
int patch_ret(void* addr) {
    if (!addr) {
        errno = EINVAL;
        return -1;
    }

    const uint32_t ret = 0xD65F03C0u;  // RET X30

    // Make the target page writable (COW).
    kern_return_t kr =
        protect_covering(addr, 4, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_ret: vm_protect (write) failed");
        return -1;
    }

    memcpy(addr, &ret, 4);

    // Restore execute permission.
    kr = protect_covering(addr, 4, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        errno = EPERM;
        CORE_LOG("patch_ret: vm_protect (exec) failed");
        return -1;
    }

    flush_cache(addr, 4);
    return 0;
}