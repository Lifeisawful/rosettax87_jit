#pragma once

#include <cstddef>
#include <cstdint>

// ThreadContext / ThreadContextVTable — the per-thread block X18 points at, and
// the dispatch table every stub reaches through `LDR X29,[X18]`.
//
// ThreadContext::create (reference 0x9840) allocates one 0x4000 page tagged
// 0xE7 and returns page+0x3A70 as the context: [0x0000,0x3A70) is that thread's
// runtime stack (growing down into the page), [0x3A70,0x4000) is the 0x590-byte
// ThreadContext packed flush against the top.  One register therefore serves as
// both context pointer and stack base, which is why a runtime routine entered
// from translated code needs no prologue to get a stack.
//
// We model only the two fields we use.  The rest stays reserved bytes: the
// layout is version-specific (it is precisely why the runtime hands
// ThreadContextOffsets to libRosettaRuntime at init), and every field we do not
// name is one we cannot get wrong.

// The vtable is a single shared global (`g_thread_context_vtable`, reference
// 0x30000).  ThreadContext::create stores the POINTER — not a copy — so the
// table is identical for every thread, present and future.
//
// Entries +0x000..+0x188 are the runtime infrastructure handlers modelled here.
// The x87/SSE operation entries follow at +0x190, and how many there are depends
// on the runtime version (121 entries in 26.x, 123 in 27.b3, which appends
// xrstor/xsave).  This struct deliberately stops before them: we only ever index
// into the fixed head, and a trailing array would bake in a version.
struct ThreadContextVTable {
    void* single_step_handler;             // +0x000
    void* single_step_with_resume;         // +0x008
    void* check_pending_signals;           // +0x010
    void* translate_indirect_branch;       // +0x018
    void* abort_handler;                   // +0x020
    void* code_segment_switch;             // +0x028
    void* branch_slot_miss;                // +0x030
    void* cache_slot_miss;                 // +0x038
    void* fork_handler;                    // +0x040
    void* madvise;                         // +0x048
    void* mmap;                            // +0x050
    void* posix_spawn;                     // +0x058
    void* mprotect;                        // +0x060
    void* munmap;                          // +0x068
    void* mach_vm_deallocate;              // +0x070
    void* mach_vm_protect;                 // +0x078
    void* bsdthread_create;                // +0x080
    void* bsdthread_register;              // +0x088
    void* sigreturn;                       // +0x090
    void* sigreturn_mask;                  // +0x098
    void* install_sigaction;               // +0x0A0
    void* sigaltstack;                     // +0x0A8
    void* exec_with_exception_ports;       // +0x0B0
    void* mig_task_handler;                // +0x0B8
    void* mig_thread_handler;              // +0x0C0
    void* mig_task_handler_ext;            // +0x0C8
    void* mig_thread_handler_ext;          // +0x0D0
    void* dyld_get_aot_size;               // +0x0D8
    void* dyld_map_aot;                    // +0x0E0
    void* task_threads_create;             // +0x0E8
    void* dyld_get_all_image_infos;        // +0x0F0
    void* classify_arm_pc_objc;            // +0x0F8
    void* invalidate_translations;         // +0x100
    void* check_rflags_pending;            // +0x108
    void* shared_cache_check;              // +0x110
    void* error_unsupported_shared_cache;  // +0x118
    void* shared_region_map_subcaches;     // +0x120
    void* exception_sync_barrier;          // +0x128
    void* debug_wait_for_thread;           // +0x130
    void* debug_resume_barrier;            // +0x138
    void* register_jit_region;             // +0x140
    void* set_ldt;                         // +0x148
    void* get_ldt;                         // +0x150
    void* get_segment_limit;               // +0x158
    void* mov_segment;                     // +0x160
    void* mov_segment_gs;                  // +0x168
    void* sse_pcmpestri;                   // +0x170
    void* sse_pcmpestrm;                   // +0x178
    void* sse_pcmpistri;                   // +0x180
    void* sse_pcmpistrm;                   // +0x188
};

static_assert(offsetof(ThreadContextVTable, classify_arm_pc_objc) == 0x0F8);
static_assert(offsetof(ThreadContextVTable, sse_pcmpistrm) == 0x188);
static_assert(sizeof(ThreadContextVTable) == 0x190);

struct ThreadContext {
    const ThreadContextVTable* vtable;  // +0x000
    uint8_t reserved_008[0x190 - 0x008];
    uint32_t task_port;    // +0x190
    uint32_t thread_port;  // +0x194  — the `self` token os_unfair_lock_*_no_tsd wants
    uint8_t reserved_198[0x330 - 0x198];
    // Cached mach reply port for this thread's MIG calls, minted lazily with
    // mach_reply_port() and dropped back to 0 when a send/receive fails.
    // ThreadContext::create zeroes it (`ctx.field_330 = 0`); MachIPC.cpp uses it.
    uint32_t reply_port;  // +0x330
    uint8_t reserved_334[0x590 - 0x334];
};

static_assert(offsetof(ThreadContext, vtable) == 0x000);
static_assert(offsetof(ThreadContext, task_port) == 0x190);
static_assert(offsetof(ThreadContext, thread_port) == 0x194);
static_assert(offsetof(ThreadContext, reply_port) == 0x330);
static_assert(sizeof(ThreadContext) == 0x590);

// The ThreadContext of the calling thread, from X18.
//
// Two caveats, both from the reference's own use of the register:
//   - the low 2 bits are a mode tag (see MachIPC.cpp's reply_port_slot, which
//     keys off them), so they must be masked before dereferencing;
//   - STUB_PROLOGUE sets bit 63 as the "in runtime" flag and runtime_exit*
//     clears it, so a context read from inside a stub carries it.
// Returns nullptr when X18 is not set up yet — it only becomes valid once
// create_from_mach_thread runs (reference 0x1348C, called from main at
// 0x1294C), which is AFTER our _start hook point but before any library export
// is called.
inline ThreadContext* current_thread_context() {
    uintptr_t x18;
    __asm__ volatile("mov %0, x18" : "=r"(x18));

    const uintptr_t base = x18 & ~static_cast<uintptr_t>(3) & 0x7FFFFFFFFFFFFFFFULL;

    // A null or misaligned value means X18 is not a context pointer; refuse
    // rather than fault on a low address.
    if (base == 0 || (base & 0xF) != 0)
        return nullptr;

    return reinterpret_cast<ThreadContext*>(base);
}
