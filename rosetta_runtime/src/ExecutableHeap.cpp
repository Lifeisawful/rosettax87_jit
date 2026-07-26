#include "ExecutableHeap.h"

#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>
#include <sys/mman.h>

#include "MachIPC.h"
#include "ThreadSelfRestrict.h"
#include "rosetta_core/hook.h"

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

extern "C" {
// The asm label is `_stub_far_jmp`; Mach-O prepends an underscore to C symbols,
// so the C name must be spelled WITHOUT the leading underscore.  Declaring it as
// `_stub_far_jmp` here would ask the linker for `__stub_far_jmp`, which does not
// exist.  TranslationCacheAbi.cpp spells it the same way.
extern char stub_far_jmp[];

// Bounds of the whole runtime_entry blob.  runtime_blob_start is co-located with
// stub_far_jmp (same address); runtime_blob_end sits at the end of the last
// section in runtime_entry.S.
extern char runtime_blob_start[];
extern char runtime_blob_end[];
}

ExecutableHeap* g_executable_heap = nullptr;

constexpr uintptr_t kHeapPreferredAddr = 0x100000000;
constexpr size_t kHeapSize = 0x8000000;  // 128 MB

// mach_vm_remap with VM_FLAGS_OVERWRITE needs 16 KB granularity on arm64.
constexpr size_t kPageSize = 0x4000;

// Sanity bounds on the computed blob size.  The linker is not formally obliged to
// keep runtime_entry.S's 16 sections contiguous or in source order, and a bad
// layout would silently yield a garbage span — which we would then hand to
// mach_vm_remap.  Anything outside this window means the assumption broke, so we
// fall back to the historical constant rather than map nonsense.
constexpr size_t kRuntimeRoutinesSizeMin = 0x4000;    // never shrink below the original
constexpr size_t kRuntimeRoutinesSizeMax = 0x100000;  // 1 MB — far above any plausible blob

// Size of the runtime-routines region, derived from the actual extent of the
// linked blob and rounded up to a page.  Growing the blob past a page boundary
// now enlarges the mapped region automatically instead of silently truncating
// against a hand-maintained 0x4000.
//
// These are link-time addresses, so this CANNOT be constexpr — the compiler
// rejects symbol arithmetic in a constant expression.  Nothing needs it at
// compile time though: every use is a struct store, a call argument, or pointer
// arithmetic.
//
// Deliberately a function rather than a `const size_t` global.  A global
// initialised from linker symbols is dynamic initialisation, which emits a
// __mod_init_func entry — and this freestanding runtime never runs static
// initialisers, so the value would read as 0 at every use.  (Verified: the
// global form does add __mod_init_func to the linked binary; this form does
// not.)  It folds to a handful of instructions and is not on a hot path —
// allocate_chunk runs once per 128 MB of heap.
inline size_t runtime_routines_size() {
    const size_t raw = static_cast<size_t>(runtime_blob_end - runtime_blob_start);
    const size_t rounded = (raw + kPageSize - 1) & ~(kPageSize - 1);
    if (rounded < kRuntimeRoutinesSizeMin || rounded > kRuntimeRoutinesSizeMax)
        return kRuntimeRoutinesSizeMin;
    return rounded;
}

inline size_t jit_heap_size() {
    return kHeapSize - runtime_routines_size();
}

constexpr int32_t kMachVmRemapMsgId = 4813;  // 0x12CD

namespace {

// trace_write_mapping_record (reference 0x16744): emits a type-5
// (RuntimeRoutinesMapped) record into the hardware trace file.
//
//   X0 = mach_thread_self()   — also the value passed on to write_to_trace_file
//   X1 = mapping base
//   X2 = mapping size
//
// It self-gates on g_write_trace == 1 and is a no-op when tracing is off, so we
// call it unconditionally rather than duplicating the flag test.
using trace_write_mapping_record_t = uint64_t (*)(uint64_t, uint64_t, uint64_t);

trace_write_mapping_record_t g_trace_write_mapping_record = nullptr;

}  // namespace

void map_runtime_routines(uintptr_t dest, uint32_t task_port) {
    union {
        __Request__mach_vm_remap_t request;
        __Reply__mach_vm_remap_t reply;
    } msg{};

    msg.request.msgh_body.msgh_descriptor_count = 1;
    msg.request.src_task.name = task_port;
    msg.request.src_task.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.request.src_task.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.request.target_address = dest;
    msg.request.size = runtime_routines_size();
    msg.request.mask = 0;
    msg.request.flags = VM_FLAGS_OVERWRITE;
    msg.request.src_address = reinterpret_cast<uintptr_t>(stub_far_jmp);
    msg.request.copy = FALSE;
    msg.request.inheritance = VM_INHERIT_COPY;

    // Receive size must leave room for the message TRAILER, not just the reply
    // body.  The reference passes 0x3C (0x34 reply + 8 trailer) at 0x13084;
    // passing bare sizeof(__Reply__) made every call fail with
    // MACH_RCV_TOO_LARGE (0x10004004), silently forcing the memmove fallback.
    // The union buffer is sizeof(__Request__) = 0x5C, so 0x3C fits.
    constexpr uint32_t kRemapReplyRcvSize = sizeof(__Reply__mach_vm_remap_t) + 8;  // 0x3C
    static_assert(kRemapReplyRcvSize <= sizeof(__Request__mach_vm_remap_t),
                  "reply+trailer must fit in the shared request/reply buffer");

    uint32_t ret = mach_vm_remap_msg(task_port, &msg, 1, 0, sizeof(__Request__mach_vm_remap_t),
                                     kRemapReplyRcvSize, kMachVmRemapMsgId, 0);

    // The address actually traced.  On the remap path the kernel reports where it
    // placed the mapping, which the reference reads back out of the reply
    // (0x13138) and traces INSTEAD of the requested address; only the memmove
    // fallback traces `dest` itself.  Read the reply before the union is reused.
    uintptr_t mapped_address = dest;

    bool use_fallback = true;
    if (!ret) {
        uint32_t msgh_size = msg.reply.Head.msgh_size;
        kern_return_t retcode = msg.reply.RetCode;
        if ((msgh_size == sizeof(__Reply__mach_vm_remap_t) ||
             msgh_size ==
                 sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + sizeof(kern_return_t)) &&
            retcode == KERN_SUCCESS) {
            use_fallback = false;
            mapped_address = static_cast<uintptr_t>(msg.reply.target_address);
        }
    }

    if (use_fallback) {
        thread_self_restrict_rwx_to_rw();
        memmove(reinterpret_cast<void*>(dest), stub_far_jmp, runtime_routines_size());
        thread_self_restrict_rwx_to_rx();

        // Make the freshly written stubs visible to the instruction fetcher.
        // ARM64 I/D caches are not coherent, and this is a D-side copy into a
        // region that is about to be executed.  The reference omits it; we keep
        // it because it is a few instructions once per 128 MB heap chunk, and
        // being explicit here is cheaper than reasoning about whether the
        // destination lines could ever be stale.
        rt_sys_icache_invalidate(reinterpret_cast<void*>(dest), runtime_routines_size());
    }

    // Emit the type-5 RuntimeRoutinesMapped trace record, so a trace captured
    // with ROSETTA_HARDWARE_TRACING_PATH still describes where the stub page
    // lives — we replace allocate_chunk/map_runtime_routines wholesale, so
    // without this the reference's own record is never written and
    // scripts/parse_rosetta_trace.py sees no runtime-routines mapping at all.
    //
    // Note the size is runtime_routines_size(), not a hardcoded 0x4000: our blob
    // can span more than one page, and the trace should describe what we really
    // mapped.  (The reference ERRORs on any size != 0x4000, but that check lives
    // in ITS map_runtime_routines, which we no longer call.)
    if (g_trace_write_mapping_record) {
        g_trace_write_mapping_record(rt_mach_thread_self(), mapped_address,
                                     runtime_routines_size());
    }
}

FreeBlock* ExecutableHeap::allocate_chunk(uint32_t lock_owner) {
    ExecutableHeap* const heap = this;
    g_executable_heap = heap;

    void* base = mmap(
        reinterpret_cast<void*>(kHeapPreferredAddr), kHeapSize, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANON | MAP_JIT | MAP_TRANSLATED_ALLOW_EXECUTE, VM_MAKE_TAG(0xEA), 0);

    if (base == MAP_FAILED)
        abort();

    uintptr_t heap_base = reinterpret_cast<uintptr_t>(base);
    heap->heap_base = base;
    heap->initialized = 1;
    heap->heap_count = 1;

    map_runtime_routines(heap_base, static_cast<uint32_t>(heap->mach_port));

    uintptr_t jit_base = heap_base + runtime_routines_size();

    // Registering the fragment is also what makes this region visible to
    // TranslationCacheAbi::classify_arm_pc — it finds the region by walking
    // arm_tree for kind == RuntimeRoutines, so no bounds need publishing here.
    register_code_fragment(lock_owner, heap_base, runtime_routines_size(), CodeFragmentKind::RuntimeRoutines);

    auto* chunk = static_cast<Chunk*>(heap->allocator.alloc());
    chunk->base = jit_base;
    chunk->size = jit_heap_size();
    chunk->next = heap->chunk_list;
    heap->chunk_list = chunk;

    auto* block = static_cast<FreeBlock*>(heap->allocator.alloc());
    block->size_color = 0;
    block->size_parent = nullptr;
    block->size_left = nullptr;
    block->size_right = nullptr;
    block->addr_color = 0;
    block->addr_parent = nullptr;
    block->addr_left = nullptr;
    block->addr_right = nullptr;
    block->base_address = jit_base;
    block->size = jit_heap_size();

    BestFitAllocator::insert_by_size(&heap->free_by_size, block);
    BestFitAllocator::insert_by_addr(&heap->free_by_addr, block);

    return block;
}

// Maps an address inside a JIT chunk back to the runtime-routines page that
// serves it.  Transliterated from 0x8C40.
//
// Every chunk is carved out of an mmap whose leading runtime_routines_size() bytes
// are the stub page (see allocate_chunk: chunk->base == heap_base + that size), so
// the answer is simply `chunk->base - runtime_routines_size()` for the chunk that
// spans `addr`.  The walk is over chunk_list, under allocator_lock — NOT arm_tree.
//
// Why we must own this: callers use the result as the base that
// g_runtime_routine_offsets[] is added to (remove_fragment 0xC664:
// `LDR X8,[g_runtime_routine_offsets]; ADD X8, X8, X0`).  Those offsets describe
// the *reference* runtime_entry layout; we map our own blob over the region, so a
// correct base with reference offsets still lands on the wrong stub.  Taking the
// hook keeps the base derivation ours end-to-end and is a prerequisite for
// rewriting the offset table itself (register_runtime_routine_offsets).
//
// The reference ERROR()s ("no runtime routines for address 0x%llx") when no chunk
// matches.  We return nullptr instead: this runs on the translation path, and a
// hard trap here would be a worse failure than letting the caller see a null base.
void* ExecutableHeap::runtime_routines_for_address(uint32_t lock_owner, uint64_t addr) {
    ExecutableHeap* const heap = this;

    os_unfair_lock_lock_no_tsd(&heap->allocator_lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION,
                               lock_owner);

    void* result = nullptr;
    for (const Chunk* chunk = heap->chunk_list; chunk; chunk = chunk->next) {
        // 0x8C7C-0x8C84: `CMP base,addr; CCMP base+size,addr,#0,LS; B.HI hit` —
        // i.e. base <= addr && addr < base + size.
        if (chunk->base <= addr && addr < chunk->base + chunk->size) {
            result = reinterpret_cast<void*>(chunk->base - runtime_routines_size());
            break;
        }
    }

    os_unfair_lock_unlock_no_tsd(&heap->allocator_lock, lock_owner);

    return result;
}

namespace {

// The reference entry points we displace.  hook_install rewrites their prologues
// to jump to ours and hands back a trampoline; we never call these back (both
// replacements are complete reimplementations), but the trampolines are kept so
// the originals stay reachable for debugging and so hook_install has somewhere to
// store them.
using allocate_chunk_t = FreeBlock* (*)(ExecutableHeap*, uint32_t);
using runtime_routines_for_address_t = void* (*)(ExecutableHeap*, uint32_t, uint64_t);

allocate_chunk_t g_original_allocate_chunk = nullptr;
runtime_routines_for_address_t g_original_runtime_routines_for_address = nullptr;

// Free-function thunks with the exact register ABI of the reference methods
// (X0 = heap, then the declared arguments).  hook_install needs a plain function
// pointer, which a pointer-to-member is not.
FreeBlock* hook_allocate_chunk(ExecutableHeap* heap, uint32_t lock_owner) {
    return heap->allocate_chunk(lock_owner);
}

void* hook_runtime_routines_for_address(ExecutableHeap* heap, uint32_t lock_owner,
                                        uint64_t addr) {
    return heap->runtime_routines_for_address(lock_owner, addr);
}

}  // namespace

void executable_heap_init(uintptr_t allocate_chunk_addr,
                          uintptr_t runtime_routines_for_address_addr,
                          uintptr_t trace_write_mapping_record_addr) {
    // Not hooked — called directly from our map_runtime_routines.  The reference
    // function stays in place and we just borrow it to write the trace record.
    g_trace_write_mapping_record =
        reinterpret_cast<trace_write_mapping_record_t>(trace_write_mapping_record_addr);

    if (allocate_chunk_addr) {
        g_original_allocate_chunk = reinterpret_cast<allocate_chunk_t>(allocate_chunk_addr);
        hook_install(reinterpret_cast<void*>(allocate_chunk_addr),
                     reinterpret_cast<void*>(&hook_allocate_chunk),
                     reinterpret_cast<void**>(&g_original_allocate_chunk));
    }

    if (runtime_routines_for_address_addr) {
        g_original_runtime_routines_for_address =
            reinterpret_cast<runtime_routines_for_address_t>(runtime_routines_for_address_addr);
        hook_install(reinterpret_cast<void*>(runtime_routines_for_address_addr),
                     reinterpret_cast<void*>(&hook_runtime_routines_for_address),
                     reinterpret_cast<void**>(&g_original_runtime_routines_for_address));
    }
}

// Allocates a metadata node, describes [base, base+size) with it, and files it
// in the image-range tree.  Transliterated from register_code_fragment (0xA95C):
// every field except the four pad gaps is explicitly zeroed, because the slab
// hands back recycled memory.
CodeFragmentMetadata* register_code_fragment(uint32_t lock_owner, uint64_t arm_base,
                                             uint32_t arm_size, CodeFragmentKind kind) {
    auto* node =
        static_cast<CodeFragmentMetadata*>(g_executable_heap->code_fragment_allocator.locked_alloc(
            lock_owner));

    node->reserved_00[0] = 0;
    node->reserved_00[1] = 0;
    node->reserved_00[2] = 0;
    node->reserved_00[3] = 0;
    node->bst_color = RB_BLACK;
    node->bst_parent = nullptr;
    node->bst_left = nullptr;
    node->bst_right = nullptr;
    node->kind = kind;
    node->x86_base = 0;
    node->reserved_50 = 0;
    node->arm_base = arm_base;
    node->reserved_60[0] = 0;
    node->reserved_60[1] = 0;
    node->reserved_60[2] = 0;
    node->reserved_60[3] = 0;
    node->reserved_60[4] = 0;
    node->reserved_60[5] = 0;
    node->reserved_60[6] = 0;
    node->x86_size = 0;
    node->arm_size = arm_size;
    node->num_branch_slots = 0;
    node->reserved_A8[0] = 0;
    node->reserved_A8[1] = 0;
    node->reserved_A8[2] = 0;
    node->reserved_A8[3] = 0;
    node->reserved_C8 = 0;
    node->reserved_D0[0] = 0;
    node->reserved_D0[1] = 0;
    node->reserved_D0[2] = 0;
    node->reserved_D0[3] = 0;
    node->reserved_D0[4] = 0;
    node->reserved_F8 = 0;
    node->retire_epoch = 0;
    node->next_free_fragment = nullptr;
    node->reserved_110 = 0;

    os_unfair_lock_lock_no_tsd(&g_executable_heap->arm_tree_lock,
                               OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION, lock_owner);
    g_executable_heap->arm_tree.insert(node);
    os_unfair_lock_unlock_no_tsd(&g_executable_heap->arm_tree_lock, lock_owner);

    return node;
}
