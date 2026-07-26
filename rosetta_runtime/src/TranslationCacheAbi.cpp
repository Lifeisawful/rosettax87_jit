#include "TranslationCacheAbi.h"

#include "ExecutableHeap.h"
#include "rosetta_core/hook.h"

#ifdef ROSETTA_RUNTIME
#include "rosetta_core/RuntimeLibC.h"
#endif

// Landmarks in our own runtime_entry.S.  These are link-time addresses in the
// *library image*; the blob is copied to the heap by allocate_chunk, so we only
// ever use differences between them (offsets into the region), never the
// addresses themselves.
extern "C" {
extern char stub_far_jmp[];              // region base / first stub
extern char runtime_savedreg_start[];    // dispatch tails begin
extern char stub_branch_slot[];          // branch-slot miss stub
extern char runtime_exit_ret[];
extern char exit_ret_debug_check[];
extern char exit_ret_post_callback[];
extern char exit_ret_gpr_restore[];
extern char runtime_exitcall[];
extern char exitcall_debug_check[];
extern char exitcall_post_callback[];
extern char exitcall_gpr_restore[];
extern char runtime_exitljmp[];
extern char exitljmp_debug_check[];
extern char exitljmp_post_callback[];
extern char exitljmp_gpr_restore[];
extern char runtime_exit_br[];
extern char exit_br_debug_check[];
extern char exit_br_post_callback[];
extern char exit_br_gpr_restore[];
extern char runtime_exit_sys[];
extern char exit_sys_debug_check[];
extern char exit_sys_post_callback[];
extern char exit_sys_gpr_restore[];
extern char runtime_exitinst[];
extern char exitinst_debug_check[];
extern char exitinst_post_callback[];
extern char exitinst_gpr_restore[];
extern char runtime_exitsigr[];
extern char exitsigr_debug_check[];
extern char exitsigr_post_callback[];
extern char exitsigr_sigreturn[];
extern char stub_wide_udiv_64[];
extern char sa_tramp_handler[];
extern char sigtramp_post_sa_tramp[];
extern char runtime_thread[];
extern char runtime_pthread[];
extern char runtime_wqthread[];
extern char runtime_syscall[];
extern char syscall_post_svc[];
extern char syscall_sigreturn_case[];
}

namespace {

using classify_arm_pc_t = void (*)(AbiInfo*, uint32_t, uintptr_t);

classify_arm_pc_t g_original_classify_arm_pc = nullptr;

// Bounds of our own loaded library image, from the loader (machoBase /
// imageSize()).  Zero until init runs, which disables the range test rather than
// matching everything.
uintptr_t g_rosettax87_base = 0;
size_t g_rosettax87_size = 0;

// Offset of a landmark from the start of the blob.  The linker lays runtime_entry
// out contiguously from _stub_far_jmp, and allocate_chunk copies it verbatim, so
// a label's offset is identical in the image and in the mapped region.
inline uintptr_t off(const char* label) {
    return reinterpret_cast<uintptr_t>(label) - reinterpret_cast<uintptr_t>(stub_far_jmp);
}

// Zeroes the payload the way every arm of the reference does before storing kind.
inline void clear(AbiInfo* result) {
    result->u.raw_offset = 0;
    result->u.translated_code.arm_pc = 0;
    result->u.translated_code.arm_range_start = 0;
    result->u.translated_code.arm_range_end = 0;
    result->u.translated_code.instruction_extents.kind = InstructionOffsetKind_0;
    result->u.translated_code.instruction_extents.length = 0;
}

inline void set(AbiInfo* result, AbiKind kind) {
    clear(result);
    result->kind = kind;
}

// The exit trampolines share one shape (reference 0xB2B0-0xB5FC): three interior
// landmarks split the path into four phases, and sa_tramp keys its "is it safe to
// deliver a signal now?" test on the resulting subkind.
//
//   subkind 0  before debug_check      — guest GPRs still committed to memory
//   subkind 1  at debug_check exactly  — safe iff x27 == 0 (sa_tramp checks it)
//   subkind 2  after debug_check, before post_callback — inside the host callback
//   subkind 3  after post_callback, before gpr_restore — safe
//   subkind 4  at/after gpr_restore    — safe
//
// sa_tramp (0x1BD74): `if (subkind - 3 < 2 || (subkind == 1 && !x27)) deliver`.
uint8_t exit_subkind(uintptr_t o, uintptr_t debug_check, uintptr_t post_callback,
                     uintptr_t gpr_restore) {
    if (o < debug_check)
        return 0;
    if (o == debug_check)
        return 1;
    if (o < post_callback)
        return 2;
    return (o < gpr_restore) ? 3 : 4;
}

struct ExitRegion {
    uintptr_t begin, debug_check, post_callback, gpr_restore;
    AbiKind kind;
};

}  // namespace

void TranslationCacheAbi::abi_info_for_runtime_routines_address(AbiInfo* result, uintptr_t o) {
    // Mirrors 0xB230's ladder, but keyed on offsets into OUR blob.  Ordered by
    // address, matching the reference's descending if-chain.

    // [base, runtime_savedreg): the entry stubs themselves.  The reference splits
    // this at runtime_savedreg into Library(4) / RuntimeRoutine(6); the first
    // range is the stub bodies, the second the dispatch tails.
    if (o < off(runtime_savedreg_start)) {
        set(result, AbiKind_Library);
        return;
    }
    if (o < off(stub_branch_slot)) {
        set(result, AbiKind_RuntimeRoutine);
        return;
    }

    // [stub_branch_slot, runtime_exit_ret): ExitCall carries the byte offset from
    // the branch-slot base — sa_tramp restores x21 for this kind.
    if (o < off(runtime_exit_ret)) {
        clear(result);
        result->kind = AbiKind_ExitCall;
        result->u.raw_offset = o - off(stub_branch_slot);
        return;
    }

    // Deliberately NOT `static`: a function-local static would need a
    // thread-safe-init guard (__cxa_guard_acquire), which this freestanding
    // runtime does not link.  The table is a handful of stores and this is not a
    // hot path — it runs once per signal.
    const ExitRegion kExits[] = {
        {off(runtime_exit_ret), off(exit_ret_debug_check), off(exit_ret_post_callback),
         off(exit_ret_gpr_restore), AbiKind_ExitTrampoline0},
        {off(runtime_exitcall), off(exitcall_debug_check), off(exitcall_post_callback),
         off(exitcall_gpr_restore), AbiKind_ExitTrampoline1},
        {off(runtime_exitljmp), off(exitljmp_debug_check), off(exitljmp_post_callback),
         off(exitljmp_gpr_restore), AbiKind_ExitTrampoline2},
        {off(runtime_exit_br), off(exit_br_debug_check), off(exit_br_post_callback),
         off(exit_br_gpr_restore), AbiKind_ExitTrampoline3},
        {off(runtime_exit_sys), off(exit_sys_debug_check), off(exit_sys_post_callback),
         off(exit_sys_gpr_restore), AbiKind_ExitTrampoline4},
        {off(runtime_exitinst), off(exitinst_debug_check), off(exitinst_post_callback),
         off(exitinst_gpr_restore), AbiKind_ExitTrampoline5},
    };

    // Each trampoline runs until the next landmark begins.
    const uintptr_t kExitEnd = off(runtime_exitsigr);
    for (unsigned i = 0; i < 6; i++) {
        const uintptr_t end = (i + 1 < 6) ? kExits[i + 1].begin : kExitEnd;
        if (o >= kExits[i].begin && o < end) {
            clear(result);
            result->kind = kExits[i].kind;
            result->u.subkind = exit_subkind(o, kExits[i].debug_check,
                                             kExits[i].post_callback, kExits[i].gpr_restore);
            return;
        }
    }

    // runtime_exitsigr: Sigreturn.  Same four-phase split, different landmark
    // names (the last one is the sigreturn svc rather than a gpr restore).
    if (o < off(stub_wide_udiv_64)) {
        clear(result);
        result->kind = AbiKind_Sigreturn;
        result->u.subkind = exit_subkind(o, off(exitsigr_debug_check),
                                         off(exitsigr_post_callback), off(exitsigr_sigreturn));
        return;
    }

    // [stub_wide_udiv_64, sa_tramp_handler): the wide-divide helpers.
    if (o < off(sa_tramp_handler)) {
        set(result, AbiKind_LibraryRoutine);
        return;
    }

    // Sigtramp.  subkind 1 once sa_tramp has returned (state is being unwound).
    if (o < off(runtime_thread)) {
        clear(result);
        result->kind = AbiKind_Sigtramp;
        result->u.subkind = (o >= off(sigtramp_post_sa_tramp) && o < off(runtime_thread)) ? 1 : 0;
        return;
    }

    // Thread entry points: one AbiKind, three subkinds.
    if (o < off(runtime_syscall)) {
        clear(result);
        result->kind = AbiKind_NewThread;
        if (o < off(runtime_pthread))
            result->u.subkind = 0;
        else if (o < off(runtime_wqthread))
            result->u.subkind = 2;
        else
            result->u.subkind = 1;
        return;
    }

    // Syscall.  subkind 1 marks "the SVC has been issued" — past that point the
    // syscall cannot be restarted, which sa_tramp must know.
    clear(result);
    result->kind = AbiKind_Syscall;
    result->u.subkind =
        (o >= off(syscall_post_svc) && o < off(syscall_sigreturn_case)) ? 1 : 0;
}

void TranslationCacheAbi::classify_arm_pc(AbiInfo* result, uint32_t thread_port,
                                          uintptr_t arm_pc) {
    // Checked first, before taking any lock: this is a two-compare range test,
    // and our own library image is where the X87 handlers live — the hottest
    // place for a signal to land after a stub has dispatched.  The two regions
    // can never overlap (this one is dyld-loaded; the stub page is inside the
    // JIT heap), so testing it first is purely an optimization.
    //
    // A stub in the mapped page runs STUB_PROLOGUE and branches to a tail_*
    // dispatcher, which `blr`s into a handler HERE, so a signal can land in this
    // range at any time.
    //
    // The original cannot classify it.  abi_info_for_runtime (0xB138) runs before
    // the tree walk and only knows two images, g_translator_image_range and
    // g_runtime_library_image_range; ours is neither, so it falls through to
    // AbiKind_Unknown at 0xB1E4 — which sa_tramp turns into
    // ERROR("no code fragment associated with the given arm pc").
    //
    // RuntimeRoutine is the right kind: STUB_PROLOGUE has already committed the
    // full guest GPR set to [x18] before any of this code runs, so sa_tramp needs
    // no register fixup — it groups RuntimeRoutine with NewThread/Unclassified in
    // the no-fixup arm.
    if (g_rosettax87_size && arm_pc >= g_rosettax87_base &&
        arm_pc < g_rosettax87_base + g_rosettax87_size) {
        clear(result);
        result->kind = AbiKind_RuntimeRoutine;
        return;
    }

    // Which fragment owns this pc is decided by the arm tree, exactly as the
    // reference does it (0xB7AC-0xB7E0) — NOT by a cached region base.  There is
    // one RuntimeRoutines fragment per heap chunk, and allocate_chunk runs again
    // every time the heap fills, so any single base/size pair is wrong the moment
    // a second chunk exists.
    //
    // We only claim the RuntimeRoutines kinds.  For every other fragment kind —
    // and for a pc no fragment covers — we defer to the original, which owns the
    // AbiKind_TranslatedCode path (instruction_extents_for_arm_address plus the
    // offset-map decoders) and the two image-range checks in abi_info_for_runtime.
    if (g_executable_heap) {
        ExecutableHeap* const heap = g_executable_heap;

        os_unfair_lock_lock_no_tsd(&heap->arm_tree_lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION,
                                   thread_port);

        const CodeFragmentMetadata* node = heap->arm_tree.root;
        uintptr_t offset = 0;
        bool is_runtime_routines = false;

        while (node) {
            const uint64_t base = node->arm_base;
            if (arm_pc < base) {
                node = node->bst_left;               // 0xB7C0: child at 0x30
                continue;
            }
            if (base + node->arm_size <= arm_pc) {
                node = node->bst_right;              // 0xB7D8: child at 0x38
                continue;
            }
            // Fragment found.  0xB854: `kind - 6 < 2` accepts RuntimeRoutines(6)
            // and InvalidRuntimeRoutines(7) — a retired region still classifies
            // until the AOT GC reclaims it.
            is_runtime_routines = (node->kind == CodeFragmentKind::RuntimeRoutines ||
                                   node->kind == CodeFragmentKind::InvalidRuntimeRoutines);
            offset = static_cast<uintptr_t>(arm_pc - base);
            break;
        }

        os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, thread_port);

        if (is_runtime_routines) {
            // No `offset < kRuntimeRoutinesSize` assert and no rebasing onto the
            // reference blob: the offset indexes our own runtime_entry image.
            abi_info_for_runtime_routines_address(result, offset);
            return;
        }
    }

    g_original_classify_arm_pc(result, thread_port, arm_pc);
}

void TranslationCacheAbi::init(uintptr_t classify_arm_pc_addr, uintptr_t rosettax87_base,
                               size_t rosettax87_size) {
    g_rosettax87_base = rosettax87_base;
    g_rosettax87_size = rosettax87_size;

    if (classify_arm_pc_addr == 0)
        return;

    g_original_classify_arm_pc = reinterpret_cast<classify_arm_pc_t>(classify_arm_pc_addr);
    hook_install(reinterpret_cast<void*>(g_original_classify_arm_pc),
                 reinterpret_cast<void*>(&TranslationCacheAbi::classify_arm_pc),
                 reinterpret_cast<void**>(&g_original_classify_arm_pc));
}
