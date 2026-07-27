#include "TranslationCacheAbi.h"

#include "ExecutableHeap.h"
#include "MachIPC.h"
#include "SIMDGuard.h"
#include "Thread.h"
#include "ThreadContext.h"
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

// Replacement for abi_info_for_runtime_routines_address (0xB230).  Takes an
// offset into our blob rather than a rebased file address — the rebasing at
// 0xB88C is exactly what we are removing.  File-local: only the
// SIMDGuardFull-protected classify functions call it, and all of them inline
// it — `inline` lets the compiler drop the otherwise-unreferenced
// out-of-line copy, whose AbiInfo stores contain unguarded SIMD that
// scripts/check_simd_guards.py would (rightly) flag.
inline void abi_info_for_runtime_routines_address(AbiInfo* result, uintptr_t o) {
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

// 0xB854 / 0x16188 both spell this `kind - 6 < 2`: RuntimeRoutines(6) and
// InvalidRuntimeRoutines(7) — a retired region still classifies until the AOT GC
// reclaims it.
inline bool is_runtime_routines_kind(CodeFragmentKind kind) {
    return kind == CodeFragmentKind::RuntimeRoutines ||
           kind == CodeFragmentKind::InvalidRuntimeRoutines;
}

// Which fragment owns a pc, decided by the arm tree exactly as the reference
// does it (0xB7AC-0xB7E0, 0x160C4-0x160EC) — NOT by a cached region base.  There
// is one RuntimeRoutines fragment per heap chunk, and allocate_chunk runs again
// every time the heap fills, so any single base/size pair is wrong the moment a
// second chunk exists.
//
// The caller must ALREADY hold arm_tree_lock.  It cannot be taken here because
// classify_arm_pc_objc_full has to keep it across the
// instruction_extents_for_arm_address call — the reference issues that at
// 0x161D8, before its unlock at 0x161E0, and the fragment's offset map is only
// stable under the lock.
const CodeFragmentMetadata* find_fragment_locked(uintptr_t arm_pc) {
    const CodeFragmentMetadata* node = g_executable_heap->arm_tree.root;

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
        return node;
    }

    return nullptr;
}

// Is arm_pc inside a mapped runtime-routines region, and if so how far in?
//
// `lock_owner` is the caller's own mach thread port, the `self` token
// os_unfair_lock_*_no_tsd takes.
bool runtime_routines_offset_for(uintptr_t arm_pc, uint32_t lock_owner, uintptr_t* out_offset) {
    if (!g_executable_heap)
        return false;

    ExecutableHeap* const heap = g_executable_heap;

    os_unfair_lock_lock_no_tsd(&heap->arm_tree_lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION,
                               lock_owner);

    const CodeFragmentMetadata* node = find_fragment_locked(arm_pc);
    uintptr_t offset = 0;
    bool is_runtime_routines = false;
    if (node) {
        is_runtime_routines = is_runtime_routines_kind(node->kind);
        offset = static_cast<uintptr_t>(arm_pc - node->arm_base);
    }

    os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, lock_owner);

    *out_offset = offset;
    return is_runtime_routines;
}

// Replacement for classify_arm_pc (0xB6FC).  Classifies two regions itself — the
// mapped runtime_entry page (found via arm_tree, kind RuntimeRoutines or
// InvalidRuntimeRoutines) and our own library image — and forwards everything
// else to the original.  File-local: installed by hook, never called by name.
void classify_arm_pc(AbiInfo* result, uint32_t thread_port, uintptr_t arm_pc) {
    // Same guest-live-XMM situation as classify_arm_pc_objc_prefilter below:
    // the AbiInfo stores in abi_info_for_runtime_routines_address compile to
    // `movi.2d v0` + `stur q0`, and this can be reached with guest vector
    // state in the caller-saved v registers. scripts/check_simd_guards.py
    // verifies the transitive clobber set stays within the guard's q0-q7.
    SIMDGuardFull simdGuard;

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

    // We only claim the RuntimeRoutines kinds.  For every other fragment kind —
    // and for a pc no fragment covers — we defer to the original, which owns the
    // AbiKind_TranslatedCode path (instruction_extents_for_arm_address plus the
    // offset-map decoders) and the two image-range checks in abi_info_for_runtime.
    uintptr_t offset = 0;
    if (runtime_routines_offset_for(arm_pc, thread_port, &offset)) {
        // No `offset < kRuntimeRoutinesSize` assert and no rebasing onto the
        // reference blob: the offset indexes our own runtime_entry image.
        abi_info_for_runtime_routines_address(result, offset);
        return;
    }

    g_original_classify_arm_pc(result, thread_port, arm_pc);
}

// ── classify_arm_pc_objc (0x15FC0) ───────────────────────────────────────────
//
// A SECOND, independent copy of the runtime-routines classification, reached
// through vtable slot +0xF8 rather than by a call to classify_arm_pc — so
// hooking classify_arm_pc does nothing for it.  It answers libobjc's restartable
// ranges: the guest registered x86 ranges via MIG msgid 0x1F40
// (task_restartable_ranges_register), the kernel cannot police them because the
// thread really executes ARM, so the guest asks Rosetta "thread T — what x86 pc
// is it at?".
//
// Its RuntimeRoutines arm (0x16194) does what classify_arm_pc's did:
//
//     offset = pc - fragment->arm_base
//     ASSERT(offset < kRuntimeRoutinesSize)          // 0x4000, traps at 0x1622C
//     abi_info_for_runtime_routines_address(stub_far_jmp + offset)
//
// Our blob is 0x4E7C bytes and runtime_syscall alone starts at blob offset
// 0x4020, so every thread parked in the syscall dispatcher — which is most
// blocked threads, most of the time — trips that assert.

// x0/x1 pair.  bsd7_case5 tail-calls runtime_exit_sys, which does
// `UBFIZ W22,W1,#29,#1; MSR NZCV,X22` — x1 bit 0 becomes the guest's carry flag,
// i.e. the BSD "this is an error, x0 is the errno" convention.  An `int` return
// would set x0 and leave x1 holding whatever the last call left there.
struct ObjcPcResult {
    uint64_t value;
    uint64_t error;
};

using classify_arm_pc_objc_t = ObjcPcResult (*)(ThreadContext*, uint32_t, uint64_t*);

classify_arm_pc_objc_t g_original_classify_arm_pc_objc = nullptr;

// ── the three reference helpers the full replacement calls ───────────────────
//
// All internal (non-exported) runtime functions; the loader locates them and
// hands the addresses to init_classify_arm_pc_objc_hook.  Null until then, which
// is what selects the pre-filter fallback.
//
// Signatures come from the reference call sites in classify_arm_pc_objc:
//   0x16048-0x16050  X0 = &AbiInfo, X1 = arm_pc
//   0x160F8-0x16104  X0 = &out, X1 = ctx->thread_port, X2 = thread
//   0x161D0-0x161D8  X0 = &TranslatedCodePayload, X1 = fragment, X2 = arm_pc
using abi_info_for_runtime_t = void (*)(AbiInfo* result, uintptr_t arm_pc);
using thread_entry_for_port_t = void (*)(ThreadLookupResult* out, uint32_t lock_owner,
                                         uint32_t thread);
using instruction_extents_for_arm_address_t = void (*)(TranslatedCodePayload* out,
                                                       const CodeFragmentMetadata* fragment,
                                                       uintptr_t arm_pc);

abi_info_for_runtime_t g_abi_info_for_runtime = nullptr;
thread_entry_for_port_t g_thread_entry_for_port = nullptr;
instruction_extents_for_arm_address_t g_instruction_extents_for_arm_address = nullptr;

// The reference's two answers, from 0x16068 (success) and 0x16024 (failure).
// 5 with the carry flag set reads as EIO to the guest: "cannot determine".
constexpr ObjcPcResult kObjcPcOk{0, 0};
constexpr ObjcPcResult kObjcPcCannotDetermine{5, 1};

// ARM_THREAD_STATE64.  The reference asks for flavor 6 with a count of 0x44
// 32-bit words (0x110 bytes) and reads the pc at +0x100.
struct ArmThreadState64 {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t pad;
};
static_assert(offsetof(ArmThreadState64, pc) == 0x100);
static_assert(sizeof(ArmThreadState64) == 0x110);

constexpr uint32_t kArmThreadState64Flavor = 6;
constexpr uint32_t kArmThreadState64Count = 0x44;

// Pre-filter over the reference.  We answer only for pcs inside a mapped
// runtime-routines region — the one case the original gets wrong — and hand
// everything else back untouched, so the AbiKind_TranslatedCode path, the
// restartable-range overlap test, the offset-map decode and the thread-registry
// fallback all stay the reference's.
//
// Reproducing its decision for our region needs no registry lookup.  The
// reference sends every non-Syscall runtime-routine pc to the registry path at
// 0x16104, which answers "x86 pc 0" only for the runtime's OWN threads
// (entry+0x10, set by register_runtime_mach_thread) and fails for guest threads.
// A thread executing the stub blob is a guest thread by construction — runtime
// threads never enter it — so that path always ends in failure here.
//
// One deliberate deviation: the reference ERRORs at 0x1621C if the guest never
// registered any ranges.  Reaching it requires the guest to make this call at
// all, which only libobjc's restartable-range support does, and that registers
// first.  We answer rather than abort in that (unreachable) ordering.
//
// ── KNOWN WEAKNESS — this is the fallback, not the fix ───────────────────────
//
// Forwarding is a second sample.  The original re-reads the thread state in its
// own prologue (0x1601C), and the interrogated thread is NOT suspended — the
// whole "return 5, caller retries" protocol exists because it is running.  So
// between our read and theirs it can move, and it only has to move into the
// syscall dispatcher (blob offset 0x4020 onward, where every blocked thread
// parks) for the original to compute an offset >= 0x4000 and trip
//
//     ASSERT(offset < kRuntimeRoutinesSize)      [0x16194, traps at 0x1622C]
//
// The window is microseconds, but a launch issues thousands of these queries.
// classify_arm_pc_objc_full below closes it by never forwarding; this version
// survives only so that a failed helper lookup degrades to the old behaviour
// instead of leaving the trap completely unhooked.
ObjcPcResult classify_arm_pc_objc_prefilter(ThreadContext* ctx, uint32_t thread,
                                            uint64_t* out_x86_pc) {
    // We are reached from the syscall dispatcher, whose entry stub spills the
    // guest GPRs to [x18] and nothing else — guest XMM state is still sitting in
    // the caller-saved v registers.  Our own AbiInfo stores compile to
    // `movi.2d v0` + `stur q0`, so this is not hypothetical.  q0-q7 is the range
    // the compiler may take without saving (v8-v15 are callee-saved, and the
    // build was checked for anything above that).
    SIMDGuardFull simdGuard;

    // Deliberately NOT zero-initialised: thread_get_state fills it, we only read
    // `pc` after it reports success, and a 0x110-byte value-init compiles to a
    // run of q-register stores for no benefit.
    ArmThreadState64 state;
    uint32_t count = kArmThreadState64Count;

    if (ctx && mach_thread_get_state(thread, kArmThreadState64Flavor, &state, &count) == 0 &&
        state.pc != 0) {
        uintptr_t offset = 0;
        if (runtime_routines_offset_for(state.pc, ctx->thread_port, &offset)) {
            AbiInfo info{};
            abi_info_for_runtime_routines_address(&info, offset);

            // 0x161C4: blocked in the syscall stub.  The guest GPRs are already
            // committed to [x18] and the thread is definitively not inside an
            // objc restartable range, so "not executing guest code" is exact.
            if (info.kind == AbiKind_Syscall) {
                *out_x86_pc = 0;
                return kObjcPcOk;
            }
            return kObjcPcCannotDetermine;
        }
    }

    // Not ours: the original re-reads the thread state.  Cheap, but see the
    // KNOWN WEAKNESS note above — that re-read is the race.
    return g_original_classify_arm_pc_objc(ctx, thread, out_x86_pc);
}

// The thread-registry fallback — reference LABEL_18 at 0x16104.
//
// MUST NOT be called with arm_tree_lock held: thread_entry_for_port takes
// g_threads.lock, and every reference path releases arm_tree first (the unlocks
// at 0x160F4 and 0x161C0 both precede the call).  Holding both would invent a
// lock order nothing else in the runtime uses.
ObjcPcResult objc_registry_answer(ThreadContext* ctx, uint32_t thread, uint64_t* out_x86_pc) {
    // Deliberately not value-initialised: a 0x28-byte zero-init compiles to a
    // q-register store, which is exactly what the SIMD guard exists to contain.
    // On a miss the callee writes only thread_id and found (see Thread.h), so
    // `found` is the one field that has to be sane going in.
    ThreadLookupResult entry;
    entry.found = 0;
    entry.thread.is_runtime_thread = 0;

    g_thread_entry_for_port(&entry, ctx->thread_port, thread);

    // 0x16128: `found == 1 && is_runtime_thread == 1`.  Only the runtime's own
    // threads — registered by register_runtime_mach_thread, which sets
    // is_runtime_thread — may legitimately answer "x86 pc 0" for a pc we could
    // not place.  A guest thread here is genuinely unresolvable.
    if (entry.found == 1 && entry.thread.is_runtime_thread == 1) {
        *out_x86_pc = 0;
        return kObjcPcOk;
    }

    return kObjcPcCannotDetermine;
}

// Full replacement for classify_arm_pc_objc (0x15FC0) — the actual fix.
//
// Samples the interrogated thread's pc exactly ONCE and never calls the
// original, which is the only way to close the race documented on the pre-filter
// above.  What follows is the reference's own control flow in its own order,
// with the one region we own answered from our own landmark table.
//
// Three regions, three authorities:
//
//   the two static image ranges  -> g_abi_info_for_runtime, the reference's.
//       Its landmark table is right for those, because we never overwrite them:
//       map_runtime_routines remaps OUR blob onto the JIT heap and leaves the
//       translator's in-image copy untouched.  That copy really is executed —
//       mig_task_subsystem (0x14790) and vtable_bsdthread_register
//       (0x14364/0x1436C) plant its addresses as thread entry points — which is
//       where AbiKind_NewThread comes from and why the arm_tree walk alone
//       cannot replace this call.
//
//   the mapped blob              -> ours, keyed on offsets into our own
//       runtime_entry.S.  No 0x4000 bound: our blob is 0x4E7C and every byte of
//       it is addressable here.
//
//   translated guest code        -> the reference's offset-map decoder.
ObjcPcResult classify_arm_pc_objc_full(ThreadContext* ctx, uint32_t thread,
                                       uint64_t* out_x86_pc) {
    // Reached from the syscall dispatcher, which spills the guest GPRs to [x18]
    // and nothing else — no FP anywhere in runtime_syscall — so the guest's XMM
    // state is still live in v0-v7.  The reference survives without a guard only
    // because its codegen happens to be v-register-free (abi_info_for_runtime
    // zeroes its AbiInfo with `STP XZR, XZR` at 0xB1E8, not `movi v0.2d`); ours
    // is not, and AbiInfo/TranslatedCodePayload zero-inits are exactly the shape
    // clang lowers to `movi.2d v0` + `stur q0`.  v8-v15 are callee-saved, so
    // q0-q7 is the whole exposure.  The guard spans the entire body, including
    // the calls into reference code.
    SIMDGuardFull simdGuard;

    // Not zero-initialised: thread_get_state fills it and we only read `pc`
    // after it reports success.
    ArmThreadState64 state;
    uint32_t count = kArmThreadState64Count;

    if (!ctx || mach_thread_get_state(thread, kArmThreadState64Flavor, &state, &count) != 0)
        return kObjcPcCannotDetermine;   // 0x16024

    if (state.pc == 0) {                 // 0x16038: not executing guest code
        *out_x86_pc = 0;
        return kObjcPcOk;
    }

    const uintptr_t arm_pc = static_cast<uintptr_t>(state.pc);

    // 0x16050.  Writes kind unconditionally and zeroes the payload, so no
    // initialisation is needed here.
    AbiInfo info;
    g_abi_info_for_runtime(&info, arm_pc);
    if (info.kind != AbiKind_Unknown) {
        // 0x16060.  A thread still inside a thread-entry trampoline has never
        // run guest code, so "x86 pc 0" is exact.
        if (info.kind == AbiKind_NewThread) {
            *out_x86_pc = 0;
            return kObjcPcOk;
        }
        return objc_registry_answer(ctx, thread, out_x86_pc);
    }

    // No heap yet means no fragments yet; nothing to walk.
    if (!g_executable_heap)
        return objc_registry_answer(ctx, thread, out_x86_pc);

    ExecutableHeap* const heap = g_executable_heap;
    const uint32_t lock_owner = ctx->thread_port;

    os_unfair_lock_lock_no_tsd(&heap->arm_tree_lock, OS_UNFAIR_LOCK_DATA_SYNCHRONIZATION,
                               lock_owner);

    const CodeFragmentMetadata* const node = find_fragment_locked(arm_pc);
    if (!node) {
        os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, lock_owner);
        return objc_registry_answer(ctx, thread, out_x86_pc);
    }

    const CodeFragmentKind kind = node->kind;

    // Our mapped runtime_entry blob.  This is the arm the reference gets wrong.
    if (is_runtime_routines_kind(kind)) {
        AbiInfo blob;
        abi_info_for_runtime_routines_address(&blob,
                                              static_cast<uintptr_t>(arm_pc - node->arm_base));
        os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, lock_owner);

        // 0x161C4.  Blocked in the syscall stub: the guest GPRs are committed to
        // [x18] and the thread is definitively not inside an objc restartable
        // range, so "not executing guest code" is exact.  Every other blob kind
        // is transient and falls through to the registry.
        if (blob.kind == AbiKind_Syscall) {
            *out_x86_pc = 0;
            return kObjcPcOk;
        }
        return objc_registry_answer(ctx, thread, out_x86_pc);
    }

    // The translator binary / libRosettaRuntime images.  The reference ASSERT2s
    // here (0x161F8, "address is in a runtime code fragment but
    // abi_kind_for_runtime did not catch it") because abi_info_for_runtime
    // should already have claimed the pc.  It can miss — a pc in the translator
    // image at or above its in-image blob window returns Unknown and lands here
    // — so we answer instead of trapping.
    if (kind == CodeFragmentKind::RuntimeBinary) {
        os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, lock_owner);
        return objc_registry_answer(ctx, thread, out_x86_pc);
    }

    // Translated guest code.
    //
    // The reference first tests the fragment's x86 range against every
    // registered objc restartable range (0x16158-0x16184) and only decodes the
    // exact pc when one overlaps, answering with the coarse node->x86_base
    // otherwise.  We always decode instead: the exact pc is a strictly better
    // answer to the caller's real question ("is this thread inside a restartable
    // range?"), it agrees with the reference wherever the reference decodes, and
    // it removes any need for g_objc_restartable_ranges / _count / _valid.
    //
    // Retired fragments are the exception.  InvalidAot/InvalidJit are on their
    // way out and their offset maps may already be gone, so those keep the
    // coarse answer — the reference reaches them far more rarely and we would
    // rather not widen that exposure for a pc no thread should be executing.
    uint64_t x86_pc = node->x86_base;
    if (kind == CodeFragmentKind::Aot || kind == CodeFragmentKind::AotSharedCache ||
        kind == CodeFragmentKind::Jit) {
        // Decoded under the lock, as at 0x161D8.  Pre-seeded so a callee that
        // declines to write leaves us with the coarse answer rather than stack
        // garbage.
        TranslatedCodePayload payload;
        payload.x86_pc = x86_pc;
        g_instruction_extents_for_arm_address(&payload, node, arm_pc);
        x86_pc = payload.x86_pc;
    }

    os_unfair_lock_unlock_no_tsd(&heap->arm_tree_lock, lock_owner);

    *out_x86_pc = x86_pc;
    return kObjcPcOk;
}

// Is the pointer in vtable slot +0xF8 really classify_arm_pc_objc?
//
// We do not need this to FIND anything — thread_get_state is our own
// (MachIPC.cpp) and the function address comes from the slot.  It exists purely
// so that a future runtime which reorders the vtable makes us decline rather
// than call some unrelated handler through this signature.
//
// The fingerprint is the one thing this function does that its neighbours do
// not: set up thread_get_state(thread, ARM_THREAD_STATE64) with a THREAD_STATE
// count of 0x44.  The reference issues that call at +0x5C — instruction 23,
// behind 13 callee-save/frame instructions, the stack-cookie load, the
// ranges-initialised test and the argument shuffle — so the window has to reach
// past it.
bool looks_like_classify_arm_pc_objc(uintptr_t fn) {
    constexpr uint32_t kMovW8_0x44 = 0x52800888;  // MOV W8, #0x44   (state_count)
    constexpr uint32_t kMovW1_6 = 0x528000C1;     // MOV W1, #6      (flavor)
    constexpr unsigned kWindow = 32;

    const uint32_t* insns = reinterpret_cast<const uint32_t*>(fn);
    bool saw_count = false;
    bool saw_flavor = false;

    for (unsigned i = 0; i < kWindow; i++) {
        const uint32_t insn = insns[i];
        if (insn == kMovW8_0x44)
            saw_count = true;
        if (insn == kMovW1_6)
            saw_flavor = true;
        if (saw_count && saw_flavor)
            return true;
    }

    return false;
}

}  // namespace

void init_translation_cache_abi_hooks(uintptr_t classify_arm_pc_addr, uintptr_t rosettax87_base,
                                      size_t rosettax87_size) {
    g_rosettax87_base = rosettax87_base;
    g_rosettax87_size = rosettax87_size;

    if (classify_arm_pc_addr == 0)
        return;

    g_original_classify_arm_pc = reinterpret_cast<classify_arm_pc_t>(classify_arm_pc_addr);
    hook_install(reinterpret_cast<void*>(g_original_classify_arm_pc),
                 reinterpret_cast<void*>(&classify_arm_pc),
                 reinterpret_cast<void**>(&g_original_classify_arm_pc));
}

void init_classify_arm_pc_objc_hook(const ThreadContextVTable* vtable,
                                    uintptr_t abi_info_for_runtime_addr,
                                    uintptr_t thread_entry_for_port_addr,
                                    uintptr_t instruction_extents_for_arm_address_addr) {
    if (!vtable || !vtable->classify_arm_pc_objc)
        return;

    const uintptr_t target = reinterpret_cast<uintptr_t>(vtable->classify_arm_pc_objc);

    if (!looks_like_classify_arm_pc_objc(target)) {
#ifdef ROSETTA_RUNTIME
        printf(
            "RosettaRuntimex87: WARNING vtable slot +0xF8 at %p does not look like "
            "classify_arm_pc_objc — leaving it unhooked (a thread parked past blob offset 0x4000 "
            "will trip its kRuntimeRoutinesSize assert)\n",
            vtable->classify_arm_pc_objc);
#endif
        return;
    }

    g_abi_info_for_runtime =
        reinterpret_cast<abi_info_for_runtime_t>(abi_info_for_runtime_addr);
    g_thread_entry_for_port =
        reinterpret_cast<thread_entry_for_port_t>(thread_entry_for_port_addr);
    g_instruction_extents_for_arm_address =
        reinterpret_cast<instruction_extents_for_arm_address_t>(
            instruction_extents_for_arm_address_addr);

    // All three or none: the full replacement calls every one of them on some
    // path, and a null there would fault instead of merely misclassifying.
    const bool have_helpers = g_abi_info_for_runtime && g_thread_entry_for_port &&
                              g_instruction_extents_for_arm_address;

#ifdef ROSETTA_RUNTIME
    if (!have_helpers) {
        printf(
            "RosettaRuntimex87: WARNING classify_arm_pc_objc helpers unresolved "
            "(abi_info_for_runtime=%p thread_entry_for_port=%p "
            "instruction_extents_for_arm_address=%p) — installing the pre-filter hook; the "
            "thread_get_state race that trips kRuntimeRoutinesSize stays open\n",
            reinterpret_cast<void*>(abi_info_for_runtime_addr),
            reinterpret_cast<void*>(thread_entry_for_port_addr),
            reinterpret_cast<void*>(instruction_extents_for_arm_address_addr));
    }
#endif

    g_original_classify_arm_pc_objc = reinterpret_cast<classify_arm_pc_objc_t>(target);
    hook_install(reinterpret_cast<void*>(g_original_classify_arm_pc_objc),
                 reinterpret_cast<void*>(have_helpers ? &classify_arm_pc_objc_full
                                                      : &classify_arm_pc_objc_prefilter),
                 reinterpret_cast<void**>(&g_original_classify_arm_pc_objc));
}
