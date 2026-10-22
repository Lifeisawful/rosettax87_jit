#include <cstdarg>
#include <cstdint>

#include "RuntimeLibrary.h"

#include "RuntimeOffsets.h"
#include "RuntimeConfig.h"

#include "ExecutableHeap.h"
#include "Export.h"
#include "TranslationCacheAbi.h"
#include "Library.h"

#include "rosetta_core/CoreConfig.h"
#include "rosetta_core/RosettaCore.h"
#include "rosetta_core/RuntimeLibC.h"

static void runtime_early_init() {
    rosetta_set_config(&kConfig);

    // Publish the runtime version before anything that branches on it.
    //
    // rosetta_core_init() cannot run until init_library (it needs
    // libRosettaRuntime's addresses), but the runtime's main() allocates the first
    // ExecutableHeap chunk BEFORE calling init_library — so the allocate_chunk hook
    // below has to pick its ABI now.  kImports.version is already valid: the loader
    // writes it into __DATA,imports before it runs our _start.
    rosetta_core_set_runtime_version(kImports.version);

    uintptr_t classify_arm_pc_ptr = kOffsets.runtime_base + kOffsets.classify_arm_pc_rva;
    // Both live in the runtime image (/usr/libexec/rosetta/runtime), not in
    // libRosettaRuntime — same base as classify_arm_pc above.
    uintptr_t runtime_routines_for_address_ptr =
        kOffsets.runtime_base + kOffsets.runtime_routines_for_address_rva;
    uintptr_t allocate_chunk_ptr = kOffsets.runtime_base + kOffsets.allocate_chunk_rva;
    // Guard the zero case explicitly: a 0 rva would otherwise yield runtime_base,
    // i.e. a valid-looking but wrong function pointer.
    uintptr_t trace_write_mapping_record_ptr =
        kOffsets.trace_write_mapping_record_rva
            ? kOffsets.runtime_base + kOffsets.trace_write_mapping_record_rva
            : 0;

    init_translation_cache_abi_hooks(classify_arm_pc_ptr, kOffsets.rosettax87_base,
                                     kOffsets.rosettax87_size);

    // Required on a 26.4+ runtime, where allocate_chunk no longer receives the
    // heap; zero (and unused) on 15.  Same zero-guard as above: a 0 rva would
    // otherwise resolve to runtime_base.
    uintptr_t executable_heap_ptr = kOffsets.executable_heap_rva
                                        ? kOffsets.runtime_base + kOffsets.executable_heap_rva
                                        : 0;

    init_executable_heap_hooks(allocate_chunk_ptr, runtime_routines_for_address_ptr,
                               trace_write_mapping_record_ptr, executable_heap_ptr);

    uintptr_t bind_library_stubs_ptr =
        kOffsets.bind_library_stubs_rva
            ? kOffsets.runtime_base + kOffsets.bind_library_stubs_rva
            : 0;
    init_bind_library_stubs_hook(bind_library_stubs_ptr);
}

// Image entry point (-Wl,-e,_start), recorded in LC_UNIXTHREAD.
//
// The loader calls this on the tracee's stopped thread right after mapping and
// relocating our image, BEFORE the Rosetta runtime's main() runs. That timing is
// the whole point: main() creates the first ExecutableHeap chunk at 0x12620,
// long before exports_fetch (0x1289c) where the loader used to first get
// control, so hooks installed from init_library missed chunk 0 entirely.
//
// Nothing here may touch kImports' export TABLES — libRosettaRuntime is not
// mapped yet, and those pointers are filled in-process later by the
// bind_library_stubs hook. kImports.version is the exception: the loader writes it
// into __DATA,imports before calling us, so runtime_early_init reads it to pick the
// version-dependent allocate_chunk ABI.
//
// This is a plain call, not a constructor: with -nostdlib/-static and a custom
// entry point the link emits no __mod_init_func array, so __attribute__((constructor))
// would silently never run.
//
// _start does NOT return. It ends in a BRK, which is how it hands control back to
// the loader: the loader sets PC here, resumes, and catches the resulting
// EXC_BREAKPOINT on its task-level exception port, then restores the thread state
// it saved. That removes the need for the loader to pick a return address and
// plant/remove a breakpoint there.
//
// This is only safe because the loader is the sole caller. Nothing else in the
// process ever enters _start, so the trap is unreachable in every other path. If
// that ever changes, this must go back to a normal `ret` with a loader-planted
// breakpoint — an uncaught BRK here would kill the tracee with SIGTRAP.
using mod_init_func_t = void (*)();

extern "C"
    __attribute__((used, visibility("default"), section("__TEXT,__text"), noinline, retain)) void
    start(mod_init_func_t* mod_inits, uint64_t mod_inits_size) {
    if (mod_inits && mod_inits_size) {
        for (auto i = 0; i < mod_inits_size / sizeof(mod_init_func_t); i++) {
            if (const auto mod_init = mod_inits[i]) {
                mod_init();
            }
        }
    }

    runtime_early_init();

    // Hand control back to the loader. `brk #0` matches the loader's
    // AARCH64_BREAKPOINT (0xD4200000) and its EXC_BREAKPOINT handling.
    __asm__ __volatile__("brk #0");
    __builtin_unreachable();
}

namespace std {
inline namespace __1 {
// Freestanding trap for the no-exceptions throw-helpers pulled in by
// std::optional / std::function from rosetta_core_runtime. Newer libc++
// (macos-26 CI) routes these through __libcpp_verbose_abort; -nostdlib does
// not provide it. Match its signature and mangling exactly.
[[noreturn]] __attribute__((used, visibility("default"))) void __libcpp_verbose_abort(
    const char* /*fmt*/, ...) {
    __builtin_trap();
}
}  // namespace __1
}  // namespace std
