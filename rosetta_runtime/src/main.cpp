#include <cstdarg>

#include "RuntimeLibrary.h"

// Image entry point (-Wl,-e,_start), recorded in LC_UNIXTHREAD.
//
// The loader calls this on the tracee's stopped thread right after mapping and
// relocating our image, BEFORE the Rosetta runtime's main() runs. That timing is
// the whole point: main() creates the first ExecutableHeap chunk at 0x12620,
// long before exports_fetch (0x1289c) where the loader used to first get
// control, so hooks installed from init_library missed chunk 0 entirely.
//
// Nothing here may touch kImports — libRosettaRuntime is not mapped yet. See
// runtime_early_init.
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
extern "C"
    __attribute__((used, visibility("default"), section("__TEXT,__text"), noinline, retain)) void
    start() {
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
[[noreturn]] __attribute__((used, visibility("default")))
void __libcpp_verbose_abort(const char* /*fmt*/, ...) {
    __builtin_trap();
}
} // namespace __1
} // namespace std
