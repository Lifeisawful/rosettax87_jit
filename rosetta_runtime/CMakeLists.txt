project(rosetta_runtime)

enable_language(ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPTIMIZATION_FLAGS
    "-fvisibility=hidden"
    "-O3"
    "-funroll-loops"
    "-march=native"
    "-mtune=native"
    "-fomit-frame-pointer"
    "-mcpu=apple-m1"
    "-fno-builtin-sin"
    "-ftree-vectorize"
    "-fvectorize"
    "-finline-functions"
    "-fno-stack-protector"
    "-fno-exceptions"
    "-fno-unwind-tables"
    "-fno-asynchronous-unwind-tables"
)

add_executable(libRuntimeRosettax87
    src/main.cpp
    src/X87Float80.cpp
    src/X87StackRegister.cpp
    src/X87State.cpp
    src/X87.cpp
    src/Export.cpp
    src/Log.cpp
    src/SIMDGuard.cpp
    src/Offsets.cpp
    src/RuntimeConfig.cpp
    src/RuntimeLibrary.cpp
    src/TranslationCacheAbi.cpp
    src/Library.cpp
    src/RuntimeRoutineOffsets.cpp
    src/runtime_entry.S
    src/runtime_stubs.cpp
    src/ExecutableHeap.cpp
    src/SlabAllocator.cpp
    src/BestFitAllocator.cpp
    src/CodeFragmentMetadata.cpp
    src/Lock.cpp
    src/RedBlackTree.cpp
    src/ThreadSelfRestrict.cpp
    src/MachIPC.cpp
)

target_include_directories(libRuntimeRosettax87 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_options(libRuntimeRosettax87 PRIVATE
    "-Wl,-no_compact_unwind"
#    "-Wl,-no_pie"
    "-static"
    "-nostdlib"
#    "-Wl,-segaddr,__TEXT,0x0"
#    "-Wl,-segaddr,__DATA,0x50000"
    "-Wl,-pagezero_size,0x0"
    "-Wl,-headerpad,0"
    "-Wl,-e,_start"
    "-Wl,-segalign,1"

    # Make the runtime_entry blob's segments EXECUTABLE.
    #
    # ld only grants execute to segments it recognises; a custom segment name
    # defaults to rw (initprot/maxprot 0x3) even when its sections are flagged
    # pure_instructions. That is fatal here: allocate_chunk mach_vm_remaps this
    # blob into the JIT heap, and mach_vm_remap propagates the SOURCE's
    # protection — so a non-executable source produced a non-executable stub
    # page, and the first branch into it died with
    # EXC_BAD_ACCESS / KERN_PROTECTION_FAILURE on the instruction fetch.
    # maxprot must be rx too, else execute could never be granted later.
    "-Wl,-segprot,runtime_entry,rx,rx"
    "-Wl,-segprot,runtime_savedreg,rx,rx"
    "-Wl,-segprot,runtime_br_miss,rx,rx"
    "-Wl,-segprot,runtime_exit_ret,rx,rx"
    "-Wl,-segprot,runtime_exitcall,rx,rx"
    "-Wl,-segprot,runtime_exitljmp,rx,rx"
    "-Wl,-segprot,runtime_exit_br,rx,rx"
    "-Wl,-segprot,runtime_exit_sys,rx,rx"
    "-Wl,-segprot,runtime_exitinst,rx,rx"
    "-Wl,-segprot,runtime_exitsigr,rx,rx"
    "-Wl,-segprot,runtime_savdnzcv,rx,rx"
    "-Wl,-segprot,runtime_sigtramp,rx,rx"
    "-Wl,-segprot,runtime_thread,rx,rx"
    "-Wl,-segprot,runtime_pthread,rx,rx"
    "-Wl,-segprot,runtime_wqthread,rx,rx"
    "-Wl,-segprot,runtime_syscall,rx,rx"
    "-Wl,-fixup_chains_section"          # emit LC_DYLD_CHAINED_FIXUPS so we can rebase
)

set_property(TARGET libRuntimeRosettax87 PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_compile_options(libRuntimeRosettax87 PRIVATE
    ${OPTIMIZATION_FLAGS}
)

target_compile_definitions(libRuntimeRosettax87 PRIVATE
    "ROSETTA_RUNTIME=1"
)

target_link_libraries(libRuntimeRosettax87 PRIVATE rosetta_core_runtime rosetta_shared)
add_dependencies(libRuntimeRosettax87 rosetta_core_runtime)
