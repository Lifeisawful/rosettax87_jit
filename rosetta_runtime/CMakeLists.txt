project(rosetta_runtime)

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
)

target_include_directories(libRuntimeRosettax87 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_options(libRuntimeRosettax87 PRIVATE
    "-O3"
    "-Wl,-no_compact_unwind"
#    "-Wl,-no_pie"
    "-static"
    "-nostdlib"
#    "-Wl,-segaddr,__TEXT,0x0"
#    "-Wl,-segaddr,__DATA,0x50000"
    "-Wl,-pagezero_size,0x0"
    "-Wl,-headerpad,0"
    "-Wl,-e,_start"
    "-Wl,-segalign,10"
    "-Wl,-fixup_chains_section"          # emit LC_DYLD_CHAINED_FIXUPS so we can rebase
)

set_property(TARGET libRuntimeRosettax87 PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_compile_options(libRuntimeRosettax87 PRIVATE
    ${OPTIMIZATION_FLAGS}
)

target_compile_definitions(libRuntimeRosettax87 PRIVATE
    "ROSETTA_RUNTIME=1"
)

target_link_libraries(libRuntimeRosettax87 PRIVATE rosetta_core_runtime)
add_dependencies(libRuntimeRosettax87 rosetta_core_runtime)
