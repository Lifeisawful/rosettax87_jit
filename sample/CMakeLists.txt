project(samples C)

# All samples are x86_64 cross-compiled with x87 FPU math (no SSE)
set(X87_C_FLAGS -mno-sse -mfpmath=387)

# --- helper: add an x87 sample executable --------------------------------
function(add_x87_sample name)
    cmake_parse_arguments(ARG "" "OPTIMIZE" "" ${ARGN})
    if(NOT ARG_OPTIMIZE)
        set(ARG_OPTIMIZE "-O0")
    endif()

    add_executable(${name} ${name}.c)
    set_target_properties(${name} PROPERTIES OSX_ARCHITECTURES x86_64)
    target_compile_options(${name} PRIVATE ${X87_C_FLAGS} ${ARG_OPTIMIZE})
endfunction()

# --- samples --------------------------------------------------------------
add_x87_sample(math)
add_x87_sample(fsqrt)
add_x87_sample(cpuid)
add_x87_sample(wow OPTIMIZE -O2)
