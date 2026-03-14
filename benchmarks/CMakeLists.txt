function(add_x86_benchmark name)
  set(output "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${name}")
  add_custom_command(
    OUTPUT "${output}"
    COMMAND /bin/zsh -lc "mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} && /usr/bin/clang -arch x86_64 -O2 -o ${output} ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    COMMENT "Building x86_64 ${name} with clang -O2"
    VERBATIM
  )
  add_custom_target(${name}_x86_64 ALL DEPENDS "${output}")
endfunction()

add_x86_benchmark(bench_constants)
add_x86_benchmark(bench_load)
add_x86_benchmark(bench_add)
add_x86_benchmark(bench_sub)
add_x86_benchmark(bench_mul)
add_x86_benchmark(bench_div)
add_x86_benchmark(bench_store)
add_x86_benchmark(bench_compare)
add_x86_benchmark(bench_unary)
add_x86_benchmark(bench_fcmov)
add_x86_benchmark(bench_fusion_fld_arithp)
add_x86_benchmark(bench_fusion_fld_fstp)
add_x86_benchmark(bench_fusion_fld_arith_fstp)
add_x86_benchmark(bench_fusion_fld_fcomp_fstsw)
add_x86_benchmark(bench_fusion_fxch_arithp)
add_x86_benchmark(bench_fusion_fxch_fstp)
add_x86_benchmark(bench_fusion_fcom_fstsw)
add_x86_benchmark(bench_round)
add_subdirectory(macro)
