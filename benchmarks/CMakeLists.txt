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


function(add_x86_benchmark_lowzero name)
  set(output "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${name}")
  add_custom_command(
    OUTPUT "${output}"
    COMMAND /bin/zsh -lc "mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} && /usr/bin/clang -arch x86_64 -O2 -Wl,-pagezero_size,0x4000 -o ${output} ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    COMMENT "Building x86_64 ${name} with clang -O2 (low pagezero)"
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
add_x86_benchmark(bench_keepalive)
add_x86_benchmark(bench_fcmov)
add_x86_benchmark(bench_fusion_fld_arithp)
add_x86_benchmark(bench_fusion_fld_fstp)
add_x86_benchmark(bench_fusion_fld_arith_fstp)
add_x86_benchmark(bench_fusion_fld_fcomp_fstsw)
add_x86_benchmark(bench_fusion_fxch_arithp)
add_x86_benchmark(bench_fusion_fxch_fstp)
add_x86_benchmark(bench_fusion_fcom_fstsw)
add_x86_benchmark(bench_fusion_arithp_fstp)
add_x86_benchmark(bench_fusion_arith_fstp)
add_x86_benchmark(bench_fusion_arith_faddp)
add_x86_benchmark(bench_fusion_fld_arith_arithp)
add_x86_benchmark(bench_fstp_fld)
add_x86_benchmark(bench_round)
add_x86_benchmark(bench_fxch)
add_x86_benchmark(bench_fistt)
add_x86_benchmark(bench_tag_batch)
add_x86_benchmark(bench_fistp_multi)
add_x86_benchmark(bench_mem_cse)
add_x86_benchmark(bench_addr_fold)
add_x86_benchmark(bench_f32)
add_x86_benchmark(bench_fcos)
add_x86_benchmark(bench_trig)
add_x86_benchmark(bench_trig_run)
add_x86_benchmark(bench_pow)
add_x86_benchmark(bench_interleaved_mov)
add_x86_benchmark_lowzero(bench_const_promote)
add_subdirectory(macro)
