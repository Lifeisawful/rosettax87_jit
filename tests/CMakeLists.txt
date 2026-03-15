function(add_x86_sample name)
  set(output "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${name}")
  add_custom_command(
    OUTPUT "${output}"
    COMMAND /bin/zsh -lc "mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} && /usr/bin/clang -arch x86_64 -O0 -g -o ${output} ${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c"
    COMMENT "Building x86_64 ${name} with clang"
    VERBATIM
  )
  add_custom_target(${name}_x86_64 ALL DEPENDS "${output}")
endfunction()

add_x86_sample(test_fldconst)
add_x86_sample(test_fld)
add_x86_sample(test_fld_m80fp)
add_x86_sample(test_fmul)
add_x86_sample(test_fild)
add_x86_sample(test_fcom)
add_x86_sample(test_peephole)
add_x86_sample(test_arith)
add_x86_sample(test_compare_unary)
add_x86_sample(test_fld_fst)
add_x86_sample(test_fcomp_mem)
add_x86_sample(test_peephole3)
add_x86_sample(test_peephole4)
add_x86_sample(test_peephole5)
add_x86_sample(test_peephole6)
add_x86_sample(test_deep_stack)
add_x86_sample(test_x87_full)
add_x86_sample(test_fstpt)
add_x86_sample(test_peephole7)
add_x86_sample(test_fcom_nzcv)
add_x86_sample(test_fxam)
add_x86_sample(test_arithp_fstp)
