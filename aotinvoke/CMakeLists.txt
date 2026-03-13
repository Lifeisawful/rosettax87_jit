# ── aotinvoke executable ──────────────────────────────────────────────────────
add_executable(aotinvoke
	src/main.cpp
	src/RosettaAotApi.cpp
)

target_include_directories(aotinvoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(aotinvoke PRIVATE rosetta_core)
target_compile_options(aotinvoke PRIVATE -g)

add_custom_command(TARGET aotinvoke POST_BUILD
    COMMAND dsymutil "$<TARGET_FILE:aotinvoke>"
        -o "$<TARGET_FILE_DIR:aotinvoke>/$<TARGET_FILE_NAME:aotinvoke>.dSYM"
    VERBATIM)
