set(ROSETTA_CORE_SOURCES
    src/CoreLog.cpp
    src/CustomTranslationHook.cpp
    src/hook.cpp
    src/AssemblerHelpers.cpp
    src/IRBlock.cpp
    src/IRInstr.cpp
    src/IROperand.cpp
    src/ModuleResult.cpp
    src/ThreadContextOffsets.cpp
    src/TranslationResult.cpp
    src/AssemblerBuffer.cpp
    src/X87State.cpp
    src/Opcode.cpp
    src/AssemblerBase.cpp
    src/TranslatorHelpers.cpp
    src/Fixup.cpp
    src/Register.cpp
    src/Translator.cpp
    src/TranslatorX87.cpp
    src/TranslatorX87Helpers.cpp
    src/RuntimeRoutine.cpp
    src/RuntimeLibC.cpp
    src/IRModuleData.cpp
)

# --- Standard build (used by aotinvoke / oahd_inject) ---
add_library(rosetta_core STATIC ${ROSETTA_CORE_SOURCES})
target_include_directories(rosetta_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rosetta_core PUBLIC cxx_std_23)
target_compile_options(rosetta_core PRIVATE -g)

# --- Runtime build (used by rosetta_runtime / libRuntimeRosettax87) ---
add_library(rosetta_core_runtime STATIC ${ROSETTA_CORE_SOURCES})
target_include_directories(rosetta_core_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rosetta_core_runtime PUBLIC cxx_std_23)
target_compile_options(rosetta_core_runtime PRIVATE
    -fvisibility=hidden
    -O3
    -funroll-loops
    -march=native
    -mtune=native
    -fomit-frame-pointer
    -mcpu=apple-m1
    -fno-builtin-sin
    -fno-builtin-printf
    -fno-builtin-puts
    -fno-builtin-putchar
    -ftree-vectorize
    -fvectorize
    -finline-functions
    -fno-stack-protector
    -fno-exceptions
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -flto
)
target_compile_definitions(rosetta_core_runtime PRIVATE ROSETTA_RUNTIME=1)
target_sources(rosetta_core_runtime PRIVATE
    src/RuntimeOperatorNew.cpp
    src/RuntimeSymbols.cpp
)
