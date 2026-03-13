cmake_minimum_required(VERSION 3.20)

project(rosetta_aot C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
foreach(cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

add_subdirectory(rosetta_core)
add_subdirectory(rosetta_runtime)
add_subdirectory(rosetta_loader)
add_subdirectory(sample)
