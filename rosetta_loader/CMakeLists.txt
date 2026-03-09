
# backwards compatibility with macOS 14 (Sonoma) and later
set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS deployment version")

project(rosetta_loader)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(runtime_loader
    src/main.cpp
    src/macho_loader.cpp
    src/offset_finder.cpp
)

set(ENTITLEMENTS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/entitlements.plist")
add_custom_command(TARGET runtime_loader POST_BUILD
    COMMAND codesign -s - --entitlements "${ENTITLEMENTS_FILE}" --force "$<TARGET_FILE:runtime_loader>"
    COMMENT "Signing runtime_loader with entitlements"
)

target_compile_features(runtime_loader PRIVATE cxx_std_23)
target_compile_options(runtime_loader PRIVATE -g)
