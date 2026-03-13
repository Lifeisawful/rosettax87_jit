add_library(rosetta_config STATIC src/Config.cpp)
target_include_directories(rosetta_config PUBLIC include)
target_compile_features(rosetta_config PUBLIC cxx_std_23)
