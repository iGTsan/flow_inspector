cmake_minimum_required(VERSION 3.10)

project(PassiveTrafficAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(TrafficAnalyzerLibrary src/ids_lib.cpp)
target_include_directories(TrafficAnalyzerLibrary PUBLIC include)

add_executable(TrafficAnalyzer src/main.cpp)

enable_testing()

add_subdirectory(tests)

target_link_libraries(TrafficAnalyzer TrafficAnalyzerLibrary)

target_compile_options(TrafficAnalyzer PRIVATE -Wall -Wextra -Werror)