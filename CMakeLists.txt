cmake_minimum_required(VERSION 3.10)

project(PassiveTrafficAnalyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CONCURRENTQUEUE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/concurrentqueue)
set(CXXOPTS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cxxopts/include)

find_package(Pcap REQUIRED)

add_library(TrafficAnalyzerLibrary src/ids_lib.cpp)
target_include_directories(TrafficAnalyzerLibrary PUBLIC include)
include_directories(${CONCURRENTQUEUE_INCLUDE_DIR})
include_directories(${CXXOPTS_INCLUDE_DIR})
target_link_libraries(TrafficAnalyzerLibrary ${PCAP_LIBRARIES})

add_executable(TrafficAnalyzer src/main.cpp)
target_link_libraries(TrafficAnalyzer TrafficAnalyzerLibrary)

target_include_directories(TrafficAnalyzer PRIVATE ${PCAP_INCLUDE_DIRS})

target_compile_options(TrafficAnalyzer PRIVATE -Wall -Wextra -Werror)

enable_testing()

add_subdirectory(tests)
