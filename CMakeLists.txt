cmake_minimum_required(VERSION 3.10)

project(PassiveFlowInspector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CONCURRENTQUEUE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/concurrentqueue)
set(CXXOPTS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cxxopts/include)

find_package(Pcap REQUIRED)

add_library(FlowInspectorLibrary src/ids_lib.cpp)
target_include_directories(FlowInspectorLibrary PUBLIC include)
include_directories(${CONCURRENTQUEUE_INCLUDE_DIR})
include_directories(${CXXOPTS_INCLUDE_DIR})
target_link_libraries(FlowInspectorLibrary ${PCAP_LIBRARIES})

add_executable(FlowInspector src/main.cpp)
target_link_libraries(FlowInspector FlowInspectorLibrary)

target_include_directories(FlowInspector PRIVATE ${PCAP_INCLUDE_DIRS})

target_compile_options(FlowInspector PRIVATE -Wall -Wextra -Werror)

enable_testing()

add_subdirectory(tests)
