cmake_minimum_required(VERSION 3.10)

project(PassiveFlowInspector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED On)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CONCURRENTQUEUE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/concurrentqueue)
set(CXXOPTS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cxxopts/include)

find_package(Pcap REQUIRED)
add_subdirectory("${CMAKE_SOURCE_DIR}/third_party/PcapPlusPlus")

add_library(FlowInspectorLibrary
    src/analyzer.cpp
    src/content_signature.cpp
    src/events_handler.cpp
    src/ids_cli.cpp
    src/ids.cpp
    src/internal_structs.cpp
    src/ip_signature.cpp
    src/logger.cpp
    src/packet_origin.cpp
    src/packet_processors_pool.cpp
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/raw_bytes_signature.cpp
    src/signature_factory.cpp
    src/tcp_signature.cpp
    src/traffic_capturer.cpp)

target_include_directories(FlowInspectorLibrary PUBLIC include)
include_directories(${CONCURRENTQUEUE_INCLUDE_DIR})
include_directories(${CXXOPTS_INCLUDE_DIR})
target_link_libraries(FlowInspectorLibrary ${PCAP_LIBRARIES})
target_link_libraries(FlowInspectorLibrary Pcap++ Packet++ Common++)

add_executable(FlowInspector src/main.cpp)
target_link_libraries(FlowInspector FlowInspectorLibrary)

target_include_directories(FlowInspector PRIVATE ${PCAP_INCLUDE_DIRS})

target_compile_options(FlowInspector PRIVATE -Wall -Wextra -Werror)

enable_testing()

add_subdirectory(tests)
