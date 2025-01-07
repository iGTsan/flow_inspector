include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip
)

FetchContent_MakeAvailable(googletest)

set(PCAP_FILES_DIR "${CMAKE_SOURCE_DIR}/tests/pcap_files")

set(PCAP_FILES
    "double_packets.pcap"
    "empty.pcap"
    "single_packet.pcap"
)

foreach(file ${PCAP_FILES})
    configure_file(${PCAP_FILES_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY)
endforeach()

add_executable(runTests
    test_1.cpp
    internal_structs_test.cpp
    pcap_reader_test.cpp
    logger_test.cpp
    events_handler_test.cpp
)

target_link_libraries(runTests GTest::gtest GTest::gtest_main TrafficAnalyzerLibrary)

include(GoogleTest)
gtest_discover_tests(runTests)
