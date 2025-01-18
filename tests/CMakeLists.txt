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
    "http.pcap"
    "single_packet.pcap"
)
foreach(file ${PCAP_FILES})
    configure_file(${PCAP_FILES_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY)
endforeach()

set(RULE_FILES_DIR "${CMAKE_SOURCE_DIR}/tests/rule_files")
set(RULE_FILES
    "1_sig.rule"
    "1_sig_with_offset.rule"
    "2_rules_same_sig.rule"
    "2_rules.rule"
    "2_sig.rule"
    "bad.rule"
    "double_packets_one_hit.rule"
    "empty.rule"
)
foreach(file ${RULE_FILES})
    configure_file(${RULE_FILES_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY)
endforeach()

add_executable(runTests
    # test_1.cpp
    internal_structs_test.cpp
    pcap_reader_test.cpp
    logger_test.cpp
    events_handler_test.cpp
    analyzer_test.cpp
    packet_processors_pool_test.cpp
    ids_test.cpp
    pcap_writer_test.cpp
)

target_link_libraries(runTests GTest::gtest GTest::gtest_main FlowInspectorLibrary)

include(GoogleTest)
gtest_discover_tests(runTests)
