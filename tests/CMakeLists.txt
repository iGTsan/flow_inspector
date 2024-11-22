include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip
)

FetchContent_MakeAvailable(googletest)

add_executable(runTests test_1.cpp)

target_link_libraries(runTests GTest::gtest GTest::gtest_main TrafficAnalyzerLibrary)

include(GoogleTest)
gtest_discover_tests(runTests)
