#!/bin/bash

set -x

SANITIZER=$1
SANITIZER_FLAGS=""
BUILD_TYPE="Release"
ENABLE_VALGRIND=0

COMPILER=clang++
ROOT=$(pwd)

case $SANITIZER in
    "")
        SANITIZER_FLAGS=""
        ;;
    address)
        SANITIZER_FLAGS="-fsanitize=address -g -fPIE -fno-omit-frame-pointer"
        BUILD_TYPE="Debug"
        ;;
    undefined)
        SANITIZER_FLAGS="-fsanitize=undefined -g -fPIE -fno-omit-frame-pointer"
        BUILD_TYPE="Debug"
        ;;
    thread)
        SANITIZER_FLAGS="-fsanitize=thread -g -fPIE -fno-omit-frame-pointer"
        BUILD_TYPE="Debug"
        ;;
    memory)
        # MemorySanitizer поддерживается только в Clang
        # if [ "$USING_CLANG" = true ]; then
        if [ false = true ]; then
            SANITIZER_FLAGS="-fsanitize=memory -g -fPIE -fno-omit-frame-pointer"
        else
            ENABLE_VALGRIND=1
        fi
        BUILD_TYPE="Debug"
        ;;
    coverage)
        SANITIZER_FLAGS="--coverage"
        BUILD_TYPE="Debug"
        COMPILER=g++
        # to run it:
        # lcov --capture --directory . --output-file coverage.info --ignore-errors inconsistent
        # genhtml coverage.info --output-directory out --ignore-errors inconsistent
        ;;
    *)
        echo "Invalid sanitizer option. Available sanitizers: none,\
            address, undefined, thread, memory, coverage"
        exit 1
        ;;
esac

if [ "$ENABLE_VALGRIND" = "1" ]; then
    # cd tests
    # valgrind --leak-check=full --suppressions=$ROOT/valgrind.supp --show-leak-kinds=all --track-origins=yes ./runTests
    docker build -f tests/docker_env/Dockerfile -t mymemcheck:latest .
    docker run --rm mymemcheck:latest
else
    mkdir -p build
    cd build
    cmake .. -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS_DEBUG="$SANITIZER_FLAGS" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_CXX_COMPILER="$COMPILER"
    cmake --build . -- -j$(nproc)
    ctest --output-on-failure
    
fi
