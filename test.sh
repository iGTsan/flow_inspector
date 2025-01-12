#!/bin/bash

set -x

SANITIZER=$1
SANITIZER_FLAGS=""
BUILD_TYPE="Release"
ENABLE_VALGRIND=0

COMPILER=$(g++ --version | head -n 1)
USING_CLANG=false
if [[ $COMPILER == *"clang"* ]]; then
    USING_CLANG=true
fi

case $SANITIZER in
    "")
        SANITIZER_FLAGS=""
        ;;
    address)
        SANITIZER_FLAGS="-fsanitize=address -g"
        BUILD_TYPE="Debug"
        ;;
    undefined)
        SANITIZER_FLAGS="-fsanitize=undefined -g"
        BUILD_TYPE="Debug"
        ;;
    thread)
        SANITIZER_FLAGS="-fsanitize=thread -g"
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
    *)
        echo "Invalid sanitizer option. Available sanitizers: none, address, undefined, thread, memory"
        exit 1
        ;;
esac

mkdir -p build
cd build
cmake -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS"\
    -DCMAKE_EXE_LINKER_FLAGS_DEBUG="$SANITIZER_FLAGS"\
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..
cmake --build . -- -j$(nproc)
if [ "$ENABLE_VALGRIND" = "1" ]; then
    cd tests
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./runTests
else
    ctest --output-on-failure
fi
