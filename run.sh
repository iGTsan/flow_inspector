#!/bin/bash

set -x

COMPILER=clang++

mkdir -p build
cd build
rm CMakeCache.txt
cmake .. -DCMAKE_CXX_COMPILER="$COMPILER" -DCMAKE_BUILD_TYPE=Release
# cmake .. -DCMAKE_CXX_COMPILER="$COMPILER" -DCMAKE_BUILD_TYPE=Debug
cmake --build . -- -j$(nproc)
cp FlowInspector ../
