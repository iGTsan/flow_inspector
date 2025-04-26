#!/bin/bash

set -x

COMPILER=clang++

mkdir -p build
cd build
rm CMakeCache.txt
# cmake -DCMAKE_C_FLAGS="--coverage -O0" -DCMAKE_CXX_FLAGS="--coverage -O0" -DCMAKE_BUILD_TYPE=Debug ..
cmake .. -DCMAKE_CXX_COMPILER="$COMPILER" -DCMAKE_BUILD_TYPE=Release
# cmake .. -DCMAKE_CXX_COMPILER="$COMPILER" -DCMAKE_BUILD_TYPE=Debug
make clean
cmake --build . -- -j$(nproc)
cp FlowInspector ../
