#!/bin/bash

set -x

COMPILER=clang++

mkdir -p build
cd build
cmake .. -DCMAKE_CXX_COMPILER="$COMPILER"
cmake --build . -- -j$(nproc)
cp TrafficAnalyzer ../
