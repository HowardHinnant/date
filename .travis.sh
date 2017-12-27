#!/bin/bash

set -e

if [[ ${CC} == "clang" ]]; then
    CMAKE_FLAGS='-DCMAKE_CXX_FLAGS=-stdlib=libc++'
fi

cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ${CMAKE_FLAGS}
make
