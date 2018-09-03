#!/bin/bash
set -e
set -x

uname -a

cmake -H. -B_build_${TOOLCHAIN} -DCMAKE_TOOLCHAIN_FILE="${PWD}/ci/toolchains/${TOOLCHAIN}.cmake" \
	-DUSE_SYSTEM_TZ_DB=ON \
	-DENABLE_DATE_TESTING=ON \
	-DDISABLE_STRING_VIEW=${DISABLE_STRING_VIEW}
cmake --build _build_${TOOLCHAIN} --target testit -- -j4

