# Copyright (c) 2016 Chase Geigle
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Attempts to find libc++ and an appropriate ABI (libc++abi or libcxxrt)
# when using clang and libc++ together.
# Defines:
# - LIBCXX_OPTIONS
# - LIBCXX_INCLUDE_DIR
# - CXXABI_LIBRARY
# - CMAKE_REQUIRED_FLAGS
# - CMAKE_REQUIRED_INCLUDES

message("-- Locating libc++...")
find_library(LIBCXX_LIBRARY NAMES c++ cxx)
if(LIBCXX_LIBRARY)
  message("-- Located libc++: ${LIBCXX_LIBRARY}")
  set(LIBCXX_OPTIONS "-stdlib=libc++")
  get_filename_component(LIBCXX_LIB_PATH ${LIBCXX_LIBRARY}
    DIRECTORY)
  find_path(LIBCXX_PREFIX c++/v1/algorithm
    PATHS ${LIBCXX_LIB_PATH}/../include
    ${CMAKE_SYSTEM_PREFIX_PATH}
    /Library/Developer/CommandLineTools/usr/include)
  if (LIBCXX_PREFIX)
    set(LIBCXX_INCLUDE_DIR ${LIBCXX_PREFIX}/c++/v1/)
    message("-- Located libc++ include path: ${LIBCXX_INCLUDE_DIR}")
  else()
    message("-- Failed to find libc++ include path!")
  endif()

  message("--     Locating libc++'s abi...")
  find_library(LIBCXXABI_LIBRARY NAMES c++abi)
  find_library(LIBCXXRT_LIBRARY NAMES cxxrt)
  if(LIBCXXABI_LIBRARY)
    message("--     Found libc++abi: ${LIBCXXABI_LIBRARY}")
    set(CXXABI_LIBRARY ${LIBCXXABI_LIBRARY})
  elseif(LIBCXXRT_LIBRARY)
    message("--     Found libcxxrt: ${LIBCXXRT_LIBRARY}")
    set(CXXABI_LIBRARY ${LIBCXXRT_LIBRARY})
  else()
    message("--     No abi library found. "
      "Attempting to continue without one...")
    set(CXXABI_LIBRARY "")
  endif()
else()
  message("-- Could not find libc++!")
endif()

macro(set_libcxx_required_flags)
  if (LIBCXX_OPTIONS)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${LIBCXX_OPTIONS}")
  endif()

  if (CXXABI_LIBRARY)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${LIBCXX_OPTIONS} ${CXXABI_LIBRARY} -L${LIBCXX_LIB_PATH}")
  endif()
  if (LIBCXX_INCLUDE_DIR)
    set(CMAKE_REQUIRED_INCLUDES "${CMAKE_REQUIRED_INCLUDES} ${LIBCXX_INCLUDE_DIR}")
  endif()
endmacro()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBCXX DEFAULT_MSG
  LIBCXX_LIBRARY
  LIBCXX_INCLUDE_DIR
  LIBCXX_LIB_PATH
  LIBCXX_OPTIONS
  CXXABI_LIBRARY)
