cmake_minimum_required(VERSION 3.1)

# We want to be able to group together projects into sub folders in the Visual Studio IDE
#   If you don't want to see sub folders and prefer everything at the top level set the to "Off"
set_property(GLOBAL PROPERTY USE_FOLDERS "On")

# Add the root of the source tree to the compilation include path
include_directories(${CMAKE_SOURCE_DIR})

project(date)

# Compiler/linker flags 
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-std=c++14)
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    # Use the Clang standard C++ library
    add_compile_options(-std=c++14)
    add_compile_options(-stdlib=libc++)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libc++")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -stdlib=libc++")

    # May be useful at some point for Clang pretending to be MS CL
    if ("${CMAKE_GENERATOR_TOOLSET}" STREQUAL "LLVM-vs2014")
    endif( )
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
else()
    message( FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER_ID} is not recognized." )
endif()

enable_testing()

set(AllFiles
    date.h
    tz.h
    tz.cpp
    tz_private.h
    README.md
    CMakeLists.txt)

source_group("" FILES ${AllFiles})

add_library(${PROJECT_NAME} SHARED ${AllFiles} CMakeLists.txt)
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION bin)


add_subdirectory(test/date_test)
add_subdirectory(test/tz_test)
