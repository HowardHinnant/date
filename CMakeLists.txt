
cmake_minimum_required(VERSION 3.2)

# We want to be able to group together projects into sub folders in the Visual Studio IDE
#   If you don't want to see sub folders and prefer everything at the top level set the to "Off"
set_property(GLOBAL PROPERTY USE_FOLDERS "On")

# Add the root of the source tree to the compilation include path
include_directories(${CMAKE_SOURCE_DIR})

# Are we building shared or static libraries, shared at the moment
set(LIBRARY_SHARED_OR_STATIC SHARED)

project(date)

set(AllFiles
    date.h
	tz.h
	tz.cpp
	tz_private.h
	README.md
	CMakeLists.txt)

source_group("" FILES ${AllFiles})

add_library(${PROJECT_NAME} ${LIBRARY_SHARED_OR_STATIC} ${AllFiles} CMakeLists.txt)

add_subdirectory(test/date_test)
add_subdirectory(test/tz_test)