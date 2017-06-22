# The MIT License (MIT)
#
# Copyright (c) 2017 Aaron Bishop, Tommy Nguyen
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
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

cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(date VERSION 2.1 LANGUAGES CXX)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
	set(NEED_PARENT Off)
	set(DATE_DEFAULT_ENABLE_TESTS On)
else()
	set(NEED_PARENT On)
	set(DATE_DEFAULT_ENABLE_TESTS Off)
endif()

find_package(CURL)

if(WIN32)
	find_program(DATE_TZ_SHELL_REMOVE_DIRECTORY "rd")
	find_program(DATE_TZ_SHELL_REMOVE_FILE "del")
	find_program(DATE_TZ_SHELL_MOVE_FILE "move")
	find_program(DATE_TZ_SHELL_UNTAR "7z.exe" PATHS "$ENV{ProgramFiles}/7-Zip")
else()
	find_program(DATE_TZ_SHELL_REMOVE_DIRECTORY "rm")
	find_program(DATE_TZ_SHELL_REMOVE_FILE "rm")
	find_program(DATE_TZ_SHELL_MOVE_FILE "mv")
	find_program(DATE_TZ_SHELL_UNTAR "tar")
endif()
find_program(DATE_TZ_SHELL_MAKE_DIRECTORY "mkdir")

option(DATE_ENABLE_TESTS "Build unit tests" ${DATE_DEFAULT_ENABLE_TESTS})
option(DATE_NO_TZ        "Disable building Time Zone static library" Off)
if(NOT DATE_NO_TZ)
	option(DATE_TZ_NO_LAZY   "Disable lazy initialization of time zones" Off)
	if(CURL_FOUND)
		message("Found cURL, enabling remote")
		option(DATE_TZ_NO_REMOTE "Disable using cURL to download IANA Time Zone rules" Off)
	else()
		message(WARNING "Could not find cURL libraries. Disabling remote.")
		option(DATE_TZ_NO_REMOTE "Disable using cURL to download IANA Time Zone rules" On)
	endif()
	if(WIN32)
		option(DATE_TZ_NO_TZMAP  "Disable Time Zone name mapping on Windows" Off)
	else()
		option(DATE_TZ_NO_TZMAP  "Disable Time Zone name mapping on Windows" On)
	endif()
	if(DATE_TZ_SHELL_REMOVE_DIRECTORY AND DATE_TZ_SHELL_REMOVE_FILE AND DATE_TZ_SHELL_MOVE_FILE AND DATE_TZ_SHELL_UNTAR AND DATE_TZ_SHELL_MAKE_DIRECTORY)
		option(DATE_TZ_NO_DATE_TZ_SHELL  "Disable using shell programs to manage IANA Time Zone rules" Off)
	else()
		option(DATE_TZ_NO_DATE_TZ_SHELL  "Disable using shell programs to manage IANA Time Zone rules" On)
	endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(LIBCXX)

message(STATUS "Using ${CMAKE_CXX_COMPILER} (compiler id: ${CMAKE_CXX_COMPILER_ID})")
if ("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang")
	if(NOT "${CMAKE_CXX_FLAGS}" MATCHES "-stdlib")
		set(CMAKE_CXX_FLAGS "-std=c++14 -stdlib=libc++ ${CMAKE_CXX_FLAGS}")
	endif()
endif ()
if(NOT NEED_PARENT)
	if("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Gnu")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
	endif()
endif()

if(NEED_PARENT)
	set(DATE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
endif()

if(NOT DATE_NO_TZ)
	add_definitions(-DDATE_BUILD_LIB=1)

	if(WIN32)
		if(DATE_TZ_NO_TZMAP)
			add_definitions(-DTIMEZONE_MAPPING=0)
		else()
			add_definitions(-DTIMEZONE_MAPPING=1)
		endif()
	endif()
	if(DATE_TZ_NO_LAZY)
		add_definitions(-DLAZY_INIT=0)
	else()
		add_definitions(-DLAZY_INIT=1)
	endif()

	set(DATE_INC ${CMAKE_CURRENT_SOURCE_DIR})

	if(NOT DATE_TZ_NO_REMOTE AND CURL_FOUND)
		message(STATUS "Date: Found cURL. Explicitly enabling HAS_REMOTE_API")
		add_definitions(-DHAS_REMOTE_API=1)
		add_definitions(-DAUTO_DOWNLOAD=1)
		set(DATE_INC ${DATE_INC} ${CURL_INCLUDE_DIRS})
		set(TZLINKS ${CURL_LIBRARIES})
	else()
		message(WARNING "Date: Disabling auto download")
		add_definitions(-DHAS_REMOTE_API=0)
		add_definitions(-DAUTO_DOWNLOAD=0)
		set(TZLINKS "")
	endif()

	add_library(date-tz STATIC tz.cpp)

	target_link_libraries(date-tz ${TZLINKS})

	set_property(TARGET date-tz PROPERTY CXX_STADARD 14)

	if(NEED_PARENT)
		set(DATE_TZ_INCLUDES ${DATE_INC} PARENT_SCOPE)
		set(DATE_TZ_LIBS ${TZLINKS} date-tz PARENT_SCOPE)
	else()
		set(DATE_TZ_LIBS ${TZLINKS} date-tz)
	endif()

	if(DATE_ENABLE_TESTS)	
		enable_testing()

		include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/test)
		add_executable(validate test/tz_test/validate.cpp)

		target_link_libraries(validate ${DATE_TZ_LIBS})
		
		add_test(validate validate)
		if(NOT MSVC)
			set(DATE_TZ_DO_FAIL_PASS On)
		elseif(${MSVC_VERSION} GREATER 1910)
			set(DATE_TZ_DO_FAIL_PASS On)
		endif()
		if(DATE_TZ_DO_FAIL_PASS)
			file(GLOB_RECURSE DATE_STATIC_TESTS RELATIVE ${CMAKE_SOURCE_DIR}/test/ *.fail.cpp)
			file(GLOB_RECURSE DATE_RUNTIME_TESTS RELATIVE ${CMAKE_SOURCE_DIR}/test/ *.pass.cpp)
			foreach(source_file ${DATE_STATIC_TESTS} ${DATE_RUNTIME_TESTS})
				string(REPLACE "." "_" source_target ${source_file})
				string(REPLACE "/" "_" source_target ${source_target})
				string(REPLACE "\\" "_" source_target ${source_target})
				string(REPLACE "_cpp" "" source_target ${source_target})
				add_executable(${source_target} ${CMAKE_SOURCE_DIR}/test/${source_file})
				target_link_libraries(${source_target} ${DATE_TZ_LIBS})
				add_test(${source_target} ${source_target})
			endforeach()
		endif()
	endif()
endif()
