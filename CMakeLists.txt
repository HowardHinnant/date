cmake_minimum_required(VERSION 3.2.2)

set(LIBRARY_NAME date)

project(${LIBRARY_NAME} LANGUAGES CXX)

set(MAJOR_VERSION 2)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

################################################################################
# Add the header-only library 

add_library(${LIBRARY_NAME} INTERFACE)
target_include_directories(${LIBRARY_NAME} INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> # for headers when building
  $<INSTALL_INTERFACE:include/${LIBRARY_NAME}> # for client in install mode
)


# This CMake configuration was and its future versions will be partially inspired by 
# - https://rix0r.nl/blog/2015/08/13/cmake-guide/
# - https://vittorioromeo.info/index/blog/2016_cpp_library_configuration_api.html  
# - https://steveire.wordpress.com/2016/08/09/opt-in-header-only-libraries-with-cmake/ 
