cmake_minimum_required(VERSION 3.2.2)
# partially inspired by https://rix0r.nl/blog/2015/08/13/cmake-guide/

set(LIBRARY_NAME date)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(${LIBRARY_NAME} LANGUAGES CXX)

set(MAJOR_VERSION 1)
set(MINOR_VERSION 0)
set(PATCH_VERSION 0)

# Determine whether this is a standalone project or included by other projects
set(${LIBRARY_NAME}_STANDALONE_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(${LIBRARY_NAME}_STANDALONE_PROJECT ON)
endif ()

# Use GNUInstallDirs to install libraries into correct locations on all platforms.
include(GNUInstallDirs)


################################################################################
# Add the library

add_library(${LIBRARY_NAME} 
    src/tz.cpp)

target_include_directories(${LIBRARY_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> # for headers when building
    $<INSTALL_INTERFACE:include/${LIBRARY_NAME}> # for client in install mode
    PRIVATE src
    )

install(TARGETS ${LIBRARY_NAME} EXPORT ${LIBRARY_NAME}  
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR})  

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIBRARY_NAME})

# This makes the project importable from the install directory
# Put config file in per-project dir (name MUST match), can also
# just go into 'cmake'.
install(EXPORT ${LIBRARY_NAME} DESTINATION share/${LIBRARY_NAME}/cmake)

# This makes the project importable from the build directory
export(TARGETS ${LIBRARY_NAME} FILE ${LIBRARY_NAME}.cmake)

###############################################################################
# Packaging configuration
if (${LIBRARY_NAME}_STANDALONE_PROJECT)
    # Debian installer prefix propagated to CMakeCPackConfig
    set(DEB_INSTALL_PREFIX "/opt/${PROJECT_NAME}-${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
    configure_file(CMakeCPackConfig.cmake.in CMakeCPackConfig.cmake @ONLY)

    ################################################################################
    # Library search path (see https://cmake.org/Wiki/CMake_RPATH_handling)

    # The trick is that setting these variables here is partially ignored 
    # unless(!) you use
    #
    #    install(TARGETS ${CMAKE_PROJECT_NAME}
    #        RUNTIME DESTINATION bin
    #        LIBRARY DESTINATION lib
    #        ARCHIVE DESTINATION lib)
    #
    # to declare what you want to isntall, e.g. in subfolders. If you use 
    #
    #    install (PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME} DESTINATION bin)
    #
    # you are definitely lost because then either the local version or the installed
    # version has the wrong RPATH settings, because the packaging skips RPATH manipulation.

    # use, i.e. don't skip the full RPATH for the build tree
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_SKIP_RPATH FALSE)

    # when building, don't use the install RPATH already
    # (but later on when installing)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE) 

    # Make RPATH in installed programs relative to executable, so it is relocatable
    # This could also be 
    #     set(CMAKE_INSTALL_RPATH "$ORIGIN:$ORIGIN/../lib")
    # Note that
    #     set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    # did not work for me for Debian packages, but ORIGIN is the cleanest approach (IMHO)
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")

    # add the automatically determined parts of the RPATH
    # which point to directories outside the build tree to the install RPATH
    # Note: I do not see the effect of this varibale
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

    ################################################################################
    # Package details configuration
    include(${CMAKE_SOURCE_DIR}/CMakeCPack.cmake)
endif ()


if (${LIBRARY_NAME}_STANDALONE_PROJECT)
    include_directories(include)
    enable_testing()
    add_subdirectory(test)
endif()