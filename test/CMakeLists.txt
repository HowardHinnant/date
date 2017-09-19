cmake_minimum_required(VERSION 3.2.2) 

include(CTest)


################################################################################
# Import Catch Test Framework 
################################################################################

# See http://dbgit.prakinf.tu-ilmenau.de/code/pfabric/blob/dbe8dbfe21a79c00738cf7762368181edf249767/cmake/Download3rdParty.cmake

include(${CMAKE_SOURCE_DIR}/cmake-helper/DownloadProject/DownloadProject.cmake)

download_project(PROJ               catch
                 GIT_REPOSITORY      https://github.com/philsquared/Catch
                 GIT_TAG             master
                 UPDATE_DISCONNECTED 1
)

set(CATCH_INCLUDE_DIR ${catch_SOURCE_DIR}/single_include CACHE INTERNAL "Path to include folder for Catch")
include_directories(${CATCH_INCLUDE_DIR})


################################################################################
# Define Unit Tests  
################################################################################

foreach (dirname 
    "${CMAKE_CURRENT_SOURCE_DIR}/date_test/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/date_test/detail/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/date_test/format/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/iso_week/*.cpp")

    get_filename_component(directory ${dirname} DIRECTORY)    
    get_filename_component(subdirname ${directory} NAME)
    
    get_filename_component(parent_directory ${directory} DIRECTORY)
    get_filename_component(dir_prefix ${parent_directory} NAME)

    if (${directory} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
        set(name_prefix "${dir_prefix}_")
    else()
        set(name_prefix "${dir_prefix}_${subdirname}_")
    endif()

    file(GLOB passing_test_files "${dirname}")
    foreach(filename ${passing_test_files})
        get_filename_component(name ${filename} NAME_WE)
        set(testname ${name_prefix}${name})
        # message(${testname} "--" ${filename})
        add_executable(${testname} ${filename})
        
        if (${filename} MATCHES ".fail.cpp")
            set_target_properties(${testname} PROPERTIES
                EXCLUDE_FROM_ALL TRUE
                EXCLUDE_FROM_DEFAULT_BUILD TRUE)
            add_test(NAME "FAIL_${testname}"
                COMMAND ${CMAKE_COMMAND} --build . --target ${testname} --config $<CONFIGURATION>
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
            set_tests_properties(FAIL_${testname} PROPERTIES WILL_FAIL TRUE)
        else()
            add_test(NAME ${testname} COMMAND ${testname})
        endif()     
    endforeach()
endforeach()



