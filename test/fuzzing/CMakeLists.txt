if (NOT DEFINED ENV{OUT} OR NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    message(FATAL_ERROR "Environment variables expected for OSSFuzz builds not provided! Cannot build fuzzer")
endif()

# Create utility library
add_library(libfuzzutil
    STATIC
    fuzzutil.cpp
)

target_include_directories(libfuzzutil
    PUBLIC "inc"
)

target_link_libraries(libfuzzutil
    PUBLIC date::date
)

target_compile_options(libfuzzutil
        PRIVATE
        $ENV{LIB_FUZZING_ENGINE}
)

target_link_options(libfuzzutil
        PRIVATE
        $ENV{LIB_FUZZING_ENGINE}
)

function(create_harness source_path)

    get_filename_component(harness_name "${source_path}" NAME_WE)

    add_executable(${harness_name}
        "${source_path}"
    )

    target_link_libraries(${harness_name}
        PRIVATE
        libfuzzutil
    )

    target_compile_definitions(${harness_name}
        PRIVATE
        -DNDEBUG  # Do not want assertions
    )

    target_compile_features(${harness_name}
        PRIVATE
        cxx_std_17
    )

    target_compile_options(${harness_name}
        PRIVATE
        $ENV{LIB_FUZZING_ENGINE}
    )

    target_link_options(${harness_name}
        PRIVATE
        $ENV{LIB_FUZZING_ENGINE}
    )

    install(TARGETS ${harness_name} DESTINATION $ENV{OUT})
endfunction()

# Create a harness executable for all sources following fuzz_*.cpp pattern
file(GLOB_RECURSE
    fuzz_source_files
    fuzz_*.cpp
)
foreach(file ${fuzz_source_files})
    create_harness("${file}")
endforeach ()