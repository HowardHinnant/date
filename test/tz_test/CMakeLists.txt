project(tz_test)

set(AllFiles validate)

source_group("" FILES ${AllFiles})

foreach(name ${AllFiles})
    source_group("" FILES ${name}.cpp)
    add_executable(${name} ${name}.cpp)
    set_property(TARGET ${name} PROPERTY FOLDER "TZTest")
    target_link_libraries(${name} date)
    install(TARGETS ${name} RUNTIME DESTINATION bin)
    add_test(${name} ${name})
endforeach()


