project(tz_test)

set(AllFiles validate)

source_group("" FILES ${AllFiles})

foreach(name ${AllFiles})
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} date)
    install(TARGETS ${name} RUNTIME DESTINATION bin)
    add_test(${name} ${name})
endforeach()


