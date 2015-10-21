project(tz_test)

set(AllFiles Validate.cpp)

source_group("" FILES ${AllFiles})

add_executable(${PROJECT_NAME} ${AllFiles})

target_link_libraries(${PROJECT_NAME} date)
