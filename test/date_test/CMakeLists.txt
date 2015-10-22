project(date_test CXX)

set(PassFiles
    day.pass
    durations.pass
    last.pass
    make_time.pass
    month_day_last.pass
    month_day.pass
    month.pass
    month_weekday_last.pass
    month_weekday.pass
    op_div_month_day_last.pass
    op_div_month_day.pass
    op_div_month_weekday_last.pass
    op_div_month_weekday.pass
    op_div_survey.pass
    op_div_year_month_day_last.pass
    op_div_year_month_day.pass
    op_div_year_month.pass
    op_div_year_month_weekday_last.pass
    op_div_year_month_weekday.pass
    sizeof.pass
    time_of_day_hours.pass
    time_of_day_milliseconds.pass
    time_of_day_minutes.pass
    time_of_day_nanoseconds.pass
    time_of_day_seconds.pass
    weekday_indexed.pass
    weekday_last.pass
    weekday.pass
    year_month_day_last.pass
    year_month_day.pass
    year_month.pass
    year_month_weekday_last.pass
    year_month_weekday.pass
    year.pass)

set(FailFiles
    daypday.fail.cpp
    daysmday.fail.cpp
    daysmweekday.fail.cpp
    monthpmonth.fail.cpp
    monthsmmonth.fail.cpp
    months_m_year_month_day.fail.cpp
    months_m_year_month.fail.cpp
    month_weekday_last_less.fail.cpp
    month_weekday_less.fail.cpp
    op_div_day_day.fail.cpp
    op_div_int_month.fail.cpp
    op_div_int_year.fail.cpp
    op_div_last_last.fail.cpp
    op_div_month_day_month_day.fail.cpp
    op_div_month_month.fail.cpp
    op_div_month_year.fail.cpp
    op_div_weekday_indexed_weekday_indexed.fail.cpp
    op_div_weekday_last_weekday_last.fail.cpp
    op_div_year_month_year_month.fail.cpp
    op_div_year_year.fail.cpp
    weekday_lessthan.fail.cpp
    weekday_sum.fail.cpp
    year_month_day_m_year_month_day.fail.cpp
    year_month_day_p_year_month_day.fail.cpp
    year_month_p_year_month.fail.cpp
    year_p_year.fail.cpp
    years_m_year.fail.cpp
    years_m_year_month_day.fail.cpp
    years_m_year_month.fail.cpp)

set(AllFiles ${PassFiles} ${FailFiles})

# set_source_files_properties(${FailFiles} PROPERTIES HEADER_FILE_ONLY TRUE)

source_group("" FILES ${AllFiles})

foreach(name ${PassFiles})
    source_group("" FILES ${name}.cpp)
    add_executable(${name} ${name}.cpp)
    set_property(TARGET ${name} PROPERTY FOLDER "DateTest")
    target_link_libraries(${name} date)
    install(TARGETS ${name} RUNTIME DESTINATION bin)
    add_test(${name} ${name})
endforeach()
