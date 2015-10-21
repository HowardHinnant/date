project(date_test)

set(AllFiles
  day.pass.cpp
  daypday.fail.cpp
  daysmday.fail.cpp
  daysmweekday.fail.cpp
  durations.pass.cpp
  last.pass.cpp
  make_time.pass.cpp
  month.pass.cpp
  month_day.pass.cpp
  month_day_last.pass.cpp
  month_weekday.pass.cpp
  month_weekday_last.pass.cpp
  month_weekday_last_less.fail.cpp
  month_weekday_less.fail.cpp
  monthpmonth.fail.cpp
  months_m_year_month.fail.cpp
  months_m_year_month_day.fail.cpp
  monthsmmonth.fail.cpp
  op_div_day_day.fail.cpp
  op_div_int_month.fail.cpp
  op_div_int_year.fail.cpp
  op_div_last_last.fail.cpp
  op_div_month_day.pass.cpp
  op_div_month_day_last.pass.cpp
  op_div_month_day_month_day.fail.cpp
  op_div_month_month.fail.cpp
  op_div_month_weekday.pass.cpp
  op_div_month_weekday_last.pass.cpp
  op_div_month_year.fail.cpp
  op_div_survey.pass.cpp
  op_div_weekday_indexed_weekday_indexed.fail.cpp
  op_div_weekday_last_weekday_last.fail.cpp
  op_div_year_month.pass.cpp
  op_div_year_month_day.pass.cpp
  op_div_year_month_day_last.pass.cpp
  op_div_year_month_weekday.pass.cpp
  op_div_year_month_weekday_last.pass.cpp
  op_div_year_month_year_month.fail.cpp
  op_div_year_year.fail.cpp
  sizeof.pass.cpp
  time_of_day_hours.pass.cpp
  time_of_day_milliseconds.pass.cpp
  time_of_day_minutes.pass.cpp
  time_of_day_nanoseconds.pass.cpp
  time_of_day_seconds.pass.cpp
  weekday.pass.cpp
  weekday_indexed.pass.cpp
  weekday_last.pass.cpp
  weekday_lessthan.fail.cpp
  weekday_sum.fail.cpp
  year.pass.cpp
  year_month.pass.cpp
  year_month_day.pass.cpp
  year_month_day_last.pass.cpp
  year_month_day_m_year_month_day.fail.cpp
  year_month_day_p_year_month_day.fail.cpp
  year_month_p_year_month.fail.cpp
  year_month_weekday.pass.cpp
  year_month_weekday_last.pass.cpp
  year_p_year.fail.cpp
  years_m_year.fail.cpp
  years_m_year_month.fail.cpp
  years_m_year_month_day.fail.cpp)

source_group("" FILES ${AllFiles})

add_executable(${PROJECT_NAME} ${AllFiles})

target_link_libraries(${PROJECT_NAME} date)
