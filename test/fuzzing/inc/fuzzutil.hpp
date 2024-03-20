#ifndef DATE_FUZZUTIL_HPP
#define DATE_FUZZUTIL_HPP

#include <fuzzer/FuzzedDataProvider.h>

#include "date/date.h"
#include "date/julian.h"
#include "date/islamic.h"

enum class duration_type
{
    NANOSECONDS,
    MICROSECONDS,
    MILLISECONDS,
    SECONDS,
    MINUTES,
    HOURS,
    DAYS,
    WEEKS,
    MONTHS,
    YEARS,
    kMaxValue=YEARS // NOLINT: FuzzedDataProvider requires kMaxValue
};

[[nodiscard]] date::year_month_day consume_year_month_day(FuzzedDataProvider &fdp);

[[nodiscard]] julian::year_month_day consume_julian_year_month_day(FuzzedDataProvider &fdp);

[[nodiscard]] islamic::year_month_day consume_islamic_year_month_day(FuzzedDataProvider &fdp);

[[nodiscard]] date::day consume_day(FuzzedDataProvider &fdp);

[[nodiscard]] std::chrono::duration<int64_t> consume_duration(FuzzedDataProvider &fdp);

[[nodiscard]] date::month_day consume_month_day(FuzzedDataProvider &fdp);


#endif //DATE_FUZZUTIL_HPP
