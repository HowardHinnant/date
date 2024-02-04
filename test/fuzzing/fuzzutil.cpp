#include "fuzzutil.hpp"

date::year_month_day consume_year_month_day(FuzzedDataProvider &fdp)
{
    auto month = fdp.ConsumeIntegral<int>();
    auto day = fdp.ConsumeIntegral<int>();
    return date::year{fdp.ConsumeIntegral<int>()}/month/day;
}

date::day consume_day(FuzzedDataProvider &fdp) {
    return date::day{fdp.ConsumeIntegral<unsigned int>()};
}

date::month_day consume_month_day(FuzzedDataProvider &fdp) {
    return {date::month{fdp.ConsumeIntegral<unsigned int>()},
            date::day{fdp.ConsumeIntegral<unsigned int>()}};
}

julian::year_month_day consume_julian_year_month_day(FuzzedDataProvider &fdp) {
    return {
            julian::year{fdp.ConsumeIntegral<int>()},
            julian::month{fdp.ConsumeIntegral<unsigned int>()},
            julian::day{fdp.ConsumeIntegral<unsigned int>()}
    };
}

islamic::year_month_day consume_islamic_year_month_day(FuzzedDataProvider &fdp) {
    return {
        islamic::year{fdp.ConsumeIntegral<int>()},
        islamic::month{fdp.ConsumeIntegral<unsigned int>()},
        islamic::day{fdp.ConsumeIntegral<unsigned int>()}
    };
}
