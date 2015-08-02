// Howard Hinnant
// This work is licensed under a Creative Commons Attribution 4.0 International License.
// http://creativecommons.org/licenses/by/4.0/

// durations
// 
// using days = std::chrono::duration
//     <int, std::ratio_multiply<std::ratio<24>, std::chrono::hours::period>>;
// 
// using weeks = std::chrono::duration
//     <int, std::ratio_multiply<std::ratio<7>, days::period>>;
// 
// using years = std::chrono::duration
//     <int, std::ratio_multiply<std::ratio<146097, 400>, days::period>>;
// 
// using months = std::chrono::duration
//     <int, std::ratio_divide<years::period, std::ratio<12>>>;
// 
// time_point
// 
// using day_point = std::chrono::time_point<std::chrono::system_clock, days>;

#include "date.h"

#include <type_traits>

static_assert(date::days{1} == std::chrono::seconds{86400}, "");
static_assert(date::weeks{1} == std::chrono::seconds{604800}, "");
static_assert(date::months{1} == std::chrono::seconds{2629746}, "");
static_assert(date::years{1} == std::chrono::seconds{31556952}, "");

static_assert(std::is_same<date::day_point::duration, date::days>{}, "");

int
main()
{
}
