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
static_assert(date::days{1} == std::chrono::hours{24}, "");
static_assert( std::is_convertible<date::days, std::chrono::seconds>{}, "");
static_assert( std::is_convertible<date::days, std::chrono::minutes>{}, "");
static_assert( std::is_convertible<date::days, std::chrono::hours>{}, "");
static_assert(!std::is_convertible<date::days, date::weeks>{}, "");
static_assert(!std::is_convertible<date::days, date::months>{}, "");
static_assert(!std::is_convertible<date::days, date::years>{}, "");

static_assert(date::weeks{1} == std::chrono::seconds{604800}, "");
static_assert(date::weeks{1} == date::days{7}, "");
static_assert( std::is_convertible<date::weeks, std::chrono::seconds>{}, "");
static_assert( std::is_convertible<date::weeks, std::chrono::minutes>{}, "");
static_assert( std::is_convertible<date::weeks, std::chrono::hours>{}, "");
static_assert( std::is_convertible<date::weeks, date::days>{}, "");
static_assert(!std::is_convertible<date::weeks, date::months>{}, "");
static_assert(!std::is_convertible<date::weeks, date::years>{}, "");

static_assert(
    std::chrono::seconds{2629745} < date::months{1} &&
                                    date::months{1} < std::chrono::seconds{2629746}, "");
static_assert(date::days{30} < date::months{1} && date::months{1} < date::days{31}, "");
static_assert(date::weeks{4} < date::months{1} && date::months{1} < date::weeks{5}, "");
static_assert(!std::is_convertible<date::months, date::years>{}, "");
static_assert(!std::is_convertible<date::months, date::weeks>{}, "");
static_assert(!std::is_convertible<date::months, date::days>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::hours>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::minutes>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::seconds>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::milliseconds>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::microseconds>{}, "");
static_assert(!std::is_convertible<date::months, std::chrono::nanoseconds>{}, "");

static_assert(
    std::chrono::seconds{31556951} < date::years{1} &&
                                     date::years{1} < std::chrono::seconds{31556952}, "");
static_assert(date::days{365} < date::years{1} && date::years{1} < date::days{366}, "");
static_assert(date::weeks{52} < date::years{1} && date::years{1} < date::weeks{53}, "");
static_assert(date::years{1} == date::months{12}, "");
static_assert( std::is_convertible<date::years, date::months>{}, "");
static_assert(!std::is_convertible<date::years, date::weeks>{}, "");
static_assert(!std::is_convertible<date::years, date::days>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::hours>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::minutes>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::seconds>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::milliseconds>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::microseconds>{}, "");
static_assert(!std::is_convertible<date::years, std::chrono::nanoseconds>{}, "");

static_assert(std::is_same<date::day_point::duration, date::days>{}, "");

int
main()
{
}
