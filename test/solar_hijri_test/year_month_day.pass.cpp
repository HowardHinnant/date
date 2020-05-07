// The MIT License (MIT)
//
// Copyright (c) 2020 Asad. Gharighi
// Copyright (c) 2015, 2016 Howard Hinnant
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// class year_month_day
// {
// public:
//     constexpr year_month_day(const date::year& y, const date::month& m,
//                                const date::day& d) noexcept;
//     constexpr year_month_day(const year_month_day_last& ymdl) noexcept;
//     constexpr year_month_day(const sys_days& dp) noexcept;
//
//     year_month_day& operator+=(const months& m) noexcept;
//     year_month_day& operator-=(const months& m) noexcept;
//     year_month_day& operator+=(const years& y)  noexcept;
//     year_month_day& operator-=(const years& y)  noexcept;
//
//     constexpr date::year  year()  const noexcept;
//     constexpr date::month month() const noexcept;
//     constexpr date::day   day()   const noexcept;
//
//     constexpr operator sys_days() const noexcept;
//     constexpr bool ok() const noexcept;
// };

// constexpr bool operator==(const year_month_day& x, const year_month_day& y) noexcept;
// constexpr bool operator!=(const year_month_day& x, const year_month_day& y) noexcept;
// constexpr bool operator< (const year_month_day& x, const year_month_day& y) noexcept;
// constexpr bool operator> (const year_month_day& x, const year_month_day& y) noexcept;
// constexpr bool operator<=(const year_month_day& x, const year_month_day& y) noexcept;
// constexpr bool operator>=(const year_month_day& x, const year_month_day& y) noexcept;

// constexpr year_month_day operator+(const year_month_day& ymd, const months& dm) noexcept;
// constexpr year_month_day operator+(const months& dm, const year_month_day& ymd) noexcept;
// constexpr year_month_day operator-(const year_month_day& ymd, const months& dm) noexcept;
// constexpr year_month_day operator+(const year_month_day& ymd, const years& dy)  noexcept;
// constexpr year_month_day operator+(const years& dy, const year_month_day& ymd)  noexcept;
// constexpr year_month_day operator-(const year_month_day& ymd, const years& dy)  noexcept;

// std::ostream& operator<<(std::ostream& os, const year_month_day& ymd);

#include "date.h"
#include "solar_hijri.h"

#include <iostream>
#include <cassert>
#include <sstream>
#include <type_traits>

static_assert( std::is_trivially_destructible<solar_hijri::year_month_day>{}, "");
static_assert( std::is_default_constructible<solar_hijri::year_month_day>{}, "");
static_assert( std::is_trivially_copy_constructible<solar_hijri::year_month_day>{}, "");
static_assert( std::is_trivially_copy_assignable<solar_hijri::year_month_day>{}, "");
static_assert( std::is_trivially_move_constructible<solar_hijri::year_month_day>{}, "");
static_assert( std::is_trivially_move_assignable<solar_hijri::year_month_day>{}, "");

static_assert(std::is_nothrow_constructible<solar_hijri::year_month_day, solar_hijri::year,
                                                                  solar_hijri::month,
                                                                  solar_hijri::day>{}, "");
static_assert(std::is_nothrow_constructible<solar_hijri::year_month_day,
                                            solar_hijri::year_month_day_last>{}, "");
static_assert(std::is_convertible<solar_hijri::year_month_day_last, solar_hijri::year_month_day>{}, "");
static_assert(std::is_nothrow_constructible<solar_hijri::year_month_day, solar_hijri::sys_days>{}, "");
static_assert(std::is_convertible<solar_hijri::sys_days, solar_hijri::year_month_day>{}, "");
static_assert(std::is_nothrow_constructible<solar_hijri::sys_days, solar_hijri::year_month_day>{}, "");
static_assert(std::is_convertible<solar_hijri::year_month_day, solar_hijri::sys_days>{}, "");

void
test_arithmetic()
{
    using namespace solar_hijri;

    for (int y1 = 1380; y1 <= 1400; ++y1)
    {
        for (unsigned m1 = 1; m1 <= 12; ++m1)
        {
            year_month_day ymd1{year{y1}, month{m1}, 9_d};
            year_month_day ymd2 = ymd1 + months(24);
            assert((ymd2 == year_month_day{year{y1+2}, ymd1.month(), ymd1.day()}));
            ymd2 = ymd1 - months(24);
            assert((ymd2 == year_month_day{year{y1-2}, ymd1.month(), ymd1.day()}));
            for (int m2 = -24; m2 <= 24; ++m2)
            {
                months m{m2};
                year_month_day ymd3 = ymd1 + m;
                months dm = year_month{ymd3.year(), ymd3.month()} -
                            year_month{ymd2.year(), ymd2.month()};
                assert(dm == m + years{2});
                assert(ymd3 - m == ymd1);
                assert(ymd3 + -m == ymd1);
                assert(-m + ymd3 == ymd1);
                assert((year_month_day{ymd1} += m) == ymd3);
                assert((year_month_day{ymd3} -= m) == ymd1);
            }
            for (int y2 = -2; y2 <= 5; ++y2)
            {
                years y{y2};
                year_month_day ymd3 = ymd1 + y;
                years dy = date::floor<years>(year_month{ymd3.year(), ymd3.month()} -
                                        year_month{ymd2.year(), ymd2.month()});
                assert(dy == y + years{2});
                assert(ymd3 - y == ymd1);
                assert(ymd3 + -y == ymd1);
                assert(-y + ymd3 == ymd1);
                assert((year_month_day{ymd1} += y) == ymd3);
                assert((year_month_day{ymd3} -= y) == ymd1);
            }
        }
    }
}

void
test_day_point_conversion()
{
    using namespace solar_hijri;
    year y   = year{-30000};
    year end =       30000_y;
    sys_days prev_dp = sys_days(year_month_day{y, far, 1_d}) - days{1};
    weekday  prev_wd = weekday{prev_dp};
    for (; y <= end; ++y)
    {
        month m = far;
        do
        {
            day last_day = year_month_day_last{y, month_day_last{m}}.day();
            for (day d = 1_d; d <= last_day; ++d)
            {
                year_month_day ymd = {y, m, d};
                assert(ymd.ok());
                sys_days dp = sys_days(ymd);
                assert(dp == prev_dp + days{1});
                year_month_day ymd2 = dp;
                assert(ymd2 == ymd);
                weekday wd = dp;
                assert(wd.ok());
                assert(wd == prev_wd + days{1});
                prev_wd = wd;
                prev_dp = dp;
            }
        } while (++m != far);
    }
}

int
main()
{
  test_arithmetic();
  test_day_point_conversion();
}
