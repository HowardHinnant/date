// The MIT License (MIT)
//
// Copyright (c) 2020 Asad. Gharighi
// Copyright (c) 2020 Howard Hinnant
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

#include "date.h"
#include "solar_hijri.h"
#include "islamic.h"
#include "tz.h"
#include <cassert>
#include <iostream>
#include <chrono>
#include <math.h>

void
test_a() {
  constexpr auto civil = date::year{2020}/date::January/27;
  using namespace solar_hijri;
  static_assert(year_month_day{civil} == 1398_y/11/07, "");
}

void
test_b() {
  using namespace solar_hijri::literals;
  static_assert(date::year_month_day{475_y/far/1} == date::year{1096}/03/21, "");
  static_assert(date::year_month_weekday{475_y/far/1} ==
                date::year{1096}/03/date::Saturday[3], "");
}

void
test_c() {
  using namespace solar_hijri;
  auto date = solar_hijri::year_month_day{1398_y/bah/6};
  for (auto i = 0; i < 24; i++) {
    auto weekday = solar_hijri::weekday{date};
    assert(date == 1398_y/11/06 + months{i});
    assert(date.month() == month{(i+10u)%12 + 1});
    assert(weekday == (weekday[1]/date.month()/date.year()).weekday());
    auto k = weekday;
    for (auto j = 0; j < 14; j++, k++) {
      assert(weekday + days{j} == k);
    }
    date+=solar_hijri::months(1);
  }
}

void
test_d() {
  auto zt = date::make_zoned(date::current_zone(), std::chrono::system_clock::now());
  auto ld = date::floor<date::days>(zt.get_local_time());
  solar_hijri::year_month_day ymd{ld};
  auto time = date::make_time(zt.get_local_time() - ld);
  (void)time;
}

void
test_e() {
  auto sd = date::floor<solar_hijri::days>(std::chrono::system_clock::now());
  auto today = solar_hijri::year_month_day{sd};
  assert(solar_hijri::year_month_weekday{today}.weekday() == solar_hijri::weekday{sd});
}

void
test_f() {
  constexpr auto isl = islamic::year{1441}/6/1;
  using namespace solar_hijri;
  static_assert(year_month_day{isl} == 1398_y/11/07, "");
}

void
test_g() {
  date::year_month_day ymdd[] = {
    date::year{1583}/date::November/21,
    date::year{1583}/date::November/22,
    date::year{1583}/date::December/6,
    date::year{1591}/date::December/26,
    date::year{1616}/date::October/20,
    date::year{1619}/date::October/13,
    date::year{1627}/date::August/9,
    date::year{1649}/date::October/15,
    date::year{1657}/date::August/9,
    date::year{1682}/date::June/23,
    date::year{1691}/date::October/12,
    date::year{1712}/date::September/13,
    date::year{1718}/date::July/17,
    date::year{1747}/date::January/4,
    date::year{1756}/date::January/1,
    date::year{1770}/date::January/15,
    date::year{1798}/date::October/24,
    date::year{1809}/date::July/11,
    date::year{1834}/date::July/17,
    date::year{1850}/date::September/9,
    date::year{1865}/date::November/4,
    date::year{1902}/date::December/21,
    date::year{1926}/date::March/21,
    date::year{1926}/date::March/22,
    date::year{1957}/date::June/1,
    date::year{1977}/date::March/7,
    date::year{1982}/date::May/30,
    date::year{1992}/date::December/8
  };

  solar_hijri::year_month_day ymdh[] = {
    solar_hijri::year{962}/solar_hijri::Aban/30,
    solar_hijri::year{962}/solar_hijri::Azar/1,
    solar_hijri::year{962}/solar_hijri::Azar/15,
    solar_hijri::year{970}/solar_hijri::Dey/5,
    solar_hijri::year{995}/solar_hijri::Mehr/29,
    solar_hijri::year{998}/solar_hijri::Mehr/21,
    solar_hijri::year{1006}/solar_hijri::Mordad/18,
    solar_hijri::year{1028}/solar_hijri::Mehr/24,
    solar_hijri::year{1036}/solar_hijri::Mordad/19,
    solar_hijri::year{1061}/solar_hijri::Tir/3,
    solar_hijri::year{1070}/solar_hijri::Mehr/20,
    solar_hijri::year{1091}/solar_hijri::Shahrivar/22,
    solar_hijri::year{1097}/solar_hijri::Tir/26,
    solar_hijri::year{1125}/solar_hijri::Dey/14,
    solar_hijri::year{1134}/solar_hijri::Dey/11,
    solar_hijri::year{1148}/solar_hijri::Dey/26,
    solar_hijri::year{1177}/solar_hijri::Aban/2,
    solar_hijri::year{1188}/solar_hijri::Tir/20,
    solar_hijri::year{1213}/solar_hijri::Tir/26,
    solar_hijri::year{1229}/solar_hijri::Shahrivar/18,
    solar_hijri::year{1244}/solar_hijri::Aban/13,
    solar_hijri::year{1281}/solar_hijri::Azar/29,
    solar_hijri::year{1304}/solar_hijri::Esfand/30,
    solar_hijri::year{1305}/solar_hijri::Farvardin/1,
    solar_hijri::year{1336}/solar_hijri::Khordad/11,
    solar_hijri::year{1355}/solar_hijri::Esfand/16,
    solar_hijri::year{1361}/solar_hijri::Khordad/9,
    solar_hijri::year{1371}/solar_hijri::Azar/17
  };

  solar_hijri::year_month_weekday ymdwd[] = {
    solar_hijri::year{962}/solar_hijri::Aban/solar_hijri::Doshanbe[5],
    solar_hijri::year{962}/solar_hijri::Azar/solar_hijri::Seshanbe[1],
    solar_hijri::year{962}/solar_hijri::Azar/solar_hijri::Seshanbe[3],
    solar_hijri::year{970}/solar_hijri::Dey/solar_hijri::Panjshanbe[1],
    solar_hijri::year{995}/solar_hijri::Mehr/solar_hijri::Panjshanbe[5],
    solar_hijri::year{998}/solar_hijri::Mehr/solar_hijri::Yekshanbe[3],
    solar_hijri::year{1006}/solar_hijri::Mordad/solar_hijri::Doshanbe[3],
    solar_hijri::year{1028}/solar_hijri::Mehr/solar_hijri::Adine[4],
    solar_hijri::year{1036}/solar_hijri::Mordad/solar_hijri::Panjshanbe[3],
    solar_hijri::year{1061}/solar_hijri::Tir/solar_hijri::Seshanbe[1],
    solar_hijri::year{1070}/solar_hijri::Mehr/solar_hijri::Adine[3],
    solar_hijri::year{1091}/solar_hijri::Shahrivar/solar_hijri::Seshanbe[4],
    solar_hijri::year{1097}/solar_hijri::Tir/solar_hijri::Yekshanbe[4],
    solar_hijri::year{1125}/solar_hijri::Dey/solar_hijri::Chaharshanbe[2],
    solar_hijri::year{1134}/solar_hijri::Dey/solar_hijri::Panjshanbe[2],
    solar_hijri::year{1148}/solar_hijri::Dey/solar_hijri::Doshanbe[4],
    solar_hijri::year{1177}/solar_hijri::Aban/solar_hijri::Chaharshanbe[1],
    solar_hijri::year{1188}/solar_hijri::Tir/solar_hijri::Seshanbe[3],
    solar_hijri::year{1213}/solar_hijri::Tir/solar_hijri::Panjshanbe[4],
    solar_hijri::year{1229}/solar_hijri::Shahrivar/solar_hijri::Doshanbe[3],
    solar_hijri::year{1244}/solar_hijri::Aban/solar_hijri::Shanbe[2],
    solar_hijri::year{1281}/solar_hijri::Azar/solar_hijri::Yekshanbe[5],
    solar_hijri::year{1304}/solar_hijri::Esfand/solar_hijri::Yekshanbe[5],
    solar_hijri::year{1305}/solar_hijri::Farvardin/solar_hijri::Doshanbe[1],
    solar_hijri::year{1336}/solar_hijri::Khordad/solar_hijri::Shanbe[2],
    solar_hijri::year{1355}/solar_hijri::Esfand/solar_hijri::Doshanbe[3],
    solar_hijri::year{1361}/solar_hijri::Khordad/solar_hijri::Yekshanbe[2],
    solar_hijri::year{1371}/solar_hijri::Azar/solar_hijri::Seshanbe[3]
  };

  bool leaps[] = {
    true,
    true,
    true,
    true,
    true,
    false,
    false,
    true,
    true,
    true,
    false,
    false,
    false,
    false,
    false,
    true,
    false,
    false,
    false,
    false,
    false,
    false,
    true,
    false,
    false,
    false,
    false,
    false
  };

  static_assert(sizeof(ymdd)/sizeof(ymdd[0]) == sizeof(ymdwd)/sizeof(ymdwd[0]), "");
  static_assert(sizeof(ymdd)/sizeof(ymdd[0]) == sizeof(ymdh)/sizeof(ymdh[0]), "");
  static_assert(sizeof(ymdd)/sizeof(ymdd[0]) == sizeof(leaps)/sizeof(leaps[0]), "");

  for (auto i = 0; i < sizeof(ymdd)/sizeof(ymdd[0]); ++i)
  {
    assert(solar_hijri::year_month_day{ymdd[i]} == ymdh[i]);
    assert(ymdd[i] == date::year_month_day{ymdh[i]});
    assert(ymdh[i].year().is_leap() == leaps[i]);
    assert(solar_hijri::year_month_weekday{ymdd[i]} == ymdwd[i]);
  }
}

int
main()
{
  test_a();
  test_b();
  test_c();
  test_d();
  test_e();
  test_f();
  test_g();
}
