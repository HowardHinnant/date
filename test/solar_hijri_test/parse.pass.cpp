#include "date.h"
#include "solar_hijri.h"
#include "islamic.h"
#include "tz.h"
#include <iostream>
#include <chrono>
#include <math.h>

void
test_a() {
  using namespace date::literals;
  std::cout << solar_hijri::year_month_day{2020_y/jan/27} << '\n';
}

void
test_b() {
  using namespace solar_hijri::literals;
  std::cout << date::year_month_day{1398_y/bah/7} << '\n';
}

void
test_c() {
  using namespace solar_hijri::literals;
  auto date = solar_hijri::year_month_day{1398_y/bah/6};
  for (auto i = 0; i < 24; i++) {
    std::cout << date << ' ' << date.month() << ' ' << solar_hijri::weekday{date} << std::endl;
    date+=solar_hijri::months(1);
  }
}

void
test_d() {
  auto zt = date::make_zoned(date::current_zone(), std::chrono::system_clock::now());
  auto ld = date::floor<date::days>(zt.get_local_time());
  solar_hijri::year_month_day ymd{ld};
  auto time = date::make_time(zt.get_local_time() - ld);
  std::cout << ymd << ' ' << time << '\n';
}

void
test_e() {
  auto today = solar_hijri::year_month_day{date::floor<solar_hijri::days>(std::chrono::system_clock::now())};
  std::cout << today << '\n';
  std::cout << solar_hijri::year_month_weekday{today}.weekday() << std::endl;
}

void
test_f() {
  using namespace islamic::literals;
  std::cout << solar_hijri::year_month_day{1441_y/6/1} << '\n';
}

void
test_g() {
  using namespace date;
  using namespace date::literals;
  solar_hijri::year_month_day ymds[] = {
    solar_hijri::year_month_day{1583_y/November/21},
    solar_hijri::year_month_day{1583_y/November/22},
    solar_hijri::year_month_day{1583_y/December/6},
    solar_hijri::year_month_day{1591_y/December/26},
    solar_hijri::year_month_day{1616_y/October/20},
    solar_hijri::year_month_day{1619_y/October/13},
    solar_hijri::year_month_day{1627_y/August/9},
    solar_hijri::year_month_day{1649_y/October/15},
    solar_hijri::year_month_day{1657_y/August/9},
    solar_hijri::year_month_day{1682_y/June/23},
    solar_hijri::year_month_day{1691_y/October/12},
    solar_hijri::year_month_day{1712_y/September/13},
    solar_hijri::year_month_day{1718_y/July/17},
    solar_hijri::year_month_day{1747_y/January/4},
    solar_hijri::year_month_day{1756_y/January/1},
    solar_hijri::year_month_day{1770_y/January/15},
    solar_hijri::year_month_day{1798_y/October/24},
    solar_hijri::year_month_day{1809_y/July/11},
    solar_hijri::year_month_day{1834_y/July/17},
    solar_hijri::year_month_day{1850_y/September/9},
    solar_hijri::year_month_day{1865_y/November/4},
    solar_hijri::year_month_day{1902_y/December/21},
    solar_hijri::year_month_day{1926_y/March/21},
    solar_hijri::year_month_day{1926_y/March/22},
    solar_hijri::year_month_day{1957_y/June/1},
    solar_hijri::year_month_day{1977_y/March/7},
    solar_hijri::year_month_day{1982_y/May/30},
    solar_hijri::year_month_day{1992_y/December/8}
  };

  for (auto ymd: ymds)
    std::cout << ymd << ' ' << ymd.year().is_leap() << ' ' << ymd.month() << ' ' << solar_hijri::year_month_weekday{ymd} << "\t\t" << date::year_month_day{ymd} << std::endl;
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
