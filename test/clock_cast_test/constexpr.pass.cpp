// The MIT License (MIT)
//
// Copyright (c) 2019 nanoric
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "tz.h"
#include <cassert>
#include <type_traits>

struct const_clock {
  using duration =
      typename std::common_type<std::chrono::system_clock::duration,
          date::days>::type;
  using rep = duration::rep;
  using period = duration::period;
  using time_point = std::chrono::time_point<const_clock, duration>;

  static constexpr date::sys_days epoch { date::days { 1000 } };

  template <typename Duration>
  static std::chrono::time_point<std::chrono::system_clock,
      typename std::common_type<Duration, date::days>::type>
      CONSTCD11 to_sys(std::chrono::time_point<const_clock, Duration> const& tp)
  {
    return epoch + tp.time_since_epoch();
  }

  template <typename Duration>
  static std::chrono::time_point<const_clock,
      typename std::common_type<Duration, date::days>::type>
      CONSTCD11 from_sys(
          std::chrono::time_point<std::chrono::system_clock, Duration> const&
              tp)
  {
    using res = std::chrono::time_point<const_clock,
        typename std::common_type<Duration, date::days>::type>;
    return res(tp - epoch);
  }
};

int main()
{
  using namespace date;
  using namespace std::chrono;
  using const_days = time_point<const_clock, days>;

  CONSTCD14 sys_days sys { days { 1024 } };
  static_assert(sys.time_since_epoch().count() == 1024, "");

  CONSTCD14 const_days c {clock_cast<const_clock>(sys)};
  CONSTCD14 sys_days sys2 {clock_cast<system_clock>(c)};
  CONSTCD14 sys_days sys3 { clock_cast<system_clock>(const_days(days(48))) };
#if __cplusplus >= 201402L
  static_assert(c.time_since_epoch().count() == 24, "");
  static_assert(sys2.time_since_epoch().count() == 1024, "");
  static_assert(sys3.time_since_epoch().count() == 1048, "");
#endif
}
