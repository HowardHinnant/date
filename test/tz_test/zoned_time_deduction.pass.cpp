// The MIT License (MIT)
//
// Copyright (c) 2019 Tomasz Kamiński
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

#include "tz.h"
#include "OffsetZone.h"
#include <cassert>
#include <type_traits>
#include <string>

#if HAS_DEDUCTION_GUIDES
#include <string_view>

template<typename TimeZonePtr, typename Source>
void testDeductionFrom(Source&& s)
{
    using namespace date;
    using namespace std::chrono;

    // No time point
    {
        zoned_time zt(std::forward<Source>(s));
        static_assert(std::is_same<decltype(zt), zoned_time<seconds, TimeZonePtr>>::value, "");
    }

    // sys_time
    {
        sys_days sd(2017_y/feb/20);
        zoned_time ztd(std::forward<Source>(s), sd);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds, TimeZonePtr>>::value, "");

        sys_time<seconds> ss(sd);
        zoned_time zts(std::forward<Source>(s), ss);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds, TimeZonePtr>>::value, "");

        sys_time<milliseconds> sms(ss);
        zoned_time ztms(std::forward<Source>(s), sms);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds, TimeZonePtr>>::value, "");
    }

    // local_time
    {
        local_days ld(2017_y/feb/20);
        zoned_time ztd(std::forward<Source>(s), ld);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds, TimeZonePtr>>::value, "");

        local_time<seconds> ls(ld);
        zoned_time zts(std::forward<Source>(s), ls);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds, TimeZonePtr>>::value, "");

        local_time<milliseconds> lms(ls);
        zoned_time ztms(std::forward<Source>(s), lms);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds, TimeZonePtr>>::value, "");
    }

    // local_time, choose
    {
        local_days ld(2017_y/feb/20);
        zoned_time ztd(std::forward<Source>(s), ld, choose::earliest);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds, TimeZonePtr>>::value, "");

        local_time<seconds> ls(ld);
        zoned_time zts(std::forward<Source>(s), ls, choose::earliest);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds, TimeZonePtr>>::value, "");

        local_time<milliseconds> lms(ls);
        zoned_time ztms(std::forward<Source>(s), lms, choose::earliest);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds, TimeZonePtr>>::value, "");
    }

    // zoned_time
    {
        zoned_time<days> zd(sys_days(2017_y/feb/20));
        zoned_time ztd(std::forward<Source>(s), zd);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds, TimeZonePtr>>::value, "");

        zoned_time<seconds> zs(zd);
        zoned_time zts(std::forward<Source>(s), zs);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds, TimeZonePtr>>::value, "");

        zoned_time<milliseconds> zms(zs);
        zoned_time ztms(std::forward<Source>(s), zms);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds, TimeZonePtr>>::value, "");
    }

    // zoned_time, choose
    {
        zoned_time<days> zd(sys_days(2017_y/feb/20));
        zoned_time ztd(std::forward<Source>(s), zd, choose::earliest);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds, TimeZonePtr>>::value, "");

        zoned_time<seconds> zs(zd);
        zoned_time zts(std::forward<Source>(s), zs, choose::earliest);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds, TimeZonePtr>>::value, "");

        zoned_time<milliseconds> zms(zs);
        zoned_time ztms(std::forward<Source>(s), zms, choose::earliest);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds, TimeZonePtr>>::value, "");
    }
}

struct MyString
{
  MyString(std::string s) : ms(std::move(s)) {}

  operator std::string_view() const { return ms; }

private:
  std::string ms;
};

struct OnlyLValueString
{
  OnlyLValueString(std::string s) : ms(std::move(s)) {}

  operator std::string_view() & { return ms; }

private:
  std::string ms;
};

#endif  // HAS_DEDUCTION_GUIDES

template<typename T>
T const& to_const(T& t) { return t; }


int
main()
{
    using namespace date;
    using namespace std::chrono;

#if HAS_DEDUCTION_GUIDES
    //  no arguments
    {
        zoned_time zt{};
        static_assert(std::is_same<decltype(zt), zoned_time<seconds>>::value, "");
    } 

    // zoned_time
    {
        zoned_time<days> zd(sys_days(2017_y/feb/20));
        zoned_time ztd(zd);
        static_assert(std::is_same<decltype(ztd), zoned_time<days>>::value, "");

        zoned_time<seconds> zs(zd);
        zoned_time zts(zs);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds>>::value, "");

        zoned_time<milliseconds> zms(zs);
        zoned_time ztms(zms);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds>>::value, "");
    }

    // sys_time
    {
        sys_days sd(2017_y/feb/20);
        zoned_time ztd(sd);
        static_assert(std::is_same<decltype(ztd), zoned_time<seconds>>::value, "");

        sys_time<seconds> ss(sd);
        zoned_time zts(ss);
        static_assert(std::is_same<decltype(zts), zoned_time<seconds>>::value, "");

        sys_time<milliseconds> sms(ss);
        zoned_time ztms(sms);
        static_assert(std::is_same<decltype(ztms), zoned_time<milliseconds>>::value, "");
    }

    // time_zone const*
    {
       time_zone const* tz = current_zone();
       testDeductionFrom<time_zone const*>(tz);
       testDeductionFrom<time_zone const*>(to_const(tz));
       testDeductionFrom<time_zone const*>(std::move(tz));
    }

    // char const*
    {
       char const* tz = "Europe/Warsaw";
       testDeductionFrom<time_zone const*>(tz);
       testDeductionFrom<time_zone const*>(to_const(tz));
       testDeductionFrom<time_zone const*>(std::move(tz));
    }

    // std::string
    {
       std::string tz = "Europe/Warsaw";
       testDeductionFrom<time_zone const*>(tz);
       testDeductionFrom<time_zone const*>(to_const(tz));
       testDeductionFrom<time_zone const*>(std::move(tz));
    }

    // std::string_view
    {
       std::string_view tz = "Europe/Warsaw";
       testDeductionFrom<time_zone const*>(tz);
       testDeductionFrom<time_zone const*>(to_const(tz));
       testDeductionFrom<time_zone const*>(std::move(tz));
    }

    // MyString
    {
       MyString tz("Europe/Warsaw");
       testDeductionFrom<time_zone const*>(tz);
       testDeductionFrom<time_zone const*>(to_const(tz));
       testDeductionFrom<time_zone const*>(std::move(tz));
    }

    // custom time zone
    {
       OffsetZone tz(minutes(45));
       testDeductionFrom<OffsetZone>(tz);
       testDeductionFrom<OffsetZone>(to_const(tz));
       testDeductionFrom<OffsetZone>(std::move(tz));
    }

    // OnlyLValue
    {
       OnlyLValueString tz("Europe/Warsaw");
       testDeductionFrom<time_zone const*>(tz);
       //testDeductionFrom<time_zone const*>(to_const(tz));
       //testDeductionFrom<time_zone const*>(std::move(tz));
    }

#endif  // HAS_DEDUCTION_GUIDES
}
