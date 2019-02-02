// The MIT License (MIT)
//
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

// template <class Rep, class Period,
//           class = typename std::enable_if
//               <!std::chrono::treat_as_floating_point<Rep>::value>::type>
// constexpr
// time_of_day<std::chrono::duration<Rep, Period>>
// make_time(std::chrono::duration<Rep, Period> d) noexcept;

#include "date.h"

#include <cassert>
#include <type_traits>

int
main()
{
    using namespace date;
    using namespace std;
    using namespace std::chrono;

    {
        static_assert(is_same<decltype(make_time(nanoseconds{18429000000022})),
                              time_of_day<nanoseconds>>{}, "");
        auto tod = make_time(nanoseconds{18429000000022});
        assert(tod.hours() == hours{5});
        assert(tod.minutes() == minutes{7});
        assert(tod.seconds() == seconds{9});
        assert(tod.subseconds() == nanoseconds{22});
    }
    {
        static_assert(is_same<decltype(make_time(microseconds{18429000022})),
                              time_of_day<microseconds>>{}, "");
        auto tod = make_time(microseconds{18429000022});
        assert(tod.hours() == hours{5});
        assert(tod.minutes() == minutes{7});
        assert(tod.seconds() == seconds{9});
        assert(tod.subseconds() == microseconds{22});
    }
    {
        static_assert(is_same<decltype(make_time(seconds{18429})),
                              time_of_day<seconds>>{}, "");
        auto tod = make_time(seconds{18429});
        assert(tod.hours() == hours{5});
        assert(tod.minutes() == minutes{7});
        assert(tod.seconds() == seconds{9});
    }
    {
        static_assert(is_same<decltype(make_time(minutes{307})),
                              time_of_day<minutes>>{}, "");
        auto tod = make_time(minutes{307});
        assert(tod.hours() == hours{5});
        assert(tod.minutes() == minutes{7});
    }
    {
        static_assert(is_same<decltype(make_time(hours{5})),
                              time_of_day<hours>>{}, "");
        auto tod = make_time(hours{5});
        assert(tod.hours() == hours{5});
    }
}
