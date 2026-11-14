// The MIT License (MIT)
//
// Copyright (c) 2026 riha ilyas
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

// The offset passed to from_stream for utc_time is only an output:
// it must not shift the result unless %z was parsed.

#include "tz.h"
#include <cassert>
#include <sstream>
#include <string>

int
main()
{
    using namespace date;
    using namespace std::chrono;
    using string = std::string;

    // No %z: a value already in *offset is not applied and is left alone
    {
        std::istringstream in{"2020-01-01 00:00:00"};
        utc_seconds tp;
        minutes offset{60};
        from_stream(in, "%F %T", tp, static_cast<string*>(nullptr), &offset);
        assert(!in.fail());
        assert(tp == clock_cast<utc_clock>(sys_days{2020_y/January/1}));
        assert(offset == minutes{60});
    }
    // An offset parsed by an earlier call does not leak into the next one
    {
        minutes offset{};
        utc_seconds tp;
        std::istringstream in1{"2020-01-01 05:30:00 +0530"};
        from_stream(in1, "%F %T %z", tp, static_cast<string*>(nullptr), &offset);
        assert(!in1.fail());
        assert(tp == clock_cast<utc_clock>(sys_days{2020_y/January/1}));
        assert(offset == hours{5} + minutes{30});
        std::istringstream in2{"2020-06-01 12:00:00"};
        from_stream(in2, "%F %T", tp, static_cast<string*>(nullptr), &offset);
        assert(!in2.fail());
        assert(tp == clock_cast<utc_clock>(sys_days{2020_y/June/1} + hours{12}));
    }
    // A leap second is still recognized when *offset holds a stale value
    {
        std::istringstream in{"2016-12-31 23:59:60"};
        utc_seconds tp;
        minutes offset{60};
        from_stream(in, "%F %T", tp, static_cast<string*>(nullptr), &offset);
        assert(!in.fail());
        assert(get_leap_second_info(tp).is_leap_second);
        assert(tp == clock_cast<utc_clock>(sys_days{2017_y/January/1}) - seconds{1});
    }
    // A parsed %z is still applied and reported
    {
        std::istringstream in{"2016-12-31 18:59:60 -0500"};
        utc_seconds tp;
        minutes offset{};
        from_stream(in, "%F %T %z", tp, static_cast<string*>(nullptr), &offset);
        assert(!in.fail());
        assert(offset == hours{-5});
        assert(get_leap_second_info(tp).is_leap_second);
    }
}
