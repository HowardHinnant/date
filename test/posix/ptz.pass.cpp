// The MIT License (MIT)
//
// Copyright (c) 2021 Howard Hinnant
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

// Test Posix::time_zone

#include "tz.h"
#include "ptz.h"
#include <cassert>

bool
is_equal(date::sys_info const& x, date::sys_info const& y)
{
    return x.begin == y.begin &&
           x.end == y.end &&
           x.offset == y.offset &&
           x.save == y.save &&
           x.abbrev == y.abbrev;
}

bool
is_equal(date::local_info const& x, date::local_info const& y)
{
    return x.result == y.result && is_equal(x.first, y.first)
                                && is_equal(x.second, y.second);
}

int
main()
{
    using namespace date;
    using namespace std;
    using namespace std::chrono;

    auto tzi = locate_zone("Australia/Sydney");
    Posix::time_zone tzp{"AEST-10AEDT,M10.1.0,M4.1.0/3"};
    auto tp = local_days{2021_y/1/1} + 0s;
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));
    
    tp = local_days{2021_y/10/Sunday[1]} + 2h + 30min;
    assert(tzp.get_info(tp).result == local_info::nonexistent);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/4/Sunday[1]} + 2h + 30min;
    assert(tzp.get_info(tp).result == local_info::ambiguous);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/7/1};
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));


    tzi = locate_zone("America/New_York");
    tzp = Posix::time_zone{"EST5EDT,M3.2.0,M11.1.0"};
    tp = local_days{2021_y/1/1};
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/3/Sunday[2]} + 2h + 30min;
    assert(tzp.get_info(tp).result == local_info::nonexistent);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/11/Sunday[1]} + 1h + 30min;
    assert(tzp.get_info(tp).result == local_info::ambiguous);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/7/1};
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));


    tzi = locate_zone("Europe/Dublin");
    tzp = Posix::time_zone{"IST-1GMT0,M10.5.0,M3.5.0/1"};
    tp = local_days{2021_y/1/1};
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/3/Sunday[last]} + 1h + 30min;
    assert(tzp.get_info(tp).result == local_info::nonexistent);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/10/Sunday[last]} + 1h + 30min;
    assert(tzp.get_info(tp).result == local_info::ambiguous);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));

    tp = local_days{2021_y/7/1};
    assert(tzp.get_info(tp).result == local_info::unique);
    assert(is_equal(tzi->get_info(tp), tzp.get_info(tp)));
}
