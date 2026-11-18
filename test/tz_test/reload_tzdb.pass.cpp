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

// A time_zone from an earlier tzdb must keep giving the same answers after
// reload_tzdb().  It walks its own database's rules, not get_tzdb().rules.

#include "tz.h"
#include <cassert>
#include <sstream>
#include <string>
#include <vector>

#if !USE_OS_TZDB

static
std::string
snapshot(const date::time_zone& tz)
{
    using namespace date;
    std::ostringstream os;
    for (int y = 1970; y <= 2040; y += 3)
        for (unsigned m = 1; m <= 12; ++m)
            os << tz.get_info(sys_days{year{y}/m/1}) << '\n';
    return os.str();
}

#endif  // !USE_OS_TZDB

int
main()
{
#if !USE_OS_TZDB
    using namespace date;
    auto const& db = get_tzdb();
    std::vector<std::string> before;
    for (auto const& tz : db.zones)
        before.push_back(snapshot(tz));
    reload_tzdb();
    for (std::size_t i = 0; i < db.zones.size(); ++i)
        assert(snapshot(db.zones[i]) == before[i]);
#endif  // !USE_OS_TZDB
}
