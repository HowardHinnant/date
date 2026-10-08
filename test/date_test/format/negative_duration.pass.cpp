// The MIT License (MIT)
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

// A negative duration is formatted as the corresponding positive value with
// a single '-' in front of the first conversion that prints part of it.

#include "date.h"
#include <cassert>
#include <chrono>

int
main()
{
    using namespace date;
    using namespace std::chrono;
    auto d = -(hours{1} + minutes{2} + seconds{3});

    assert(format("%T", d) == "-01:02:03");
    assert(format("%R", d) == "-01:02");
    assert(format("%H:%M:%S", d) == "-01:02:03");
    assert(format("%Q", d) == "-3723");

    // Only the first conversion gets the sign.
    assert(format("%H %T", d) == "-01 01:02:03");
    assert(format("%T %H", d) == "-01:02:03 01");
    assert(format("%R %S", d) == "-01:02 03");
    assert(format("%Q %T", d) == "-3723 01:02:03");
    assert(format("%T %Q", d) == "-01:02:03 3723");

    auto ms = -milliseconds{50};
    assert(format("%T", ms) == "-00:00:00.050");
    assert(format("%R:%S", ms) == "-00:00:00.050");

    // Positive values are unchanged.
    assert(format("%T %R", -d) == "01:02:03 01:02");

#if ONLY_C_LOCALE
    assert(format("%X", d) == "-01:02:03");
    assert(format("%r", d) == "-01:02:03 AM");
#else
    assert(format("%X", d).front() == '-');
    assert(format("%r", d).front() == '-');
#endif
}
