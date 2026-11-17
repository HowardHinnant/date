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

// to_stream with a month or date that is not ok() sets failbit and writes
// nothing for %b, %B, %h and %c, the same as %a does for an invalid weekday.

#include "date.h"
#include <cassert>
#include <sstream>
#include <string>

template <class T>
void
test_invalid(const char* fmt, const T& t)
{
    std::ostringstream os;
    date::to_stream(os, fmt, t);
    assert(os.fail());
    assert(os.str().empty());
}

int
main()
{
    using namespace date;
    test_invalid("%b", month{0});
    test_invalid("%B", month{0});
    test_invalid("%h", month{0});
    test_invalid("%b", month{13});
    test_invalid("%B", month{13});
    test_invalid("%h", month{13});
    test_invalid("%B", year{2024}/month{13}/day{1});
    test_invalid("%c", year{2024}/month{13}/day{1});
    test_invalid("%c", year{2024}/month{0}/day{1});

    std::ostringstream os;
    to_stream(os, "%b %B %h", month{3});
    assert(!os.fail());
    assert(os.str() == "Mar March Mar");
}
