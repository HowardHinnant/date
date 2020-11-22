// The MIT License (MIT)
//
// Copyright (c) 2017 Howard Hinnant
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

// width<n>::value is the number of fractional decimal digits in 1/n
// width<0>::value and width<1>::value are defined to be 0
// If 1/n takes more than 18 fractional decimal digits,
//   the result is truncated to 19.
// Example:  width<2>::value    ==  1
// Example:  width<3>::value    == 19
// Example:  width<4>::value    ==  2
// Example:  width<10>::value   ==  1
// Example:  width<1000>::value ==  3
// template <std::uint64_t n>
//
// struct width
// {
//     static constexpr unsigned value = ...;
// };

#include "date.h"

#include <cassert>
#include <sstream>
#include <type_traits>

int
main()
{
    using namespace date::detail;
    static_assert(width<0, 1>::value == 0, "");
    static_assert(width<1, 1>::value == 0, "");
    static_assert(width<1, 2>::value == 1, "");
    static_assert(width<1, 3>::value == 19, "");
    static_assert(width<1, 4>::value == 2, "");
    static_assert(width<1, 5>::value == 1, "");
    static_assert(width<1, 6>::value == 19, "");
    static_assert(width<1, 7>::value == 19, "");
    static_assert(width<1, 8>::value == 3, "");
    static_assert(width<1, 9>::value == 19, "");
    static_assert(width<1, 10>::value == 1, "");
    static_assert(width<1, 100>::value == 2, "");
    static_assert(width<1, 1000>::value == 3, "");
    static_assert(width<1, 10000>::value == 4, "");
    static_assert(width<756, 625>::value == 4, "");
}
