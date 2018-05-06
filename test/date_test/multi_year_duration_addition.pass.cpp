// The MIT License (MIT)
//
// Copyright (c) 2018 Tomasz Kamiński
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


#include "date.h"
#include <chrono>
#include <cassert>
#include <type_traits>

template<typename T>
constexpr T copy(T const& t) noexcept { return t; }

int
main()
{
    using namespace date;
    using namespace std::chrono;

    using decades = duration<int, std::ratio_multiply<std::ratio<10>, years::period>>;
    using decamonths = duration<int, std::ratio_multiply<std::ratio<10>, months::period>>;

    {
       constexpr year_month ym{2001_y, feb};
       static_assert(ym + months{1} == 2001_y/mar);
       static_assert(noexcept(ym + months{1}));
       static_assert(months{1} + ym == 2001_y/mar);
       static_assert(noexcept(months{1} + ym));
       static_assert(ym - months{1} == 2001_y/jan);
       static_assert(noexcept(ym - months{1}));
       static_assert((copy(ym) += months{1}) == 2001_y/mar);
       static_assert(noexcept(copy(ym) += months{1}));
       static_assert((copy(ym) -= months{1}) == 2001_y/jan);
       static_assert(noexcept(copy(ym) -= months{1}));
      
       static_assert(ym + years{1} == 2002_y/feb);
       static_assert(noexcept(ym + years{1}));
       static_assert(years{1} + ym == 2002_y/feb);
       static_assert(noexcept(years{1} + ym));
       static_assert(ym - years{1} == 2000_y/feb);
       static_assert(noexcept(ym - years{1}));
       static_assert((copy(ym) += years{1}) == 2002_y/feb);
       static_assert(noexcept(copy(ym) += years{1}));
       static_assert((copy(ym) -= years{1}) == 2000_y/feb);
       static_assert(noexcept(copy(ym) -= years{1}));

       static_assert(ym + decades{1} == 2011_y/feb);
       static_assert(noexcept(ym + decades{1}));
       static_assert(decades{1} + ym == 2011_y/feb);
       static_assert(noexcept(decades{1} + ym));
       static_assert(ym - decades{1} == 1991_y/feb);
       static_assert(noexcept(ym - decades{1}));
       static_assert((copy(ym) += decades{1}) == 2011_y/feb);
       static_assert(noexcept(copy(ym) += decades{1}));
       static_assert((copy(ym) -= decades{1}) == 1991_y/feb);
       static_assert(noexcept(copy(ym) -= decades{1}));

       static_assert(ym + decamonths{1} == 2001_y/dec);
       static_assert(noexcept(ym + decamonths{1}));
       static_assert(decamonths{1} + ym == 2001_y/dec);
       static_assert(noexcept(decamonths{1} + ym));
       static_assert(ym - decamonths{1} == 2000_y/apr);
       static_assert(noexcept(ym - decamonths{1}));
       static_assert((copy(ym) += decamonths{1}) == 2001_y/dec);
       static_assert(noexcept(copy(ym) += decamonths{1}));
       static_assert((copy(ym) -= decamonths{1}) == 2000_y/apr);
       static_assert(noexcept(copy(ym) -= decamonths{1}));
    }

    {
       constexpr year_month_day ym{2001_y, feb, 10_d};
       static_assert(ym + months{1} == 2001_y/mar/10);
       static_assert(noexcept(ym + months{1}));
       static_assert(months{1} + ym == 2001_y/mar/10);
       static_assert(noexcept(months{1} + ym));
       static_assert(ym - months{1} == 2001_y/jan/10);
       static_assert(noexcept(ym - months{1}));
       static_assert((copy(ym) += months{1}) == 2001_y/mar/10);
       static_assert(noexcept(copy(ym) += months{1}));
       static_assert((copy(ym) -= months{1}) == 2001_y/jan/10);
       static_assert(noexcept(copy(ym) -= months{1}));
      
       static_assert(ym + years{1} == 2002_y/feb/10);
       static_assert(noexcept(ym + years{1}));
       static_assert(years{1} + ym == 2002_y/feb/10);
       static_assert(noexcept(years{1} + ym));
       static_assert(ym - years{1} == 2000_y/feb/10);
       static_assert(noexcept(ym - years{1}));
       static_assert((copy(ym) += years{1}) == 2002_y/feb/10);
       static_assert(noexcept(copy(ym) += years{1}));
       static_assert((copy(ym) -= years{1}) == 2000_y/feb/10);
       static_assert(noexcept(copy(ym) -= years{1}));

      /* static_assert(ym + decades{1} == 2011_y/feb/10);
       static_assert(noexcept(ym + decades{1}));
       static_assert(decades{1} + ym == 2011_y/feb/10);
       static_assert(noexcept(decades{1} + ym));
       static_assert(ym - decades{1} == 1991_y/feb/10);
       static_assert(noexcept(ym - decades{1}));
       static_assert((copy(ym) += decades{1}) == 2011_y/feb/10);
       static_assert(noexcept(copy(ym) += decades{1}));
       static_assert((copy(ym) -= decades{1}) == 1991_y/feb/10);
       static_assert(noexcept(copy(ym) -= decades{1}));*/

       static_assert(ym + decamonths{1} == 2001_y/dec/10);
       static_assert(noexcept(ym + decamonths{1}));
       static_assert(decamonths{1} + ym == 2001_y/dec/10);
       static_assert(noexcept(decamonths{1} + ym));
       static_assert(ym - decamonths{1} == 2000_y/apr/10);
       static_assert(noexcept(ym - decamonths{1}));
       static_assert((copy(ym) += decamonths{1}) == 2001_y/dec/10);
       static_assert(noexcept(copy(ym) += decamonths{1}));
       static_assert((copy(ym) -= decamonths{1}) == 2000_y/apr/10);
       static_assert(noexcept(copy(ym) -= decamonths{1}));
    }

}
