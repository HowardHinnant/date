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

// Commented noexcept test cases depends on duration constructors from other duration being noexcept.
// The constants are used to avoid invoking it inside noexcept.

int
main()
{
    using namespace date;
    using namespace std::chrono;

    using decades = duration<int, std::ratio_multiply<std::ratio<10>, years::period>>;
    using decamonths = duration<int, std::ratio_multiply<std::ratio<10>, months::period>>;

    constexpr months one_month{1};
    constexpr years one_year{1};
    constexpr decades one_decade{1};
    constexpr decamonths one_decamonth{1};

    {
       constexpr year_month ym = 2001_y/feb;
       static_assert(ym + one_month == 2001_y/mar);
       static_assert(noexcept(ym + one_month));
       static_assert(one_month + ym == 2001_y/mar);
       static_assert(noexcept(one_month + ym));
       static_assert(ym - one_month == 2001_y/jan);
       static_assert(noexcept(ym - one_month));
       static_assert((copy(ym) += one_month) == 2001_y/mar);
       static_assert(noexcept(copy(ym) += one_month));
       static_assert((copy(ym) -= one_month) == 2001_y/jan);
       static_assert(noexcept(copy(ym) -= one_month));
      
       static_assert(ym + one_year == 2002_y/feb);
       static_assert(noexcept(ym + one_year));
       static_assert(one_year + ym == 2002_y/feb);
       static_assert(noexcept(one_year + ym));
       static_assert(ym - one_year == 2000_y/feb);
       static_assert(noexcept(ym - one_year));
       static_assert((copy(ym) += one_year) == 2002_y/feb);
       static_assert(noexcept(copy(ym) += one_year));
       static_assert((copy(ym) -= one_year) == 2000_y/feb);
       static_assert(noexcept(copy(ym) -= one_year));

       static_assert(ym + one_decade == 2011_y/feb);
       //static_assert(noexcept(ym + one_decade));
       static_assert(one_decade + ym == 2011_y/feb);
       //static_assert(noexcept(one_decade + ym));
       static_assert(ym - one_decade == 1991_y/feb);
       //static_assert(noexcept(ym - one_decade));
       static_assert((copy(ym) += one_decade) == 2011_y/feb);
       //static_assert(noexcept(copy(ym) += one_decade));
       static_assert((copy(ym) -= one_decade) == 1991_y/feb);
       //static_assert(noexcept(copy(ym) -= one_decade));

       static_assert(ym + one_decamonth == 2001_y/dec);
       //static_assert(noexcept(ym + one_decamonth));
       static_assert(one_decamonth + ym == 2001_y/dec);
       //static_assert(noexcept(one_decamonth + ym));
       static_assert(ym - one_decamonth == 2000_y/apr);
       //static_assert(noexcept(ym - one_decamonth));
       static_assert((copy(ym) += one_decamonth) == 2001_y/dec);
       //static_assert(noexcept(copy(ym) += one_decamonth));
       static_assert((copy(ym) -= one_decamonth) == 2000_y/apr);
       //static_assert(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_day ym = 2001_y/feb/10;
       static_assert(ym + one_month == 2001_y/mar/10);
       static_assert(noexcept(ym + one_month));
       static_assert(one_month + ym == 2001_y/mar/10);
       static_assert(noexcept(one_month + ym));
       static_assert(ym - one_month == 2001_y/jan/10);
       static_assert(noexcept(ym - one_month));
       static_assert((copy(ym) += one_month) == 2001_y/mar/10);
       static_assert(noexcept(copy(ym) += one_month));
       static_assert((copy(ym) -= one_month) == 2001_y/jan/10);
       static_assert(noexcept(copy(ym) -= one_month));
      
       static_assert(ym + one_year == 2002_y/feb/10);
       static_assert(noexcept(ym + one_year));
       static_assert(one_year + ym == 2002_y/feb/10);
       static_assert(noexcept(one_year + ym));
       static_assert(ym - one_year == 2000_y/feb/10);
       static_assert(noexcept(ym - one_year));
       static_assert((copy(ym) += one_year) == 2002_y/feb/10);
       static_assert(noexcept(copy(ym) += one_year));
       static_assert((copy(ym) -= one_year) == 2000_y/feb/10);
       static_assert(noexcept(copy(ym) -= one_year));

       static_assert(ym + one_decade == 2011_y/feb/10);
       //static_assert(noexcept(ym + one_decade));
       static_assert(one_decade + ym == 2011_y/feb/10);
       //static_assert(noexcept(one_decade + ym));
       static_assert(ym - one_decade == 1991_y/feb/10);
       //static_assert(noexcept(ym - one_decade));
       static_assert((copy(ym) += one_decade) == 2011_y/feb/10);
       //static_assert(noexcept(copy(ym) += one_decade));
       static_assert((copy(ym) -= one_decade) == 1991_y/feb/10);
       //static_assert(noexcept(copy(ym) -= one_decade));

       static_assert(ym + one_decamonth == 2001_y/dec/10);
       //static_assert(noexcept(ym + one_decamonth));
       static_assert(one_decamonth + ym == 2001_y/dec/10);
       //static_assert(noexcept(one_decamonth + ym));
       static_assert(ym - one_decamonth == 2000_y/apr/10);
       //static_assert(noexcept(ym - one_decamonth));
       static_assert((copy(ym) += one_decamonth) == 2001_y/dec/10);
       //static_assert(noexcept(copy(ym) += one_decamonth));
       static_assert((copy(ym) -= one_decamonth) == 2000_y/apr/10);
       //static_assert(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_day_last ym = 2001_y/feb/last;
       static_assert(ym + one_month == 2001_y/mar/last);
       static_assert(noexcept(ym + one_month));
       static_assert(one_month + ym == 2001_y/mar/last);
       static_assert(noexcept(one_month + ym));
       static_assert(ym - one_month == 2001_y/jan/last);
       static_assert(noexcept(ym - one_month));
       static_assert((copy(ym) += one_month) == 2001_y/mar/last);
       static_assert(noexcept(copy(ym) += one_month));
       static_assert((copy(ym) -= one_month) == 2001_y/jan/last);
       static_assert(noexcept(copy(ym) -= one_month));
      
       static_assert(ym + one_year == 2002_y/feb/last);
       static_assert(noexcept(ym + one_year));
       static_assert(one_year + ym == 2002_y/feb/last);
       static_assert(noexcept(one_year + ym));
       static_assert(ym - one_year == 2000_y/feb/last);
       static_assert(noexcept(ym - one_year));
       static_assert((copy(ym) += one_year) == 2002_y/feb/last);
       static_assert(noexcept(copy(ym) += one_year));
       static_assert((copy(ym) -= one_year) == 2000_y/feb/last);
       static_assert(noexcept(copy(ym) -= one_year));

       static_assert(ym + one_decade == 2011_y/feb/last);
       //static_assert(noexcept(ym + one_decade));
       static_assert(one_decade + ym == 2011_y/feb/last);
       //static_assert(noexcept(one_decade + ym));
       static_assert(ym - one_decade == 1991_y/feb/last);
       //static_assert(noexcept(ym - one_decade));
       static_assert((copy(ym) += one_decade) == 2011_y/feb/last);
       //static_assert(noexcept(copy(ym) += one_decade));
       static_assert((copy(ym) -= one_decade) == 1991_y/feb/last);
       //static_assert(noexcept(copy(ym) -= one_decade));

       static_assert(ym + one_decamonth == 2001_y/dec/last);
       //static_assert(noexcept(ym + one_decamonth));
       static_assert(one_decamonth + ym == 2001_y/dec/last);
       //static_assert(noexcept(one_decamonth + ym));
       static_assert(ym - one_decamonth == 2000_y/apr/last);
       //static_assert(noexcept(ym - one_decamonth));
       static_assert((copy(ym) += one_decamonth) == 2001_y/dec/last);
       //static_assert(noexcept(copy(ym) += one_decamonth));
       static_assert((copy(ym) -= one_decamonth) == 2000_y/apr/last);
       //static_assert(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_weekday ym = 2001_y/feb/fri[4];
       static_assert(ym + one_month == 2001_y/mar/fri[4]);
       static_assert(noexcept(ym + one_month));
       static_assert(one_month + ym == 2001_y/mar/fri[4]);
       static_assert(noexcept(one_month + ym));
       static_assert(ym - one_month == 2001_y/jan/fri[4]);
       static_assert(noexcept(ym - one_month));
       static_assert((copy(ym) += one_month) == 2001_y/mar/fri[4]);
       static_assert(noexcept(copy(ym) += one_month));
       static_assert((copy(ym) -= one_month) == 2001_y/jan/fri[4]);
       static_assert(noexcept(copy(ym) -= one_month));
      
       static_assert(ym + one_year == 2002_y/feb/fri[4]);
       static_assert(noexcept(ym + one_year));
       static_assert(one_year + ym == 2002_y/feb/fri[4]);
       static_assert(noexcept(one_year + ym));
       static_assert(ym - one_year == 2000_y/feb/fri[4]);
       static_assert(noexcept(ym - one_year));
       static_assert((copy(ym) += one_year) == 2002_y/feb/fri[4]);
       static_assert(noexcept(copy(ym) += one_year));
       static_assert((copy(ym) -= one_year) == 2000_y/feb/fri[4]);
       static_assert(noexcept(copy(ym) -= one_year));

       static_assert(ym + one_decade == 2011_y/feb/fri[4]);
       //static_assert(noexcept(ym + one_decade));
       static_assert(one_decade + ym == 2011_y/feb/fri[4]);
       //static_assert(noexcept(one_decade + ym));
       static_assert(ym - one_decade == 1991_y/feb/fri[4]);
       //static_assert(noexcept(ym - one_decade));
       static_assert((copy(ym) += one_decade) == 2011_y/feb/fri[4]);
       //static_assert(noexcept(copy(ym) += one_decade));
       static_assert((copy(ym) -= one_decade) == 1991_y/feb/fri[4]);
       //static_assert(noexcept(copy(ym) -= one_decade));

       static_assert(ym + one_decamonth == 2001_y/dec/fri[4]);
       //static_assert(noexcept(ym + one_decamonth));
       static_assert(one_decamonth + ym == 2001_y/dec/fri[4]);
       //static_assert(noexcept(one_decamonth + ym));
       static_assert(ym - one_decamonth == 2000_y/apr/fri[4]);
       //static_assert(noexcept(ym - one_decamonth));
       static_assert((copy(ym) += one_decamonth) == 2001_y/dec/fri[4]);
       //static_assert(noexcept(copy(ym) += one_decamonth));
       static_assert((copy(ym) -= one_decamonth) == 2000_y/apr/fri[4]);
       //static_assert(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_weekday_last ym = 2001_y/feb/fri[last];
       static_assert(ym + one_month == 2001_y/mar/fri[last]);
       static_assert(noexcept(ym + one_month));
       static_assert(one_month + ym == 2001_y/mar/fri[last]);
       static_assert(noexcept(one_month + ym));
       static_assert(ym - one_month == 2001_y/jan/fri[last]);
       static_assert(noexcept(ym - one_month));
       static_assert((copy(ym) += one_month) == 2001_y/mar/fri[last]);
       static_assert(noexcept(copy(ym) += one_month));
       static_assert((copy(ym) -= one_month) == 2001_y/jan/fri[last]);
       static_assert(noexcept(copy(ym) -= one_month));
      
       static_assert(ym + one_year == 2002_y/feb/fri[last]);
       static_assert(noexcept(ym + one_year));
       static_assert(one_year + ym == 2002_y/feb/fri[last]);
       static_assert(noexcept(one_year + ym));
       static_assert(ym - one_year == 2000_y/feb/fri[last]);
       static_assert(noexcept(ym - one_year));
       static_assert((copy(ym) += one_year) == 2002_y/feb/fri[last]);
       static_assert(noexcept(copy(ym) += one_year));
       static_assert((copy(ym) -= one_year) == 2000_y/feb/fri[last]);
       static_assert(noexcept(copy(ym) -= one_year));

       static_assert(ym + one_decade == 2011_y/feb/fri[last]);
       //static_assert(noexcept(ym + one_decade));
       static_assert(one_decade + ym == 2011_y/feb/fri[last]);
       //static_assert(noexcept(one_decade + ym));
       static_assert(ym - one_decade == 1991_y/feb/fri[last]);
       //static_assert(noexcept(ym - one_decade));
       static_assert((copy(ym) += one_decade) == 2011_y/feb/fri[last]);
       //static_assert(noexcept(copy(ym) += one_decade));
       static_assert((copy(ym) -= one_decade) == 1991_y/feb/fri[last]);
       //static_assert(noexcept(copy(ym) -= one_decade));

       static_assert(ym + one_decamonth == 2001_y/dec/fri[last]);
       //static_assert(noexcept(ym + one_decamonth));
       static_assert(one_decamonth + ym == 2001_y/dec/fri[last]);
       //static_assert(noexcept(one_decamonth + ym));
       static_assert(ym - one_decamonth == 2000_y/apr/fri[last]);
       //static_assert(noexcept(ym - one_decamonth));
       static_assert((copy(ym) += one_decamonth) == 2001_y/dec/fri[last]);
       //static_assert(noexcept(copy(ym) += one_decamonth));
       static_assert((copy(ym) -= one_decamonth) == 2000_y/apr/fri[last]);
       //static_assert(noexcept(copy(ym) -= one_decamonth));
    }

}
