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

#define CPP11_ASSERT(...) static_assert(__VA_ARGS__, "")

#if __cplusplus >= 201402
// C++14
#  define CPP14_ASSERT(...) static_assert(__VA_ARGS__, "")
#else
// C++11
#  define CPP14_ASSERT(...) assert(__VA_ARGS__)
#endif



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
       CPP14_ASSERT(ym + one_month == 2001_y/mar);
       CPP11_ASSERT(noexcept(ym + one_month));
       CPP14_ASSERT(one_month + ym == 2001_y/mar);
       CPP11_ASSERT(noexcept(one_month + ym));
       CPP14_ASSERT(ym - one_month == 2001_y/jan);
       CPP11_ASSERT(noexcept(ym - one_month));
       CPP14_ASSERT((copy(ym) += one_month) == 2001_y/mar);
       CPP11_ASSERT(noexcept(copy(ym) += one_month));
       CPP14_ASSERT((copy(ym) -= one_month) == 2001_y/jan);
       CPP11_ASSERT(noexcept(copy(ym) -= one_month));
      
       CPP11_ASSERT(ym + one_year == 2002_y/feb);
       CPP11_ASSERT(noexcept(ym + one_year));
       CPP11_ASSERT(one_year + ym == 2002_y/feb);
       CPP11_ASSERT(noexcept(one_year + ym));
       CPP11_ASSERT(ym - one_year == 2000_y/feb);
       CPP11_ASSERT(noexcept(ym - one_year));
       CPP14_ASSERT((copy(ym) += one_year) == 2002_y/feb);
       CPP11_ASSERT(noexcept(copy(ym) += one_year));
       CPP14_ASSERT((copy(ym) -= one_year) == 2000_y/feb);
       CPP11_ASSERT(noexcept(copy(ym) -= one_year));

       CPP11_ASSERT(ym + one_decade == 2011_y/feb);
       //CPP11_ASSERT(noexcept(ym + one_decade));
       CPP11_ASSERT(one_decade + ym == 2011_y/feb);
       //CPP11_ASSERT(noexcept(one_decade + ym));
       CPP11_ASSERT(ym - one_decade == 1991_y/feb);
       //CPP11_ASSERT(noexcept(ym - one_decade));
       CPP14_ASSERT((copy(ym) += one_decade) == 2011_y/feb);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decade));
       CPP14_ASSERT((copy(ym) -= one_decade) == 1991_y/feb);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decade));

       CPP14_ASSERT(ym + one_decamonth == 2001_y/dec);
       //CPP11_ASSERT(noexcept(ym + one_decamonth));
       CPP14_ASSERT(one_decamonth + ym  == 2001_y/dec);
       //CPP11_ASSERT(noexcept(one_decamonth + ym));
       CPP14_ASSERT(ym - one_decamonth == 2000_y/apr);
       //CPP11_ASSERT(noexcept(ym - one_decamonth));
       CPP14_ASSERT((copy(ym) += one_decamonth) == 2001_y/dec);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decamonth));
       CPP14_ASSERT((copy(ym) -= one_decamonth) == 2000_y/apr);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_day ym = 2001_y/feb/10;
       CPP14_ASSERT(ym + one_month == 2001_y/mar/10);
       CPP11_ASSERT(noexcept(ym + one_month));
       CPP14_ASSERT(one_month + ym == 2001_y/mar/10);
       CPP11_ASSERT(noexcept(one_month + ym));
       CPP14_ASSERT(ym - one_month == 2001_y/jan/10);
       CPP11_ASSERT(noexcept(ym - one_month));
       CPP14_ASSERT((copy(ym) += one_month) == 2001_y/mar/10);
       CPP11_ASSERT(noexcept(copy(ym) += one_month));
       CPP14_ASSERT((copy(ym) -= one_month) == 2001_y/jan/10);
       CPP11_ASSERT(noexcept(copy(ym) -= one_month));
      
       CPP11_ASSERT(ym + one_year == 2002_y/feb/10);
       CPP11_ASSERT(noexcept(ym + one_year));
       CPP11_ASSERT(one_year + ym == 2002_y/feb/10);
       CPP11_ASSERT(noexcept(one_year + ym));
       CPP11_ASSERT(ym - one_year == 2000_y/feb/10);
       CPP11_ASSERT(noexcept(ym - one_year));
       CPP14_ASSERT((copy(ym) += one_year) == 2002_y/feb/10);
       CPP11_ASSERT(noexcept(copy(ym) += one_year));
       CPP14_ASSERT((copy(ym) -= one_year) == 2000_y/feb/10);
       CPP11_ASSERT(noexcept(copy(ym) -= one_year));

       CPP11_ASSERT(ym + one_decade == 2011_y/feb/10);
       //CPP11_ASSERT(noexcept(ym + one_decade));
       CPP11_ASSERT(one_decade + ym == 2011_y/feb/10);
       //CPP11_ASSERT(noexcept(one_decade + ym));
       CPP11_ASSERT(ym - one_decade == 1991_y/feb/10);
       //CPP11_ASSERT(noexcept(ym - one_decade));
       CPP14_ASSERT((copy(ym) += one_decade) == 2011_y/feb/10);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decade));
       CPP14_ASSERT((copy(ym) -= one_decade) == 1991_y/feb/10);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decade));

       CPP14_ASSERT(ym + one_decamonth == 2001_y/dec/10);
       //CPP11_ASSERT(noexcept(ym + one_decamonth));
       CPP14_ASSERT(one_decamonth + ym  == 2001_y/dec/10);
       //CPP11_ASSERT(noexcept(one_decamonth + ym));
       CPP14_ASSERT(ym - one_decamonth == 2000_y/apr/10);
       //CPP11_ASSERT(noexcept(ym - one_decamonth));
       CPP14_ASSERT((copy(ym) += one_decamonth) == 2001_y/dec/10);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decamonth));
       CPP14_ASSERT((copy(ym) -= one_decamonth) == 2000_y/apr/10);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_day_last ym = 2001_y/feb/last;
       CPP14_ASSERT(ym + one_month == 2001_y/mar/last);
       CPP11_ASSERT(noexcept(ym + one_month));
       CPP14_ASSERT(one_month + ym == 2001_y/mar/last);
       CPP11_ASSERT(noexcept(one_month + ym));
       CPP14_ASSERT(ym - one_month == 2001_y/jan/last);
       CPP11_ASSERT(noexcept(ym - one_month));
       CPP14_ASSERT((copy(ym) += one_month) == 2001_y/mar/last);
       CPP11_ASSERT(noexcept(copy(ym) += one_month));
       CPP14_ASSERT((copy(ym) -= one_month) == 2001_y/jan/last);
       CPP11_ASSERT(noexcept(copy(ym) -= one_month));
      
       CPP11_ASSERT(ym + one_year == 2002_y/feb/last);
       CPP11_ASSERT(noexcept(ym + one_year));
       CPP11_ASSERT(one_year + ym == 2002_y/feb/last);
       CPP11_ASSERT(noexcept(one_year + ym));
       CPP11_ASSERT(ym - one_year == 2000_y/feb/last);
       CPP11_ASSERT(noexcept(ym - one_year));
       CPP14_ASSERT((copy(ym) += one_year) == 2002_y/feb/last);
       CPP11_ASSERT(noexcept(copy(ym) += one_year));
       CPP14_ASSERT((copy(ym) -= one_year) == 2000_y/feb/last);
       CPP11_ASSERT(noexcept(copy(ym) -= one_year));

       CPP11_ASSERT(ym + one_decade == 2011_y/feb/last);
       //CPP11_ASSERT(noexcept(ym + one_decade));
       CPP11_ASSERT(one_decade + ym == 2011_y/feb/last);
       //CPP11_ASSERT(noexcept(one_decade + ym));
       CPP11_ASSERT(ym - one_decade == 1991_y/feb/last);
       //CPP11_ASSERT(noexcept(ym - one_decade));
       CPP14_ASSERT((copy(ym) += one_decade) == 2011_y/feb/last);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decade));
       CPP14_ASSERT((copy(ym) -= one_decade) == 1991_y/feb/last);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decade));

       CPP14_ASSERT(ym + one_decamonth == 2001_y/dec/last);
       //CPP11_ASSERT(noexcept(ym + one_decamonth));
       CPP14_ASSERT(one_decamonth + ym  == 2001_y/dec/last);
       //CPP11_ASSERT(noexcept(one_decamonth + ym));
       CPP14_ASSERT(ym - one_decamonth == 2000_y/apr/last);
       //CPP11_ASSERT(noexcept(ym - one_decamonth));
       CPP14_ASSERT((copy(ym) += one_decamonth) == 2001_y/dec/last);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decamonth));
       CPP14_ASSERT((copy(ym) -= one_decamonth) == 2000_y/apr/last);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_weekday ym = 2001_y/feb/fri[4];
       CPP14_ASSERT(ym + one_month == 2001_y/mar/fri[4]);
       CPP11_ASSERT(noexcept(ym + one_month));
       CPP14_ASSERT(one_month + ym == 2001_y/mar/fri[4]);
       CPP11_ASSERT(noexcept(one_month + ym));
       CPP14_ASSERT(ym - one_month == 2001_y/jan/fri[4]);
       CPP11_ASSERT(noexcept(ym - one_month));
       CPP14_ASSERT((copy(ym) += one_month) == 2001_y/mar/fri[4]);
       CPP11_ASSERT(noexcept(copy(ym) += one_month));
       CPP14_ASSERT((copy(ym) -= one_month) == 2001_y/jan/fri[4]);
       CPP11_ASSERT(noexcept(copy(ym) -= one_month));
      
       CPP11_ASSERT(ym + one_year == 2002_y/feb/fri[4]);
       CPP11_ASSERT(noexcept(ym + one_year));
       CPP11_ASSERT(one_year + ym == 2002_y/feb/fri[4]);
       CPP11_ASSERT(noexcept(one_year + ym));
       CPP11_ASSERT(ym - one_year == 2000_y/feb/fri[4]);
       CPP11_ASSERT(noexcept(ym - one_year));
       CPP14_ASSERT((copy(ym) += one_year) == 2002_y/feb/fri[4]);
       CPP11_ASSERT(noexcept(copy(ym) += one_year));
       CPP14_ASSERT((copy(ym) -= one_year) == 2000_y/feb/fri[4]);
       CPP11_ASSERT(noexcept(copy(ym) -= one_year));

       CPP11_ASSERT(ym + one_decade == 2011_y/feb/fri[4]);
       //CPP11_ASSERT(noexcept(ym + one_decade));
       CPP11_ASSERT(one_decade + ym == 2011_y/feb/fri[4]);
       //CPP11_ASSERT(noexcept(one_decade + ym));
       CPP11_ASSERT(ym - one_decade == 1991_y/feb/fri[4]);
       //CPP11_ASSERT(noexcept(ym - one_decade));
       CPP14_ASSERT((copy(ym) += one_decade) == 2011_y/feb/fri[4]);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decade));
       CPP14_ASSERT((copy(ym) -= one_decade) == 1991_y/feb/fri[4]);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decade));

       CPP14_ASSERT(ym + one_decamonth == 2001_y/dec/fri[4]);
       //CPP11_ASSERT(noexcept(ym + one_decamonth));
       CPP14_ASSERT(one_decamonth + ym  == 2001_y/dec/fri[4]);
       //CPP11_ASSERT(noexcept(one_decamonth + ym));
       CPP14_ASSERT(ym - one_decamonth == 2000_y/apr/fri[4]);
       //CPP11_ASSERT(noexcept(ym - one_decamonth));
       CPP14_ASSERT((copy(ym) += one_decamonth) == 2001_y/dec/fri[4]);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decamonth));
       CPP14_ASSERT((copy(ym) -= one_decamonth) == 2000_y/apr/fri[4]);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decamonth));
    }

    {
       constexpr year_month_weekday_last ym = 2001_y/feb/fri[last];
       CPP14_ASSERT(ym + one_month == 2001_y/mar/fri[last]);
       CPP11_ASSERT(noexcept(ym + one_month));
       CPP14_ASSERT(one_month + ym == 2001_y/mar/fri[last]);
       CPP11_ASSERT(noexcept(one_month + ym));
       CPP14_ASSERT(ym - one_month == 2001_y/jan/fri[last]);
       CPP11_ASSERT(noexcept(ym - one_month));
       CPP14_ASSERT((copy(ym) += one_month) == 2001_y/mar/fri[last]);
       CPP11_ASSERT(noexcept(copy(ym) += one_month));
       CPP14_ASSERT((copy(ym) -= one_month) == 2001_y/jan/fri[last]);
       CPP11_ASSERT(noexcept(copy(ym) -= one_month));
      
       CPP11_ASSERT(ym + one_year == 2002_y/feb/fri[last]);
       CPP11_ASSERT(noexcept(ym + one_year));
       CPP11_ASSERT(one_year + ym == 2002_y/feb/fri[last]);
       CPP11_ASSERT(noexcept(one_year + ym));
       CPP11_ASSERT(ym - one_year == 2000_y/feb/fri[last]);
       CPP11_ASSERT(noexcept(ym - one_year));
       CPP14_ASSERT((copy(ym) += one_year) == 2002_y/feb/fri[last]);
       CPP11_ASSERT(noexcept(copy(ym) += one_year));
       CPP14_ASSERT((copy(ym) -= one_year) == 2000_y/feb/fri[last]);
       CPP11_ASSERT(noexcept(copy(ym) -= one_year));

       CPP11_ASSERT(ym + one_decade == 2011_y/feb/fri[last]);
       //CPP11_ASSERT(noexcept(ym + one_decade));
       CPP11_ASSERT(one_decade + ym == 2011_y/feb/fri[last]);
       //CPP11_ASSERT(noexcept(one_decade + ym));
       CPP11_ASSERT(ym - one_decade == 1991_y/feb/fri[last]);
       //CPP11_ASSERT(noexcept(ym - one_decade));
       CPP14_ASSERT((copy(ym) += one_decade) == 2011_y/feb/fri[last]);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decade));
       CPP14_ASSERT((copy(ym) -= one_decade) == 1991_y/feb/fri[last]);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decade));

       CPP14_ASSERT(ym + one_decamonth == 2001_y/dec/fri[last]);
       //CPP11_ASSERT(noexcept(ym + one_decamonth));
       CPP14_ASSERT(one_decamonth + ym  == 2001_y/dec/fri[last]);
       //CPP11_ASSERT(noexcept(one_decamonth + ym));
       CPP14_ASSERT(ym - one_decamonth == 2000_y/apr/fri[last]);
       //CPP11_ASSERT(noexcept(ym - one_decamonth));
       CPP14_ASSERT((copy(ym) += one_decamonth) == 2001_y/dec/fri[last]);
       //CPP11_ASSERT(noexcept(copy(ym) += one_decamonth));
       CPP14_ASSERT((copy(ym) -= one_decamonth) == 2000_y/apr/fri[last]);
       //CPP11_ASSERT(noexcept(copy(ym) -= one_decamonth));
    }

}
