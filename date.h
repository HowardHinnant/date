#ifndef DATE_H
#define DATE_H

// The MIT License (MIT)
// 
// Copyright (c) 2015 Howard Hinnant
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

#include <chrono>
#include <climits>
#if !(__cplusplus >= 201402)
#  include <cmath>
#endif
#include <limits>
#include <ostream>
#include <ratio>
#include <stdexcept>

namespace date
{

//---------------+
// Configuration |
//---------------+

// MSVC's constexpr support is still a WIP, even in VS2015.
// Fall back to a lesser mode to support it.
// TODO: Remove this or retest later once MSVC's constexpr improves.
#if defined(_MSC_VER)
#  define CONSTDATA const
#  define CONSTCD11
#  define CONSTCD14
#elif __cplusplus >= 201402
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14 constexpr
#  define _NOEXCEPT noexcept
#else
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14
#  define _NOEXCEPT noexcept
#endif

//-----------+
// Interface |
//-----------+

// durations

using days = std::chrono::duration
    <int, std::ratio_multiply<std::ratio<24>, std::chrono::hours::period>>;

using weeks = std::chrono::duration
    <int, std::ratio_multiply<std::ratio<7>, days::period>>;

using years = std::chrono::duration
    <int, std::ratio_multiply<std::ratio<146097, 400>, days::period>>;

using months = std::chrono::duration
    <int, std::ratio_divide<years::period, std::ratio<12>>>;

// time_point

using day_point = std::chrono::time_point<std::chrono::system_clock, days>;

// types

struct last_spec
{
    explicit last_spec() = default;
};

class day;
class month;
class year;

class weekday;
class weekday_indexed;
class weekday_last;

class month_day;
class month_day_last;
class month_weekday;
class month_weekday_last;

class year_month;

class year_month_day;
class year_month_day_last;
class year_month_weekday;
class year_month_weekday_last;

// date composition operators

CONSTCD11 year_month operator/(const year& y, const month& m) _NOEXCEPT;
CONSTCD11 year_month operator/(const year& y, int          m) _NOEXCEPT;

CONSTCD11 month_day operator/(const day& d, const month& m) _NOEXCEPT;
CONSTCD11 month_day operator/(const day& d, int          m) _NOEXCEPT;
CONSTCD11 month_day operator/(const month& m, const day& d) _NOEXCEPT;
CONSTCD11 month_day operator/(const month& m, int        d) _NOEXCEPT;
CONSTCD11 month_day operator/(int          m, const day& d) _NOEXCEPT;

CONSTCD11 month_day_last operator/(const month& m, last_spec) _NOEXCEPT;
CONSTCD11 month_day_last operator/(int          m, last_spec) _NOEXCEPT;
CONSTCD11 month_day_last operator/(last_spec, const month& m) _NOEXCEPT;
CONSTCD11 month_day_last operator/(last_spec, int          m) _NOEXCEPT;

CONSTCD11 month_weekday operator/(const month& m, const weekday_indexed& wdi) _NOEXCEPT;
CONSTCD11 month_weekday operator/(int          m, const weekday_indexed& wdi) _NOEXCEPT;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, const month& m) _NOEXCEPT;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, int          m) _NOEXCEPT;

CONSTCD11 month_weekday_last operator/(const month& m, const weekday_last& wdl) _NOEXCEPT;
CONSTCD11 month_weekday_last operator/(int          m, const weekday_last& wdl) _NOEXCEPT;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, const month& m) _NOEXCEPT;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, int          m) _NOEXCEPT;

CONSTCD11 year_month_day operator/(const year_month& ym, const day& d) _NOEXCEPT;
CONSTCD11 year_month_day operator/(const year_month& ym, int        d) _NOEXCEPT;
CONSTCD11 year_month_day operator/(const year& y, const month_day& md) _NOEXCEPT;
CONSTCD11 year_month_day operator/(int         y, const month_day& md) _NOEXCEPT;
CONSTCD11 year_month_day operator/(const month_day& md, const year& y) _NOEXCEPT;
CONSTCD11 year_month_day operator/(const month_day& md, int         y) _NOEXCEPT;

CONSTCD11
    year_month_day_last operator/(const year_month& ym,   last_spec) _NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const year& y, const month_day_last& mdl) _NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(int         y, const month_day_last& mdl) _NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, const year& y) _NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, int         y) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const year&        y, const month_weekday&   mwd) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(int                y, const month_weekday&   mwd) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, const year&          y) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, int                  y) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(int         y, const month_weekday_last& mwdl) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int         y) _NOEXCEPT;

// Detailed interface

// day

class day
{
    unsigned char d_;

public:
    explicit CONSTCD11 day(unsigned d = 0) _NOEXCEPT;

    day& operator++()    _NOEXCEPT;
    day  operator++(int) _NOEXCEPT;
    day& operator--()    _NOEXCEPT;
    day  operator--(int) _NOEXCEPT;

    day& operator+=(const days& d) _NOEXCEPT;
    day& operator-=(const days& d) _NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const day& x, const day& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const day& x, const day& y) _NOEXCEPT;
CONSTCD11 bool operator< (const day& x, const day& y) _NOEXCEPT;
CONSTCD11 bool operator> (const day& x, const day& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const day& x, const day& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const day& x, const day& y) _NOEXCEPT;

CONSTCD11 day  operator+(const day&  x, const days& y) _NOEXCEPT;
CONSTCD11 day  operator+(const days& x, const day&  y) _NOEXCEPT;
CONSTCD11 day  operator-(const day&  x, const days& y) _NOEXCEPT;
CONSTCD11 days operator-(const day&  x, const day&  y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const day& d);

// month

class month
{
    unsigned char m_;

public:
    explicit CONSTCD11 month(unsigned m = 0) _NOEXCEPT;

    month& operator++()    _NOEXCEPT;
    month  operator++(int) _NOEXCEPT;
    month& operator--()    _NOEXCEPT;
    month  operator--(int) _NOEXCEPT;

    month& operator+=(const months& m) _NOEXCEPT;
    month& operator-=(const months& m) _NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const month& x, const month& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const month& x, const month& y) _NOEXCEPT;
CONSTCD11 bool operator< (const month& x, const month& y) _NOEXCEPT;
CONSTCD11 bool operator> (const month& x, const month& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const month& x, const month& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const month& x, const month& y) _NOEXCEPT;

CONSTCD14 month  operator+(const month&  x, const months& y) _NOEXCEPT;
CONSTCD14 month  operator+(const months& x,  const month& y) _NOEXCEPT;
CONSTCD14 month  operator-(const month&  x, const months& y) _NOEXCEPT;
CONSTCD14 months operator-(const month&  x,  const month& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const month& m);

// year

class year
{
    short y_;

public:
    explicit CONSTCD11 year(int y = 0) _NOEXCEPT;

    year& operator++()    _NOEXCEPT;
    year  operator++(int) _NOEXCEPT;
    year& operator--()    _NOEXCEPT;
    year  operator--(int) _NOEXCEPT;

    year& operator+=(const years& y) _NOEXCEPT;
    year& operator-=(const years& y) _NOEXCEPT;

    CONSTCD11 bool is_leap() const _NOEXCEPT;

    CONSTCD11 explicit operator int() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;

    static CONSTCD11 year min() _NOEXCEPT;
    static CONSTCD11 year max() _NOEXCEPT;
};

CONSTCD11 bool operator==(const year& x, const year& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const year& x, const year& y) _NOEXCEPT;
CONSTCD11 bool operator< (const year& x, const year& y) _NOEXCEPT;
CONSTCD11 bool operator> (const year& x, const year& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const year& x, const year& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const year& x, const year& y) _NOEXCEPT;

CONSTCD11 year  operator+(const year&  x, const years& y) _NOEXCEPT;
CONSTCD11 year  operator+(const years& x, const year&  y) _NOEXCEPT;
CONSTCD11 year  operator-(const year&  x, const years& y) _NOEXCEPT;
CONSTCD11 years operator-(const year&  x, const year&  y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year& y);

// weekday

class weekday
{
    unsigned char wd_;
public:
    explicit CONSTCD11 weekday(unsigned wd = 0) _NOEXCEPT;
    explicit weekday(int) = delete;
    CONSTCD11 weekday(const day_point& dp) _NOEXCEPT;

    weekday& operator++()    _NOEXCEPT;
    weekday  operator++(int) _NOEXCEPT;
    weekday& operator--()    _NOEXCEPT;
    weekday  operator--(int) _NOEXCEPT;

    weekday& operator+=(const days& d) _NOEXCEPT;
    weekday& operator-=(const days& d) _NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;

    CONSTCD11 weekday_indexed operator[](unsigned index) const _NOEXCEPT;
    CONSTCD11 weekday_last    operator[](last_spec)      const _NOEXCEPT;

private:
    static CONSTCD11 unsigned char weekday_from_days(int z) _NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday& x, const weekday& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const weekday& x, const weekday& y) _NOEXCEPT;

CONSTCD14 weekday operator+(const weekday& x, const days&    y) _NOEXCEPT;
CONSTCD14 weekday operator+(const days&    x, const weekday& y) _NOEXCEPT;
CONSTCD14 weekday operator-(const weekday& x, const days&    y) _NOEXCEPT;
CONSTCD14 days    operator-(const weekday& x, const weekday& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const weekday& wd);

// weekday_indexed

class weekday_indexed
{
    unsigned char wd_    : 4;
    unsigned char index_ : 4;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 weekday_indexed() : wd_(0), index_(0) {}
#endif

    CONSTCD11 weekday_indexed(const date::weekday& wd, unsigned index) _NOEXCEPT;

    CONSTCD11 date::weekday weekday() const _NOEXCEPT;
    CONSTCD11 unsigned index() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday_indexed& x, const weekday_indexed& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const weekday_indexed& x, const weekday_indexed& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const weekday_indexed& wdi);

// weekday_last

class weekday_last
{
    date::weekday wd_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 weekday_last() {}
#endif

    explicit CONSTCD11 weekday_last(const date::weekday& wd) _NOEXCEPT;

    CONSTCD11 date::weekday weekday() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday_last& x, const weekday_last& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const weekday_last& x, const weekday_last& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const weekday_last& wdl);

// year_month

class year_month
{
    date::year  y_;
    date::month m_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 year_month() {}
#endif

    CONSTCD11 year_month(const date::year& y, const date::month& m) _NOEXCEPT;

    CONSTCD11 date::year  year()  const _NOEXCEPT;
    CONSTCD11 date::month month() const _NOEXCEPT;

    year_month& operator+=(const months& dm) _NOEXCEPT;
    year_month& operator-=(const months& dm) _NOEXCEPT;
    year_month& operator+=(const years& dy) _NOEXCEPT;
    year_month& operator-=(const years& dy) _NOEXCEPT;

    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 bool operator< (const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 bool operator> (const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const year_month& x, const year_month& y) _NOEXCEPT;

CONSTCD14 year_month operator+(const year_month& ym, const months& dm) _NOEXCEPT;
CONSTCD14 year_month operator+(const months& dm, const year_month& ym) _NOEXCEPT;
CONSTCD14 year_month operator-(const year_month& ym, const months& dm) _NOEXCEPT;

CONSTCD11 months operator-(const year_month& x, const year_month& y) _NOEXCEPT;
CONSTCD11 year_month operator+(const year_month& ym, const years& dy) _NOEXCEPT;
CONSTCD11 year_month operator+(const years& dy, const year_month& ym) _NOEXCEPT;
CONSTCD11 year_month operator-(const year_month& ym, const years& dy) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year_month& ym);

// month_day

class month_day
{
    date::month m_;
    date::day   d_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 month_day() {}
#endif

    CONSTCD11 month_day(const date::month& m, const date::day& d) _NOEXCEPT;

    CONSTCD11 date::month month() const _NOEXCEPT;
    CONSTCD11 date::day   day() const _NOEXCEPT;

    CONSTCD14 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const month_day& x, const month_day& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const month_day& x, const month_day& y) _NOEXCEPT;
CONSTCD11 bool operator< (const month_day& x, const month_day& y) _NOEXCEPT;
CONSTCD11 bool operator> (const month_day& x, const month_day& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const month_day& x, const month_day& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const month_day& x, const month_day& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const month_day& md);

// month_day_last

class month_day_last
{
    date::month m_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 month_day_last() {}
#endif

    CONSTCD11 explicit month_day_last(const date::month& m) _NOEXCEPT;

    CONSTCD11 date::month month() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const month_day_last& x, const month_day_last& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const month_day_last& x, const month_day_last& y) _NOEXCEPT;
CONSTCD11 bool operator< (const month_day_last& x, const month_day_last& y) _NOEXCEPT;
CONSTCD11 bool operator> (const month_day_last& x, const month_day_last& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const month_day_last& x, const month_day_last& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const month_day_last& x, const month_day_last& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const month_day_last& mdl);

// month_weekday

class month_weekday
{
    date::month           m_;
    date::weekday_indexed wdi_;
public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 month_weekday() {}
#endif

	CONSTCD11 month_weekday(const date::month& m,
                              const date::weekday_indexed& wdi) _NOEXCEPT;

    CONSTCD11 date::month           month()           const _NOEXCEPT;
    CONSTCD11 date::weekday_indexed weekday_indexed() const _NOEXCEPT;

    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11 bool operator==(const month_weekday& x, const month_weekday& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const month_weekday& x, const month_weekday& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const month_weekday& mwd);

// month_weekday_last

class month_weekday_last
{
    date::month        m_;
    date::weekday_last wdl_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 month_weekday_last() {}
#endif

    CONSTCD11 month_weekday_last(const date::month& m,
                                 const date::weekday_last& wd) _NOEXCEPT;

    CONSTCD11 date::month        month()        const _NOEXCEPT;
    CONSTCD11 date::weekday_last weekday_last() const _NOEXCEPT;

    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11
    bool operator==(const month_weekday_last& x, const month_weekday_last& y) _NOEXCEPT;
CONSTCD11
    bool operator!=(const month_weekday_last& x, const month_weekday_last& y) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const month_weekday_last& mwdl);

// class year_month_day

class year_month_day
{
    date::year  y_;
    date::month m_;
    date::day   d_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 year_month_day() {}
#endif

    CONSTCD11 year_month_day(const date::year& y, const date::month& m,
                               const date::day& d) _NOEXCEPT;
    CONSTCD14 year_month_day(const year_month_day_last& ymdl) _NOEXCEPT;
    CONSTCD14 year_month_day(const day_point& dp) _NOEXCEPT;

    year_month_day& operator+=(const months& m) _NOEXCEPT;
    year_month_day& operator-=(const months& m) _NOEXCEPT;
    year_month_day& operator+=(const years& y)  _NOEXCEPT;
    year_month_day& operator-=(const years& y)  _NOEXCEPT;

    CONSTCD11 date::year  year()  const _NOEXCEPT;
    CONSTCD11 date::month month() const _NOEXCEPT;
    CONSTCD11 date::day   day()   const _NOEXCEPT;

    CONSTCD14 operator day_point() const _NOEXCEPT;
    CONSTCD14 bool ok() const _NOEXCEPT;

private:
    static CONSTCD14 year_month_day from_day_point(const day_point& dp) _NOEXCEPT;
};

CONSTCD11 bool operator==(const year_month_day& x, const year_month_day& y) _NOEXCEPT;
CONSTCD11 bool operator!=(const year_month_day& x, const year_month_day& y) _NOEXCEPT;
CONSTCD11 bool operator< (const year_month_day& x, const year_month_day& y) _NOEXCEPT;
CONSTCD11 bool operator> (const year_month_day& x, const year_month_day& y) _NOEXCEPT;
CONSTCD11 bool operator<=(const year_month_day& x, const year_month_day& y) _NOEXCEPT;
CONSTCD11 bool operator>=(const year_month_day& x, const year_month_day& y) _NOEXCEPT;

CONSTCD14 year_month_day operator+(const year_month_day& ymd, const months& dm) _NOEXCEPT;
CONSTCD14 year_month_day operator+(const months& dm, const year_month_day& ymd) _NOEXCEPT;
CONSTCD14 year_month_day operator-(const year_month_day& ymd, const months& dm) _NOEXCEPT;
CONSTCD11 year_month_day operator+(const year_month_day& ymd, const years& dy)  _NOEXCEPT;
CONSTCD11 year_month_day operator+(const years& dy, const year_month_day& ymd)  _NOEXCEPT;
CONSTCD11 year_month_day operator-(const year_month_day& ymd, const years& dy)  _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year_month_day& ymd);

// year_month_day_last

class year_month_day_last
{
    date::year           y_;
    date::month_day_last mdl_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 year_month_day_last() {}
#endif

	CONSTCD11 year_month_day_last(const date::year& y,
                                  const date::month_day_last& mdl) _NOEXCEPT;

    year_month_day_last& operator+=(const months& m) _NOEXCEPT;
    year_month_day_last& operator-=(const months& m) _NOEXCEPT;
    year_month_day_last& operator+=(const years& y)  _NOEXCEPT;
    year_month_day_last& operator-=(const years& y)  _NOEXCEPT;

    CONSTCD11 date::year           year()           const _NOEXCEPT;
    CONSTCD11 date::month          month()          const _NOEXCEPT;
    CONSTCD11 date::month_day_last month_day_last() const _NOEXCEPT;
    CONSTCD14 date::day            day()            const _NOEXCEPT;

    CONSTCD14 operator day_point() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11
    bool operator==(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;
CONSTCD11
    bool operator!=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;
CONSTCD11
    bool operator< (const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;
CONSTCD11
    bool operator> (const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;
CONSTCD11
    bool operator<=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;
CONSTCD11
    bool operator>=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT;

CONSTCD14
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) _NOEXCEPT;

CONSTCD14
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) _NOEXCEPT;

CONSTCD11
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) _NOEXCEPT;

CONSTCD11
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) _NOEXCEPT;

CONSTCD14
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) _NOEXCEPT;

CONSTCD11
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year_month_day_last& ymdl);

// year_month_weekday

class year_month_weekday
{
    date::year            y_;
    date::month           m_;
    date::weekday_indexed wdi_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 year_month_weekday() {}
#endif

    CONSTCD11 year_month_weekday(const date::year& y, const date::month& m,
                                   const date::weekday_indexed& wdi) _NOEXCEPT;
    CONSTCD14 year_month_weekday(const day_point& dp) _NOEXCEPT;

    year_month_weekday& operator+=(const months& m) _NOEXCEPT;
    year_month_weekday& operator-=(const months& m) _NOEXCEPT;
    year_month_weekday& operator+=(const years& y)  _NOEXCEPT;
    year_month_weekday& operator-=(const years& y)  _NOEXCEPT;

    CONSTCD11 date::year year() const _NOEXCEPT;
    CONSTCD11 date::month month() const _NOEXCEPT;
    CONSTCD11 date::weekday weekday() const _NOEXCEPT;
    CONSTCD11 unsigned index() const _NOEXCEPT;
    CONSTCD11 date::weekday_indexed weekday_indexed() const _NOEXCEPT;

    CONSTCD14 operator day_point() const _NOEXCEPT;
    CONSTCD14 bool ok() const _NOEXCEPT;

private:
    static CONSTCD14 year_month_weekday from_day_point(const day_point& dp) _NOEXCEPT;
};

CONSTCD11
    bool operator==(const year_month_weekday& x, const year_month_weekday& y) _NOEXCEPT;
CONSTCD11
    bool operator!=(const year_month_weekday& x, const year_month_weekday& y) _NOEXCEPT;

CONSTCD14
year_month_weekday
operator+(const year_month_weekday& ymwd, const months& dm) _NOEXCEPT;

CONSTCD14
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) _NOEXCEPT;

CONSTCD14
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) _NOEXCEPT;

CONSTCD11
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year_month_weekday& ymwdi);

// year_month_weekday_last

class year_month_weekday_last
{
    date::year y_;
    date::month m_;
    date::weekday_last wdl_;

public:

#if defined(_MSC_VER) && (_MSC_VER < 1900)
	CONSTCD11 year_month_weekday_last() {}
#endif

	CONSTCD11 year_month_weekday_last(const date::year& y, const date::month& m,
                                      const date::weekday_last& wdl) _NOEXCEPT;

    year_month_weekday_last& operator+=(const months& m) _NOEXCEPT;
    year_month_weekday_last& operator-=(const months& m) _NOEXCEPT;
    year_month_weekday_last& operator+=(const years& y) _NOEXCEPT;
    year_month_weekday_last& operator-=(const years& y) _NOEXCEPT;

    CONSTCD11 date::year year() const _NOEXCEPT;
    CONSTCD11 date::month month() const _NOEXCEPT;
    CONSTCD11 date::weekday weekday() const _NOEXCEPT;
    CONSTCD11 date::weekday_last weekday_last() const _NOEXCEPT;

    CONSTCD14 operator day_point() const _NOEXCEPT;
    CONSTCD11 bool ok() const _NOEXCEPT;
};

CONSTCD11
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) _NOEXCEPT;

CONSTCD11
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) _NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const months& dm) _NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) _NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) _NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) _NOEXCEPT;

std::ostream& operator<<(std::ostream& os, const year_month_weekday_last& ymwdl);

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
inline namespace literals
{
#endif

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
CONSTCD11 date::day  operator "" _d(unsigned long long d) _NOEXCEPT;
CONSTCD11 date::year operator "" _y(unsigned long long y) _NOEXCEPT;
#endif

// CONSTDATA date::month jan{1};
// CONSTDATA date::month feb{2};
// CONSTDATA date::month mar{3};
// CONSTDATA date::month apr{4};
// CONSTDATA date::month may{5};
// CONSTDATA date::month jun{6};
// CONSTDATA date::month jul{7};
// CONSTDATA date::month aug{8};
// CONSTDATA date::month sep{9};
// CONSTDATA date::month oct{10};
// CONSTDATA date::month nov{11};
// CONSTDATA date::month dec{12};
// 
// CONSTDATA date::weekday sun{0u};
// CONSTDATA date::weekday mon{1u};
// CONSTDATA date::weekday tue{2u};
// CONSTDATA date::weekday wed{3u};
// CONSTDATA date::weekday thu{4u};
// CONSTDATA date::weekday fri{5u};
// CONSTDATA date::weekday sat{6u};

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
}  // inline namespace literals
#endif

//----------------+
// Implementation |
//----------------+

// utilities
namespace detail {
	class save_stream
	{
		std::ostream& os_;
		char fill_;
		std::ios::fmtflags flags_;

	public:
		~save_stream()
		{
			os_.fill(fill_);
			os_.flags(flags_);
		}

		save_stream(const save_stream&) = delete;
		save_stream& operator=(const save_stream&) = delete;

		explicit save_stream(std::ostream& os)
			: os_(os)
			, fill_(os.fill())
			, flags_(os.flags())
		{}
	};
}

// truncate towards zero
template <class To, class Rep, class Period>
CONSTCD11
inline
To
truncate(const std::chrono::duration<Rep, Period>& d)
{
    return std::chrono::duration_cast<To>(d);
}

// round down
template <class To, class Rep, class Period>
CONSTCD14
inline
To
floor(const std::chrono::duration<Rep, Period>& d)
{
    To t = std::chrono::duration_cast<To>(d);
    if (t > d)
        t = t - To{1};
    return t;
}

// round to nearest, to even on tie
template <class To, class Rep, class Period>
CONSTCD14
inline
To
round(const std::chrono::duration<Rep, Period>& d)
{
    To t0 = floor<To>(d);
    To t1 = t0 + To{1};
    auto diff0 = d - t0;
    auto diff1 = t1 - d;
    if (diff0 == diff1)
    {
        if (t0.count() & 1)
            return t1;
        return t0;
    }
    else if (diff0 < diff1)
        return t0;
    return t1;
}

// round up
template <class To, class Rep, class Period>
CONSTCD14
inline
To
ceil(const std::chrono::duration<Rep, Period>& d)
{
    To t = std::chrono::duration_cast<To>(d);
    if (t < d)
        t = t + To{1};
    return t;
}

// truncate towards zero
template <class To, class Clock, class FromDuration>
CONSTCD11
inline
std::chrono::time_point<Clock, To>
truncate(const std::chrono::time_point<Clock, FromDuration>& tp)
{
    return std::chrono::time_point_cast<To>(tp);
}

// round down
template <class To, class Clock, class FromDuration>
CONSTCD11
inline
std::chrono::time_point<Clock, To>
floor(const std::chrono::time_point<Clock, FromDuration>& tp)
{
    using std::chrono::time_point;
    return time_point<Clock, To>{floor<To>(tp.time_since_epoch())};
}

// round to nearest, to even on tie
template <class To, class Clock, class FromDuration>
CONSTCD11
inline
std::chrono::time_point<Clock, To>
round(const std::chrono::time_point<Clock, FromDuration>& tp)
{
    using std::chrono::time_point;
    return time_point<Clock, To>{round<To>(tp.time_since_epoch())};
}

// round up
template <class To, class Clock, class FromDuration>
CONSTCD11
inline
std::chrono::time_point<Clock, To>
ceil(const std::chrono::time_point<Clock, FromDuration>& tp)
{
    using std::chrono::time_point;
    return time_point<Clock, To>{ceil<To>(tp.time_since_epoch())};
}

// day

CONSTCD11 inline day::day(unsigned d) _NOEXCEPT : d_(static_cast<unsigned char>(d)) {}
inline day& day::operator++() _NOEXCEPT {++d_; return *this;}
inline day day::operator++(int) _NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
inline day& day::operator--() _NOEXCEPT {--d_; return *this;}
inline day day::operator--(int) _NOEXCEPT {auto tmp(*this); --(*this); return tmp;}
inline day& day::operator+=(const days& d) _NOEXCEPT {*this = *this + d; return *this;}
inline day& day::operator-=(const days& d) _NOEXCEPT {*this = *this - d; return *this;}
CONSTCD11 inline day::operator unsigned() const _NOEXCEPT {return d_;}
CONSTCD11 inline bool day::ok() const _NOEXCEPT {return 1 <= d_ && d_ <= 31;}

CONSTCD11
inline
bool
operator==(const day& x, const day& y) _NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const day& x, const day& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const day& x, const day& y) _NOEXCEPT
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const day& x, const day& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const day& x, const day& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const day& x, const day& y) _NOEXCEPT
{
    return !(x < y);
}

CONSTCD11
inline
days
operator-(const day& x, const day& y) _NOEXCEPT
{
    return days{static_cast<days::rep>(static_cast<unsigned>(x)
                                     - static_cast<unsigned>(y))};
}

CONSTCD11
inline
day
operator+(const day& x, const days& y) _NOEXCEPT
{
    return day{static_cast<unsigned>(x) + static_cast<unsigned>(y.count())};
}

CONSTCD11
inline
day
operator+(const days& x, const day& y) _NOEXCEPT
{
    return y + x;
}

CONSTCD11
inline
day
operator-(const day& x, const days& y) _NOEXCEPT
{
    return x + -y;
}

inline
std::ostream&
operator<<(std::ostream& os, const day& d)
{
    detail::save_stream _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::right);
    os.width(2);
    os << static_cast<unsigned>(d);
    return os;
}

// month

CONSTCD11 inline month::month(unsigned m) _NOEXCEPT : m_(static_cast<decltype(m_)>(m)) {}
inline month& month::operator++() _NOEXCEPT {if (++m_ == 13) m_ = 1; return *this;}
inline month month::operator++(int) _NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
inline month& month::operator--() _NOEXCEPT {if (--m_ == 0) m_ = 12; return *this;}
inline month month::operator--(int) _NOEXCEPT {auto tmp(*this); --(*this); return tmp;}

inline
month&
month::operator+=(const months& m) _NOEXCEPT
{
    *this = *this + m;
    return *this;
}

inline
month&
month::operator-=(const months& m) _NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD11 inline month::operator unsigned() const _NOEXCEPT {return m_;}
CONSTCD11 inline bool month::ok() const _NOEXCEPT {return 1 <= m_ && m_ <= 12;}

CONSTCD11
inline
bool
operator==(const month& x, const month& y) _NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const month& x, const month& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month& x, const month& y) _NOEXCEPT
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const month& x, const month& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month& x, const month& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month& x, const month& y) _NOEXCEPT
{
    return !(x < y);
}

CONSTCD14
inline
months
operator-(const month& x, const month& y) _NOEXCEPT
{
    auto const d = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return months(d <= 11 ? d : d + 12);
}

CONSTCD14
inline
month
operator+(const month& x, const months& y) _NOEXCEPT
{
    auto const mu = static_cast<long long>(static_cast<unsigned>(x)) - 1 + y.count();
    auto const yr = (mu >= 0 ? mu : mu-11) / 12;
    return month{static_cast<unsigned>(mu - yr * 12 + 1)};
}

CONSTCD14
inline
month
operator+(const months& x, const month& y) _NOEXCEPT
{
    return y + x;
}

CONSTCD14
inline
month
operator-(const month& x, const months& y) _NOEXCEPT
{
    return x + -y;
}

inline
std::ostream&
operator<<(std::ostream& os, const month& m)
{
    switch (static_cast<unsigned>(m))
    {
    case 1:
        os << "Jan";
        break;
    case 2:
        os << "Feb";
        break;
    case 3:
        os << "Mar";
        break;
    case 4:
        os << "Apr";
        break;
    case 5:
        os << "May";
        break;
    case 6:
        os << "Jun";
        break;
    case 7:
        os << "Jul";
        break;
    case 8:
        os << "Aug";
        break;
    case 9:
        os << "Sep";
        break;
    case 10:
        os << "Oct";
        break;
    case 11:
        os << "Nov";
        break;
    case 12:
        os << "Dec";
        break;
    default:
        os << static_cast<unsigned>(m) << " is not a valid month";
        break;
    }
    return os;
}

// year

CONSTCD11 inline year::year(int y) _NOEXCEPT : y_(static_cast<decltype(y_)>(y)) {}
inline year& year::operator++() _NOEXCEPT {++y_; return *this;}
inline year year::operator++(int) _NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
inline year& year::operator--() _NOEXCEPT {--y_; return *this;}
inline year year::operator--(int) _NOEXCEPT {auto tmp(*this); --(*this); return tmp;}
inline year& year::operator+=(const years& y) _NOEXCEPT {*this = *this + y; return *this;}
inline year& year::operator-=(const years& y) _NOEXCEPT {*this = *this - y; return *this;}

CONSTCD11
inline
bool
year::is_leap() const _NOEXCEPT
{
    return y_ % 4 == 0 && (y_ % 100 != 0 || y_ % 400 == 0);
}

CONSTCD11 inline year::operator int() const _NOEXCEPT {return y_;}
CONSTCD11 inline bool year::ok() const _NOEXCEPT {return min() <= *this && *this <= max();}

CONSTCD11
inline
year
year::min() _NOEXCEPT
{
    using namespace std::chrono;
    static_assert(sizeof(seconds)*CHAR_BIT >= 41, "seconds may overflow");
    static_assert(sizeof(hours)*CHAR_BIT >= 30, "hours may overflow");
    return sizeof(minutes)*CHAR_BIT < 34 ?
        year{1970} + duration_cast<years>(minutes::min()) :
        year{std::numeric_limits<short>::min()};
}

CONSTCD11
inline
year
year::max() _NOEXCEPT
{
    using namespace std::chrono;
    static_assert(sizeof(seconds)*CHAR_BIT >= 41, "seconds may overflow");
    static_assert(sizeof(hours)*CHAR_BIT >= 30, "hours may overflow");
    return sizeof(minutes)*CHAR_BIT < 34 ?
        year{1969} + duration_cast<years>(minutes::max()) :
        year{std::numeric_limits<short>::max()};
}

CONSTCD11
inline
bool
operator==(const year& x, const year& y) _NOEXCEPT
{
    return static_cast<int>(x) == static_cast<int>(y);
}

CONSTCD11
inline
bool
operator!=(const year& x, const year& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year& x, const year& y) _NOEXCEPT
{
    return static_cast<int>(x) < static_cast<int>(y);
}

CONSTCD11
inline
bool
operator>(const year& x, const year& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year& x, const year& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year& x, const year& y) _NOEXCEPT
{
    return !(x < y);
}

CONSTCD11
inline
years
operator-(const year& x, const year& y) _NOEXCEPT
{
    return years{static_cast<int>(x) - static_cast<int>(y)};
}

CONSTCD11
inline
year
operator+(const year& x, const years& y) _NOEXCEPT
{
    return year{static_cast<int>(x) + y.count()};
}

CONSTCD11
inline
year
operator+(const years& x, const year& y) _NOEXCEPT
{
    return y + x;
}

CONSTCD11
inline
year
operator-(const year& x, const years& y) _NOEXCEPT
{
    return year{static_cast<int>(x) - y.count()};
}

inline
std::ostream&
operator<<(std::ostream& os, const year& y)
{
    detail::save_stream _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::internal);
    os.width(4 + (y < year{0}));
    os << static_cast<int>(y);
    return os;
}

// weekday

CONSTCD11
inline
unsigned char
weekday::weekday_from_days(int z) _NOEXCEPT
{
    return static_cast<unsigned char>(static_cast<unsigned>(
        z >= -4 ? (z+4) % 7 : (z+5) % 7 + 6));
}

CONSTCD11
inline
weekday::weekday(unsigned wd) _NOEXCEPT
    : wd_(static_cast<decltype(wd_)>(wd))
    {}

CONSTCD11
inline
weekday::weekday(const day_point& dp) _NOEXCEPT
    : wd_(weekday_from_days(dp.time_since_epoch().count()))
    {}

inline weekday& weekday::operator++() _NOEXCEPT {if (++wd_ == 7) wd_ = 0; return *this;}
inline weekday weekday::operator++(int) _NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
inline weekday& weekday::operator--() _NOEXCEPT {if (wd_-- == 0) wd_ = 6; return *this;}
inline weekday weekday::operator--(int) _NOEXCEPT {auto tmp(*this); --(*this); return tmp;}

inline
weekday&
weekday::operator+=(const days& d) _NOEXCEPT
{
    *this = *this + d;
    return *this;
}

inline
weekday&
weekday::operator-=(const days& d) _NOEXCEPT
{
    *this = *this - d;
    return *this;
}

CONSTCD11
inline
weekday::operator unsigned() const _NOEXCEPT
{
    return static_cast<unsigned>(wd_);
}

CONSTCD11 inline bool weekday::ok() const _NOEXCEPT {return wd_ <= 6;}

CONSTCD11
inline
bool
operator==(const weekday& x, const weekday& y) _NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const weekday& x, const weekday& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD14
inline
days
operator-(const weekday& x, const weekday& y) _NOEXCEPT
{
    auto const diff = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return days{diff <= 6 ? diff : diff + 7};
}

CONSTCD14
inline
weekday
operator+(const weekday& x, const days& y) _NOEXCEPT
{
    auto const wdu = static_cast<long long>(static_cast<unsigned>(x)) + y.count();
    auto const wk = (wdu >= 0 ? wdu : wdu-6) / 7;
    return weekday{static_cast<unsigned>(wdu - wk * 7)};
}

CONSTCD14
inline
weekday
operator+(const days& x, const weekday& y) _NOEXCEPT
{
    return y + x;
}

CONSTCD14
inline
weekday
operator-(const weekday& x, const days& y) _NOEXCEPT
{
    return x + -y;
}

inline
std::ostream&
operator<<(std::ostream& os, const weekday& wd)
{
    switch (static_cast<unsigned>(wd))
    {
    case 0:
        os << "Sun";
        break;
    case 1:
        os << "Mon";
        break;
    case 2:
        os << "Tue";
        break;
    case 3:
        os << "Wed";
        break;
    case 4:
        os << "Thu";
        break;
    case 5:
        os << "Fri";
        break;
    case 6:
        os << "Sat";
        break;
    default:
        os << static_cast<unsigned>(wd) << " is not a valid weekday";
        break;
    }
    return os;
}

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
inline namespace literals
{
#endif

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
CONSTCD11
inline
date::day
operator "" _d(unsigned long long d) _NOEXCEPT
{
    return date::day{static_cast<unsigned>(d)};
}

CONSTCD11
inline
date::year
operator "" _y(unsigned long long y) _NOEXCEPT
{
    return date::year(static_cast<int>(y));
}
#endif

CONSTDATA date::last_spec last{};

CONSTDATA date::month jan{1};
CONSTDATA date::month feb{2};
CONSTDATA date::month mar{3};
CONSTDATA date::month apr{4};
CONSTDATA date::month may{5};
CONSTDATA date::month jun{6};
CONSTDATA date::month jul{7};
CONSTDATA date::month aug{8};
CONSTDATA date::month sep{9};
CONSTDATA date::month oct{10};
CONSTDATA date::month nov{11};
CONSTDATA date::month dec{12};

CONSTDATA date::weekday sun{0u};
CONSTDATA date::weekday mon{1u};
CONSTDATA date::weekday tue{2u};
CONSTDATA date::weekday wed{3u};
CONSTDATA date::weekday thu{4u};
CONSTDATA date::weekday fri{5u};
CONSTDATA date::weekday sat{6u};

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
}  // inline namespace literals
#endif

// weekday_indexed

CONSTCD11
inline
weekday
weekday_indexed::weekday() const _NOEXCEPT
{
    return date::weekday{static_cast<unsigned>(wd_)};
}

CONSTCD11 inline unsigned weekday_indexed::index() const _NOEXCEPT {return index_;}

CONSTCD11
inline
bool
weekday_indexed::ok() const _NOEXCEPT
{
    return weekday().ok() && 1 <= index_ && index_ <= 5;
}

CONSTCD11
inline
weekday_indexed::weekday_indexed(const date::weekday& wd, unsigned index) _NOEXCEPT
    : wd_(static_cast<decltype(wd_)>(static_cast<unsigned>(wd)))
    , index_(static_cast<decltype(index_)>(index))
    {}

inline
std::ostream&
operator<<(std::ostream& os, const weekday_indexed& wdi)
{
    return os << wdi.weekday() << '[' << wdi.index() << ']';
}

CONSTCD11
inline
weekday_indexed
weekday::operator[](unsigned index) const _NOEXCEPT
{
    return {*this, index};
}

CONSTCD11
inline
bool
operator==(const weekday_indexed& x, const weekday_indexed& y) _NOEXCEPT
{
    return x.weekday() == y.weekday() && x.index() == y.index();
}

CONSTCD11
inline
bool
operator!=(const weekday_indexed& x, const weekday_indexed& y) _NOEXCEPT
{
    return !(x == y);
}

// weekday_last

CONSTCD11 inline date::weekday weekday_last::weekday() const _NOEXCEPT {return wd_;}
CONSTCD11 inline bool weekday_last::ok() const _NOEXCEPT {return wd_.ok();}
CONSTCD11 inline weekday_last::weekday_last(const date::weekday& wd) _NOEXCEPT : wd_(wd) {}

CONSTCD11
inline
bool
operator==(const weekday_last& x, const weekday_last& y) _NOEXCEPT
{
    return x.weekday() == y.weekday();
}

CONSTCD11
inline
bool
operator!=(const weekday_last& x, const weekday_last& y) _NOEXCEPT
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const weekday_last& wdl)
{
    return os << wdl.weekday() << "[last]";
}

CONSTCD11
inline
weekday_last
weekday::operator[](last_spec) const _NOEXCEPT
{
    return weekday_last{*this};
}

// year_month

CONSTCD11
inline
year_month::year_month(const date::year& y, const date::month& m) _NOEXCEPT
    : y_(y)
    , m_(m)
    {}

CONSTCD11 inline year year_month::year() const _NOEXCEPT {return y_;}
CONSTCD11 inline month year_month::month() const _NOEXCEPT {return m_;}
CONSTCD11 inline bool year_month::ok() const _NOEXCEPT {return y_.ok() && m_.ok();}

inline
year_month&
year_month::operator+=(const months& dm) _NOEXCEPT
{
    *this = *this + dm;
    return *this;
}

inline
year_month&
year_month::operator-=(const months& dm) _NOEXCEPT
{
    *this = *this - dm;
    return *this;
}

inline
year_month&
year_month::operator+=(const years& dy) _NOEXCEPT
{
    *this = *this + dy;
    return *this;
}

inline
year_month&
year_month::operator-=(const years& dy) _NOEXCEPT
{
    *this = *this - dy;
    return *this;
}

CONSTCD11
inline
bool
operator==(const year_month& x, const year_month& y) _NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const year_month& x, const year_month& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month& x, const year_month& y) _NOEXCEPT
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month() < y.month()));
}

CONSTCD11
inline
bool
operator>(const year_month& x, const year_month& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month& x, const year_month& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month& x, const year_month& y) _NOEXCEPT
{
    return !(x < y);
}

CONSTCD14
inline
year_month
operator+(const year_month& ym, const months& dm) _NOEXCEPT
{
    auto dmi = static_cast<int>(static_cast<unsigned>(ym.month())) - 1 + dm.count();
    auto dy = (dmi >= 0 ? dmi : dmi-11) / 12;
    dmi = dmi - dy * 12 + 1;
    return (ym.year() + years(dy)) / month(static_cast<unsigned>(dmi));
}

CONSTCD14
inline
year_month
operator+(const months& dm, const year_month& ym) _NOEXCEPT
{
    return ym + dm;
}

CONSTCD14
inline
year_month
operator-(const year_month& ym, const months& dm) _NOEXCEPT
{
    return ym + -dm;
}

CONSTCD11
inline
months
operator-(const year_month& x, const year_month& y) _NOEXCEPT
{
    return (x.year() - y.year()) +
            months(static_cast<unsigned>(x.month()) - static_cast<unsigned>(y.month()));
}

CONSTCD11
inline
year_month
operator+(const year_month& ym, const years& dy) _NOEXCEPT
{
    return (ym.year() + dy) / ym.month();
}

CONSTCD11
inline
year_month
operator+(const years& dy, const year_month& ym) _NOEXCEPT
{
    return ym + dy;
}

CONSTCD11
inline
year_month
operator-(const year_month& ym, const years& dy) _NOEXCEPT
{
    return ym + -dy;
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month& ym)
{
    return os << ym.year() << '/' << ym.month();
}

// month_day

CONSTCD11
inline
month_day::month_day(const date::month& m, const date::day& d) _NOEXCEPT
    : m_(m)
    , d_(d)
    {}

CONSTCD11 inline date::month month_day::month() const _NOEXCEPT {return m_;}
CONSTCD11 inline date::day month_day::day() const _NOEXCEPT {return d_;}

CONSTCD14
inline
bool
month_day::ok() const _NOEXCEPT
{
	static const date::day d_1 = date::day(1);
    static const date::day d[] =
    {
		date::day(31), date::day(29), date::day(31), date::day(30), date::day(31), date::day(30), 
		date::day(31), date::day(31), date::day(30), date::day(31), date::day(30), date::day(31) 
	};
    return m_.ok() && d_1 <= d_ && d_ <= d[static_cast<unsigned>(m_)-1];
}

CONSTCD11
inline
bool
operator==(const month_day& x, const month_day& y) _NOEXCEPT
{
    return x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const month_day& x, const month_day& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day& x, const month_day& y) _NOEXCEPT
{
    return x.month() < y.month() ? true
        : (x.month() > y.month() ? false
        : (x.day() < y.day()));
}

CONSTCD11
inline
bool
operator>(const month_day& x, const month_day& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day& x, const month_day& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day& x, const month_day& y) _NOEXCEPT
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const month_day& md)
{
    return os << md.month() << '/' << md.day();
}

// month_day_last

CONSTCD11 inline month month_day_last::month() const _NOEXCEPT {return m_;}
CONSTCD11 inline bool month_day_last::ok() const _NOEXCEPT {return m_.ok();}
CONSTCD11 inline month_day_last::month_day_last(const date::month& m) _NOEXCEPT : m_(m) {}

CONSTCD11
inline
bool
operator==(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return x.month() < y.month();
}

CONSTCD11
inline
bool
operator>(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day_last& x, const month_day_last& y) _NOEXCEPT
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const month_day_last& mdl)
{
    return os << mdl.month() << "/last";
}

// month_weekday

CONSTCD11
inline
month_weekday::month_weekday(const date::month& m,
                             const date::weekday_indexed& wdi) _NOEXCEPT
    : m_(m)
    , wdi_(wdi)
    {}

CONSTCD11 inline month month_weekday::month() const _NOEXCEPT {return m_;}

CONSTCD11
inline
weekday_indexed
month_weekday::weekday_indexed() const _NOEXCEPT
{
    return wdi_;
}

CONSTCD11
inline
bool
month_weekday::ok() const _NOEXCEPT
{
    return m_.ok() && wdi_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday& x, const month_weekday& y) _NOEXCEPT
{
    return x.month() == y.month() && x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const month_weekday& x, const month_weekday& y) _NOEXCEPT
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const month_weekday& mwd)
{
    return os << mwd.month() << '/' << mwd.weekday_indexed();
}

// month_weekday_last

CONSTCD11
inline
month_weekday_last::month_weekday_last(const date::month& m,
                                       const date::weekday_last& wdl) _NOEXCEPT
    : m_(m)
    , wdl_(wdl)
    {}

CONSTCD11 inline month month_weekday_last::month() const _NOEXCEPT {return m_;}

CONSTCD11
inline
weekday_last
month_weekday_last::weekday_last() const _NOEXCEPT
{
    return wdl_;
}

CONSTCD11
inline
bool
month_weekday_last::ok() const _NOEXCEPT
{
    return m_.ok() && wdl_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday_last& x, const month_weekday_last& y) _NOEXCEPT
{
    return x.month() == y.month() && x.weekday_last() == y.weekday_last();
}

CONSTCD11
inline
bool
operator!=(const month_weekday_last& x, const month_weekday_last& y) _NOEXCEPT
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const month_weekday_last& mwdl)
{
    return os << mwdl.month() << '/' << mwdl.weekday_last();
}

// year_month_day_last

CONSTCD11
inline
year_month_day_last::year_month_day_last(const date::year& y,
                                         const date::month_day_last& mdl) _NOEXCEPT
    : y_(y)
    , mdl_(mdl)
    {}

inline
year_month_day_last&
year_month_day_last::operator+=(const months& m) _NOEXCEPT
{
    *this = *this + m;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator-=(const months& m) _NOEXCEPT
{
    *this = *this - m;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator+=(const years& y) _NOEXCEPT
{
    *this = *this + y;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator-=(const years& y) _NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_day_last::year() const _NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_day_last::month() const _NOEXCEPT {return mdl_.month();}

CONSTCD11
inline
month_day_last
year_month_day_last::month_day_last() const _NOEXCEPT
{
    return mdl_;
}

CONSTCD14
inline
day
year_month_day_last::day() const _NOEXCEPT
{
	static const date::day d_29 = date::day(29);
    static const date::day d[] =
    {
		date::day(31), date::day(28), date::day(31), date::day(30), date::day(31), date::day(30),
		date::day(31), date::day(31), date::day(30), date::day(31), date::day(30), date::day(31)
	};
    return month() != feb || !y_.is_leap() ? d[static_cast<unsigned>(month())-1] : d_29;
}

CONSTCD11
inline
bool
year_month_day_last::ok() const _NOEXCEPT
{
    return y_.ok() && mdl_.ok();
}

CONSTCD11
inline
bool
operator==(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return x.year() == y.year() && x.month_day_last() == y.month_day_last();
}

CONSTCD11
inline
bool
operator!=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month_day_last() < y.month_day_last()));
}

CONSTCD11
inline
bool
operator>(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day_last& x, const year_month_day_last& y) _NOEXCEPT
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_day_last& ymdl)
{
    return os << ymdl.year() << '/' << ymdl.month_day_last();
}

CONSTCD14
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) _NOEXCEPT
{
    return (ymdl.year() / ymdl.month() + dm) / last;
}

CONSTCD14
inline
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) _NOEXCEPT
{
    return ymdl + dm;
}

CONSTCD14
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) _NOEXCEPT
{
    return ymdl + (-dm);
}

CONSTCD11
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) _NOEXCEPT
{
    return {ymdl.year()+dy, ymdl.month_day_last()};
}

CONSTCD11
inline
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) _NOEXCEPT
{
    return ymdl + dy;
}

CONSTCD11
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) _NOEXCEPT
{
    return ymdl + (-dy);
}

// year_month_day

CONSTCD11
inline
year_month_day::year_month_day(const date::year& y, const date::month& m,
                               const date::day& d) _NOEXCEPT
    : y_(y)
    , m_(m)
    , d_(d)
    {}

CONSTCD14
inline
year_month_day::year_month_day(const year_month_day_last& ymdl) _NOEXCEPT
    : y_(ymdl.year())
    , m_(ymdl.month())
    , d_(ymdl.day())
    {}

CONSTCD14
inline
year_month_day::year_month_day(const day_point& dp) _NOEXCEPT
    : year_month_day(from_day_point(dp))
    {}

CONSTCD11 inline year year_month_day::year() const _NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_day::month() const _NOEXCEPT {return m_;}
CONSTCD11 inline day year_month_day::day() const _NOEXCEPT {return d_;}

inline
year_month_day&
year_month_day::operator+=(const months& m) _NOEXCEPT
{
    *this = *this + m;
    return *this;
}

inline
year_month_day&
year_month_day::operator-=(const months& m) _NOEXCEPT
{
    *this = *this - m;
    return *this;
}

inline
year_month_day&
year_month_day::operator+=(const years& y) _NOEXCEPT
{
    *this = *this + y;
    return *this;
}

inline
year_month_day&
year_month_day::operator-=(const years& y) _NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD14
inline
year_month_day::operator day_point() const _NOEXCEPT
{
    static_assert(std::numeric_limits<unsigned>::digits >= 18,
             "This algorithm has not been ported to a 16 bit unsigned integer");
    static_assert(std::numeric_limits<int>::digits >= 20,
             "This algorithm has not been ported to a 16 bit signed integer");
    auto const y = static_cast<int>(y_) - (m_ <= feb);
    auto const m = static_cast<unsigned>(m_);
    auto const d = static_cast<unsigned>(d_);
    auto const era = (y >= 0 ? y : y-399) / 400;
    auto const yoe = static_cast<unsigned>(y - era * 400);       // [0, 399]
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4146) // unary minus operator applied to unsigned type, result still unsigned
#endif
    auto const doy = (153*(m + (m > 2 ? -3u : 9)) + 2)/5 + d-1;  // [0, 365]
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    auto const doe = yoe * 365 + yoe/4 - yoe/100 + doy;          // [0, 146096]
    return day_point{days{era * 146097 + static_cast<int>(doe) - 719468}};
}

CONSTCD14
inline
year_month_day_last::operator day_point() const _NOEXCEPT
{
    return day_point(year()/month()/day());
}

CONSTCD14
inline
bool
year_month_day::ok() const _NOEXCEPT
{
	static const date::day d_1 = date::day(1);
    if (!(y_.ok() && m_.ok()))
        return false;
    return d_1 <= d_ && d_ <= (y_/m_/last).day();
}

CONSTCD11
inline
bool
operator==(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month() < y.month() ? true
        : (x.month() > y.month() ? false
        : (x.day() < y.day()))));
}

CONSTCD11
inline
bool
operator>(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day& x, const year_month_day& y) _NOEXCEPT
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_day& ymd)
{
    detail::save_stream _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::right);
    os << ymd.year() << '-';
    os.width(2);
    os << static_cast<unsigned>(ymd.month()) << '-';
    os << ymd.day();
    return os;
}

CONSTCD14
inline
year_month_day
year_month_day::from_day_point(const day_point& dp) _NOEXCEPT
{
    static_assert(std::numeric_limits<unsigned>::digits >= 18,
             "This algorithm has not been ported to a 16 bit unsigned integer");
    static_assert(std::numeric_limits<int>::digits >= 20,
             "This algorithm has not been ported to a 16 bit signed integer");
    auto const z = dp.time_since_epoch().count() + 719468;
    auto const era = (z >= 0 ? z : z - 146096) / 146097;
    auto const doe = static_cast<unsigned>(z - era * 146097);          // [0, 146096]
    auto const yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;  // [0, 399]
    auto const y = static_cast<day_point::rep>(yoe) + era * 400;
    auto const doy = doe - (365*yoe + yoe/4 - yoe/100);                // [0, 365]
    auto const mp = (5*doy + 2)/153;                                   // [0, 11]
    auto const d = doy - (153*mp+2)/5 + 1;                             // [1, 31]
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4146) // unary minus operator applied to unsigned type, result still unsigned
#endif
    auto const m = mp + (mp < 10 ? 3 : -9u);                           // [1, 12]
#ifdef _MSVC_VER
#pragma warning(pop)
#endif
    return year_month_day{date::year{y + (m <= 2)}, date::month(m), date::day(d)};
}

CONSTCD14
inline
year_month_day
operator+(const year_month_day& ymd, const months& dm) _NOEXCEPT
{
    return (ymd.year() / ymd.month() + dm) / ymd.day();
}

CONSTCD14
inline
year_month_day
operator+(const months& dm, const year_month_day& ymd) _NOEXCEPT
{
    return ymd + dm;
}

CONSTCD14
inline
year_month_day
operator-(const year_month_day& ymd, const months& dm) _NOEXCEPT
{
    return ymd + (-dm);
}

CONSTCD11
inline
year_month_day
operator+(const year_month_day& ymd, const years& dy) _NOEXCEPT
{
    return (ymd.year() + dy) / ymd.month() / ymd.day();
}

CONSTCD11
inline
year_month_day
operator+(const years& dy, const year_month_day& ymd) _NOEXCEPT
{
    return ymd + dy;
}

CONSTCD11
inline
year_month_day
operator-(const year_month_day& ymd, const years& dy) _NOEXCEPT
{
    return ymd + (-dy);
}

// year_month_weekday

CONSTCD11
inline
year_month_weekday::year_month_weekday(const date::year& y, const date::month& m,
                                       const date::weekday_indexed& wdi)
        _NOEXCEPT
    : y_(y)
    , m_(m)
    , wdi_(wdi)
    {}

CONSTCD14
inline
year_month_weekday::year_month_weekday(const day_point& dp) _NOEXCEPT
    : year_month_weekday(from_day_point(dp))
    {}

inline
year_month_weekday&
year_month_weekday::operator+=(const months& m) _NOEXCEPT
{
    *this = *this + m;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator-=(const months& m) _NOEXCEPT
{
    *this = *this - m;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator+=(const years& y) _NOEXCEPT
{
    *this = *this + y;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator-=(const years& y) _NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday::year() const _NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_weekday::month() const _NOEXCEPT {return m_;}

CONSTCD11
inline
weekday
year_month_weekday::weekday() const _NOEXCEPT
{
    return wdi_.weekday();
}

CONSTCD11
inline
unsigned
year_month_weekday::index() const _NOEXCEPT
{
    return wdi_.index();
}

CONSTCD11
inline
weekday_indexed
year_month_weekday::weekday_indexed() const _NOEXCEPT
{
    return wdi_;
}

CONSTCD14
inline
year_month_weekday::operator day_point() const _NOEXCEPT
{
    auto d = day_point(y_/m_/1);
    return d + (wdi_.weekday() - date::weekday(d) + days{(wdi_.index()-1)*7});
}

CONSTCD14
inline
bool
year_month_weekday::ok() const _NOEXCEPT
{
    if (!y_.ok() || !m_.ok() || !wdi_.weekday().ok() || wdi_.index() < 1)
        return false;
    if (wdi_.index() <= 4)
        return true;
    auto d2 = wdi_.weekday() - date::weekday(y_/m_/1) + days((wdi_.index()-1)*7 + 1);
    return static_cast<unsigned>(d2.count()) <= static_cast<unsigned>((y_/m_/last).day());
}

CONSTCD14
inline
year_month_weekday
year_month_weekday::from_day_point(const day_point& dp) _NOEXCEPT
{
    auto const wd = date::weekday(dp);
    auto const ymd = year_month_day(dp);
    return {ymd.year(), ymd.month(), wd[(static_cast<unsigned>(ymd.day())-1)/7+1]};
}

CONSTCD11
inline
bool
operator==(const year_month_weekday& x, const year_month_weekday& y) _NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday& x, const year_month_weekday& y) _NOEXCEPT
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_weekday& ymwdi)
{
    return os << ymwdi.year() << '/' << ymwdi.month()
              << '/' << ymwdi.weekday_indexed();
}

CONSTCD14
inline
year_month_weekday
operator+(const year_month_weekday& ymwd, const months& dm) _NOEXCEPT
{
    return (ymwd.year() / ymwd.month() + dm) / ymwd.weekday_indexed();
}

CONSTCD14
inline
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) _NOEXCEPT
{
    return ymwd + dm;
}

CONSTCD14
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) _NOEXCEPT
{
    return ymwd + (-dm);
}

CONSTCD11
inline
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) _NOEXCEPT
{
    return {ymwd.year()+dy, ymwd.month(), ymwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) _NOEXCEPT
{
    return ymwd + dy;
}

CONSTCD11
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) _NOEXCEPT
{
    return ymwd + (-dy);
}

// year_month_weekday_last

CONSTCD11
inline
year_month_weekday_last::year_month_weekday_last(const date::year& y,
                                                 const date::month& m,
                                                 const date::weekday_last& wdl) _NOEXCEPT
    : y_(y)
    , m_(m)
    , wdl_(wdl)
    {}

inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const months& m) _NOEXCEPT
{
    *this = *this + m;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const months& m) _NOEXCEPT
{
    *this = *this - m;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const years& y) _NOEXCEPT
{
    *this = *this + y;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const years& y) _NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday_last::year() const _NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_weekday_last::month() const _NOEXCEPT {return m_;}

CONSTCD11
inline
weekday
year_month_weekday_last::weekday() const _NOEXCEPT
{
    return wdl_.weekday();
}

CONSTCD11
inline
weekday_last
year_month_weekday_last::weekday_last() const _NOEXCEPT
{
    return wdl_;
}

CONSTCD14
inline
year_month_weekday_last::operator day_point() const _NOEXCEPT
{
    auto const d = day_point(y_/m_/last);
    return d - (date::weekday{d} - wdl_.weekday());
}

CONSTCD11
inline
bool
year_month_weekday_last::ok() const _NOEXCEPT
{
    return y_.ok() && m_.ok() && wdl_.ok();
}

CONSTCD11
inline
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) _NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_last() == y.weekday_last();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) _NOEXCEPT
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_weekday_last& ymwdl)
{
    return os << ymwdl.year() << '/' << ymwdl.month() << '/' << ymwdl.weekday_last();
}

CONSTCD14
inline
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const months& dm) _NOEXCEPT
{
    return (ymwdl.year() / ymwdl.month() + dm) / ymwdl.weekday_last();
}

CONSTCD14
inline
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) _NOEXCEPT
{
    return ymwdl + dm;
}

CONSTCD14
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) _NOEXCEPT
{
    return ymwdl + (-dm);
}

CONSTCD11
inline
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) _NOEXCEPT
{
    return {ymwdl.year()+dy, ymwdl.month(), ymwdl.weekday_last()};
}

CONSTCD11
inline
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) _NOEXCEPT
{
    return ymwdl + dy;
}

CONSTCD11
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) _NOEXCEPT
{
    return ymwdl + (-dy);
}

// year_month from operator/()

CONSTCD11
inline
year_month
operator/(const year& y, const month& m) _NOEXCEPT
{
    return {y, m};
}

CONSTCD11
inline
year_month
operator/(const year& y, int   m) _NOEXCEPT
{
    return y / month(static_cast<unsigned>(m));
}

// month_day from operator/()

CONSTCD11
inline
month_day
operator/(const month& m, const day& d) _NOEXCEPT
{
    return {m, d};
}

CONSTCD11
inline
month_day
operator/(const day& d, const month& m) _NOEXCEPT
{
    return m / d;
}

CONSTCD11
inline
month_day
operator/(const month& m, int d) _NOEXCEPT
{
    return m / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
month_day
operator/(int m, const day& d) _NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / d;
}

CONSTCD11 inline month_day operator/(const day& d, int m) _NOEXCEPT {return m / d;}

// month_day_last from operator/()

CONSTCD11
inline
month_day_last
operator/(const month& m, last_spec) _NOEXCEPT
{
    return month_day_last{m};
}

CONSTCD11
inline
month_day_last
operator/(last_spec, const month& m) _NOEXCEPT
{
    return m/last;
}

CONSTCD11
inline
month_day_last
operator/(int m, last_spec) _NOEXCEPT
{
    return month(static_cast<unsigned>(m))/last;
}

CONSTCD11
inline
month_day_last
operator/(last_spec, int m) _NOEXCEPT
{
    return m/last;
}

// month_weekday from operator/()

CONSTCD11
inline
month_weekday
operator/(const month& m, const weekday_indexed& wdi) _NOEXCEPT
{
    return {m, wdi};
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, const month& m) _NOEXCEPT
{
    return m / wdi;
}

CONSTCD11
inline
month_weekday
operator/(int m, const weekday_indexed& wdi) _NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / wdi;
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, int m) _NOEXCEPT
{
    return m / wdi;
}

// month_weekday_last from operator/()

CONSTCD11
inline
month_weekday_last
operator/(const month& m, const weekday_last& wdl) _NOEXCEPT
{
    return {m, wdl};
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, const month& m) _NOEXCEPT
{
    return m / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(int m, const weekday_last& wdl) _NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, int m) _NOEXCEPT
{
    return m / wdl;
}

// year_month_day from operator/()

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, const day& d) _NOEXCEPT
{
    return {ym.year(), ym.month(), d};
}

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, int d)  _NOEXCEPT
{
    return ym / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
year_month_day
operator/(const year& y, const month_day& md) _NOEXCEPT
{
    return y / md.month() / md.day();
}

CONSTCD11
inline
year_month_day
operator/(int y, const month_day& md) _NOEXCEPT
{
    return year(y) / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, const year& y)  _NOEXCEPT
{
    return y / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, int y) _NOEXCEPT
{
    return year(y) / md;
}

// year_month_day_last from operator/()

CONSTCD11
inline
year_month_day_last
operator/(const year_month& ym, last_spec) _NOEXCEPT
{
    return {ym.year(), month_day_last{ym.month()}};
}

CONSTCD11
inline
year_month_day_last
operator/(const year& y, const month_day_last& mdl) _NOEXCEPT
{
    return {y, mdl};
}

CONSTCD11
inline
year_month_day_last
operator/(int y, const month_day_last& mdl) _NOEXCEPT
{
    return year(y) / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, const year& y) _NOEXCEPT
{
    return y / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, int y) _NOEXCEPT
{
    return year(y) / mdl;
}

// year_month_weekday from operator/()

CONSTCD11
inline
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) _NOEXCEPT
{
    return {ym.year(), ym.month(), wdi};
}

CONSTCD11
inline
year_month_weekday
operator/(const year& y, const month_weekday& mwd) _NOEXCEPT
{
    return {y, mwd.month(), mwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator/(int y, const month_weekday& mwd) _NOEXCEPT
{
    return year(y) / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, const year& y) _NOEXCEPT
{
    return y / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, int y) _NOEXCEPT
{
    return year(y) / mwd;
}

// year_month_weekday_last from operator/()

CONSTCD11
inline
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) _NOEXCEPT
{
    return {ym.year(), ym.month(), wdl};
}

CONSTCD11
inline
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) _NOEXCEPT
{
    return {y, mwdl.month(), mwdl.weekday_last()};
}

CONSTCD11
inline
year_month_weekday_last
operator/(int y, const month_weekday_last& mwdl) _NOEXCEPT
{
    return year(y) / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) _NOEXCEPT
{
    return y / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int y) _NOEXCEPT
{
    return year(y) / mwdl;
}

// time_of_day

enum {am = 1, pm};

namespace detail
{

enum class classify
{
    not_valid,
    hour,
    minute,
    second,
    subsecond
};

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)

template <class Duration>
struct classify_duration
{
    static CONSTDATA classify value =
        Duration{1} >= days{1}                 ? classify::not_valid :
        Duration{1} >= std::chrono::hours{1}   ? classify::hour :
        Duration{1} >= std::chrono::minutes{1} ? classify::minute :
        Duration{1} >= std::chrono::seconds{1} ? classify::second :
                                                 classify::subsecond;
};

#else

template <class Duration>
struct classify_duration
{
    static CONSTDATA classify value = classify::not_valid;
};

template<> struct classify_duration<std::chrono::hours> { static CONSTDATA classify value = classify::hour; };
template<> struct classify_duration<std::chrono::minutes> { static CONSTDATA classify value = classify::minute; };
template<> struct classify_duration<std::chrono::seconds> { static CONSTDATA classify value = classify::second; };
template<> struct classify_duration<std::chrono::milliseconds> { static CONSTDATA classify value = classify::subsecond; };
template<> struct classify_duration<std::chrono::microseconds> { static CONSTDATA classify value = classify::subsecond; };
template<> struct classify_duration<std::chrono::nanoseconds> { static CONSTDATA classify value = classify::subsecond; };

#endif

class time_of_day_base
{
protected:
    std::chrono::hours   h_;
    unsigned char mode_;

    enum {is24hr};

    CONSTCD11 time_of_day_base(std::chrono::hours h, unsigned m) _NOEXCEPT
        : h_(h)
        , mode_(static_cast<decltype(mode_)>(m))
        {}

    CONSTCD14 void make24() _NOEXCEPT;
    CONSTCD14 void make12() _NOEXCEPT;

    CONSTCD14 std::chrono::hours to24hr() const;
};

CONSTCD14
inline
std::chrono::hours
time_of_day_base::to24hr() const
{
    auto h = h_;
    if (mode_ == am || mode_ == pm)
    {
        CONSTDATA auto h12 = std::chrono::hours(12);
        if (mode_ == pm)
        {
            if (h != h12)
                h = h + h12;
        }
        else if (h == h12)
            h = std::chrono::hours(0);
    }
    return h;
}

CONSTCD14
inline
void
time_of_day_base::make24() _NOEXCEPT
{
    h_ = to24hr();
    mode_ = is24hr;
}

CONSTCD14
inline
void
time_of_day_base::make12() _NOEXCEPT
{
    if (mode_ == is24hr)
    {
        CONSTDATA auto h12 = std::chrono::hours(12);
        if (h_ >= h12)
        {
            if (h_ > h12)
                h_ = h_ - h12;
            mode_ = pm;
        }
        else
        {
            if (h_ == std::chrono::hours(0))
                h_ = h12;
            mode_ = am;
        }
    }
}

template <class Duration, detail::classify = detail::classify_duration<Duration>::value>
class time_of_day_storage;

template <class Rep, class Period>
class time_of_day_storage<std::chrono::duration<Rep, Period>, detail::classify::hour>
    : private detail::time_of_day_base
{
    using base = detail::time_of_day_base;

public:
    using precision = std::chrono::hours;

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours since_midnight) _NOEXCEPT
        : base(since_midnight, is24hr)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, unsigned md) _NOEXCEPT
        : base(h, md)
        {}

    CONSTCD11 std::chrono::hours hours() const _NOEXCEPT {return h_;}
    CONSTCD11 unsigned mode() const _NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const _NOEXCEPT
    {
        return to24hr();
    }

    CONSTCD14 precision to_duration() const _NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() _NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() _NOEXCEPT {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream _(os);
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << t.h_.count();
        switch (t.mode_)
        {
        case time_of_day_storage::is24hr:
            os << "00";
            break;
        case am:
            os << "am";
            break;
        case pm:
            os << "pm";
            break;
        }
        return os;
    }
};

template <class Rep, class Period>
class time_of_day_storage<std::chrono::duration<Rep, Period>, detail::classify::minute>
    : private detail::time_of_day_base
{
    using base = detail::time_of_day_base;

    std::chrono::minutes m_;

public:
   using precision = std::chrono::minutes;

   CONSTCD11 explicit time_of_day_storage(std::chrono::minutes since_midnight) _NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(since_midnight - h_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           unsigned md) _NOEXCEPT
        : base(h, md)
        , m_(m)
        {}

    CONSTCD11 std::chrono::hours hours() const _NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const _NOEXCEPT {return m_;}
    CONSTCD11 unsigned mode() const _NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const _NOEXCEPT
    {
        return to24hr() + m_;
    }

    CONSTCD14 precision to_duration() const _NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() _NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() _NOEXCEPT {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << abs(t.h_.count()) << ':';
        os.width(2);
        os << abs(t.m_.count());
        switch (t.mode_)
        {
        case am:
            os << "am";
            break;
        case pm:
            os << "pm";
            break;
        }
        return os;
    }
};

template <class Rep, class Period>
class time_of_day_storage<std::chrono::duration<Rep, Period>, detail::classify::second>
    : private detail::time_of_day_base
{
    using base = detail::time_of_day_base;

    std::chrono::minutes m_;
    std::chrono::seconds s_;

public:
    using precision = std::chrono::seconds;

    CONSTCD11 explicit time_of_day_storage(std::chrono::seconds since_midnight) _NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(since_midnight - h_ - m_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, unsigned md) _NOEXCEPT
        : base(h, md)
        , m_(m)
        , s_(s)
        {}

    CONSTCD11 std::chrono::hours hours() const _NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const _NOEXCEPT {return m_;}
    CONSTCD11 std::chrono::seconds seconds() const _NOEXCEPT {return s_;}
    CONSTCD11 unsigned mode() const _NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const _NOEXCEPT
    {
        return to24hr() + m_ + s_;
    }

    CONSTCD14 precision to_duration() const _NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() _NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() _NOEXCEPT {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << abs(t.h_.count()) << ':';
        os.width(2);
        os << abs(t.m_.count()) << ':';
        os.width(2);
        os << abs(t.s_.count());
        switch (t.mode_)
        {
        case am:
            os << "am";
            break;
        case pm:
            os << "pm";
            break;
        }
        return os;
    }
};

template <class Rep, class Period>
class time_of_day_storage<std::chrono::duration<Rep, Period>, detail::classify::subsecond>
    : private detail::time_of_day_base
{
public:
    using precision = std::chrono::duration<Rep, Period>;

private:
    using base = detail::time_of_day_base;

    std::chrono::minutes m_;
    std::chrono::seconds s_;
    precision            sub_s_;

public:
    CONSTCD11 explicit time_of_day_storage(precision since_midnight) _NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(std::chrono::duration_cast<std::chrono::seconds>(since_midnight - h_ - m_))
        , sub_s_(since_midnight - h_ - m_ - s_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, precision sub_s,
                                           unsigned md) _NOEXCEPT
        : base(h, md)
        , m_(m)
        , s_(s)
        , sub_s_(sub_s)
        {}

    CONSTCD11 std::chrono::hours hours() const _NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const _NOEXCEPT {return m_;}
    CONSTCD11 std::chrono::seconds seconds() const _NOEXCEPT {return s_;}
    CONSTCD11 precision subseconds() const _NOEXCEPT {return sub_s_;}
    CONSTCD11 unsigned mode() const _NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const _NOEXCEPT
    {
        return to24hr() + m_ + s_ + sub_s_;
    }

    CONSTCD14 precision to_duration() const _NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() _NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() _NOEXCEPT {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << abs(t.h_.count()) << ':';
        os.width(2);
        os << abs(t.m_.count()) << ':';
        os.width(2);
        os << abs(t.s_.count()) << '.';
#if __cplusplus >= 201402
        CONSTDATA auto cl10 = ceil_log10(Period::den);
        using scale = std::ratio_multiply<Period, std::ratio<pow10(cl10)>>;
        os.width(cl10);
        os << abs(t.sub_s_.count()) * scale::num / scale::den;
#else  // __cplusplus >= 201402
        // inefficient sub-optimal run-time mess, but gets the job done
        const unsigned long long cl10 = std::ceil(log10(Period::den));
        const auto p10 = std::pow(10., cl10);
        os.width(cl10);
        os << static_cast<unsigned long long>(abs(t.sub_s_.count())
                                              * Period::num * p10 / Period::den);
#endif  // __cplusplus >= 201402
        switch (t.mode_)
        {
        case am:
            os << "am";
            break;
        case pm:
            os << "pm";
            break;
        }
        return os;
    }

private:
#if __cplusplus >= 201402
    CONSTCD11 static int ceil_log10(unsigned long long i) _NOEXCEPT
    {
        --i;
        int n = 0;
        if (i >= 10000000000000000) {i /= 10000000000000000; n += 16;}
        if (i >= 100000000) {i /= 100000000; n += 8;}
        if (i >= 10000) {i /= 10000; n += 4;}
        if (i >= 100) {i /= 100; n += 2;}
        if (i >= 10) {i /= 10; n += 1;}
        if (i >= 1) {i /= 10; n += 1;}
        return n;
    }

    CONSTCD11 static unsigned long long pow10(unsigned y) _NOEXCEPT
    {
        CONSTDATA unsigned long long p10[] =
        {
            1ull,
            10ull,
            100ull,
            1000ull,
            10000ull,
            100000ull,
            1000000ull,
            10000000ull,
            100000000ull,
            1000000000ull,
            10000000000ull,
            100000000000ull,
            1000000000000ull,
            10000000000000ull,
            100000000000000ull,
            1000000000000000ull,
            10000000000000000ull,
            100000000000000000ull,
            1000000000000000000ull,
            10000000000000000000ull
        };
        return p10[y];
    }
#endif  // __cplusplus >= 201402
};

}  // namespace detail

template <class Duration>
class time_of_day
    : public detail::time_of_day_storage<Duration>
{
	using base = detail::time_of_day_storage<Duration>;
public:
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    using base::base;
#endif
};

#if defined(_MSC_VER) && (_MSC_VER < 1900)

template <>
class time_of_day<std::chrono::hours>: public detail::time_of_day_storage<std::chrono::hours>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::hours since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	CONSTCD11 time_of_day(std::chrono::hours h, unsigned md) _NOEXCEPT 
		: time_of_day_storage(h, md) {}
};

template <>
class time_of_day<std::chrono::minutes>: public detail::time_of_day_storage<std::chrono::minutes>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::minutes since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	CONSTCD11 time_of_day(std::chrono::hours h, std::chrono::minutes m, unsigned md) _NOEXCEPT 
		: time_of_day_storage(h, m, md) {}
};

template <>
class time_of_day<std::chrono::seconds>: public detail::time_of_day_storage<std::chrono::seconds>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::seconds since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	CONSTCD11 time_of_day(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s, unsigned md) _NOEXCEPT 
		: time_of_day_storage(h, m, s, md) {}
};

template <>
class time_of_day<std::chrono::milliseconds>: public detail::time_of_day_storage<std::chrono::milliseconds>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::milliseconds since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	template <class Rep> CONSTCD11 time_of_day(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s, std::chrono::duration<Rep, std::chrono::milliseconds> sub_s, unsigned md) _NOEXCEPT
		: time_of_day_storage(h, m, s, sub_s, md) {}
};

template<>
class time_of_day<std::chrono::microseconds>: public detail::time_of_day_storage<std::chrono::microseconds>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::microseconds since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	template <class Rep> CONSTCD11 time_of_day(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s, std::chrono::duration<Rep, std::chrono::microseconds> sub_s, unsigned md) _NOEXCEPT
		: time_of_day_storage(h, m, s, sub_s, md) {}
};

template<>
class time_of_day<std::chrono::nanoseconds>: public detail::time_of_day_storage<std::chrono::nanoseconds>
{
public:
    CONSTCD11 explicit time_of_day(std::chrono::nanoseconds since_midnight) _NOEXCEPT
        : time_of_day_storage(since_midnight)
        {}

	template <class Rep> CONSTCD11 time_of_day(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s, std::chrono::duration<Rep, std::chrono::nanoseconds> sub_s, unsigned md) _NOEXCEPT
		: time_of_day_storage(h, m, s, sub_s, md) {}
};

#endif

template <class Rep, class Period,
          class = typename std::enable_if
              <!std::chrono::treat_as_floating_point<Rep>::value>::type>
CONSTCD11
inline
time_of_day<std::chrono::duration<Rep, Period>>
make_time(std::chrono::duration<Rep, Period> d) _NOEXCEPT
{
    return time_of_day<std::chrono::duration<Rep, Period>>(d);
}

CONSTCD11
inline
time_of_day<std::chrono::hours>
make_time(std::chrono::hours h, unsigned md) _NOEXCEPT
{
    return time_of_day<std::chrono::hours>(h, md);
}

CONSTCD11
inline
time_of_day<std::chrono::minutes>
make_time(std::chrono::hours h, std::chrono::minutes m, unsigned md) _NOEXCEPT
{
    return time_of_day<std::chrono::minutes>(h, m, md);
}

CONSTCD11
inline
time_of_day<std::chrono::seconds>
make_time(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s,
          unsigned md) _NOEXCEPT
{
    return time_of_day<std::chrono::seconds>(h, m, s, md);
}

template <class Rep, class Period,
          class = typename std::enable_if<std::ratio_less<Period,
                                                          std::ratio<1>>::value>::type>
CONSTCD11
inline
time_of_day<std::chrono::duration<Rep, Period>>
make_time(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s,
          std::chrono::duration<Rep, Period> sub_s, unsigned md) _NOEXCEPT
{
    return time_of_day<std::chrono::duration<Rep, Period>>(h, m, s, sub_s, md);
}

template <class Duration>
inline
typename std::enable_if
<
    !std::chrono::treat_as_floating_point<typename Duration::rep>::value &&
        std::ratio_less<typename Duration::period, days::period>::value
    , std::ostream&
>::type
operator<<(std::ostream& os,
           const std::chrono::time_point<std::chrono::system_clock, Duration>& tp)
{
    auto const dp = floor<days>(tp);
    return os << year_month_day(dp) << ' ' << make_time(tp-dp);
}

inline
std::ostream&
operator<<(std::ostream& os, const day_point& dp)
{
    return os << year_month_day(dp);
}

}  // namespace date

#endif  // DATE_H
