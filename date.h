#ifndef DATE_H
#define DATE_H

// The MIT License (MIT)
//
// Copyright (c) 2015, 2016 Howard Hinnant
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
//
// Our apologies.  When the previous paragraph was written, lowercase had not yet
// been invented (that woud involve another several millennia of evolution).
// We did not mean to shout.

#include <chrono>
#include <climits>
#if !(__cplusplus >= 201402)
#  include <cmath>
#endif
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <locale>
#include <ostream>
#include <ratio>
#include <type_traits>

namespace date
{

//---------------+
// Configuration |
//---------------+

// MSVC's constexpr support is still a WIP, even in VS2015.
// Fall back to a lesser mode to support it.
// TODO: Remove this or retest later once MSVC's constexpr improves.
#if defined(_MSC_VER) && ! defined(__clang__)
// MS cl compiler.
#  define CONSTDATA const
#  define CONSTCD11
#  define CONSTCD14
#  define NOEXCEPT _NOEXCEPT
#elif __cplusplus >= 201402
// C++14
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14 constexpr
#  define NOEXCEPT noexcept
#else
// C++11
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14
#  define NOEXCEPT noexcept
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

template <class Duration>
    using sys_time = std::chrono::time_point<std::chrono::system_clock, Duration>;

using sys_days    = sys_time<days>;
using sys_seconds = sys_time<std::chrono::seconds>;

struct local_t {};

template <class Duration>
    using local_time = std::chrono::time_point<local_t, Duration>;

using local_seconds = local_time<std::chrono::seconds>;
using local_days    = local_time<days>;

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

CONSTCD11 year_month operator/(const year& y, const month& m) NOEXCEPT;
CONSTCD11 year_month operator/(const year& y, int          m) NOEXCEPT;

CONSTCD11 month_day operator/(const day& d, const month& m) NOEXCEPT;
CONSTCD11 month_day operator/(const day& d, int          m) NOEXCEPT;
CONSTCD11 month_day operator/(const month& m, const day& d) NOEXCEPT;
CONSTCD11 month_day operator/(const month& m, int        d) NOEXCEPT;
CONSTCD11 month_day operator/(int          m, const day& d) NOEXCEPT;

CONSTCD11 month_day_last operator/(const month& m, last_spec) NOEXCEPT;
CONSTCD11 month_day_last operator/(int          m, last_spec) NOEXCEPT;
CONSTCD11 month_day_last operator/(last_spec, const month& m) NOEXCEPT;
CONSTCD11 month_day_last operator/(last_spec, int          m) NOEXCEPT;

CONSTCD11 month_weekday operator/(const month& m, const weekday_indexed& wdi) NOEXCEPT;
CONSTCD11 month_weekday operator/(int          m, const weekday_indexed& wdi) NOEXCEPT;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, const month& m) NOEXCEPT;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, int          m) NOEXCEPT;

CONSTCD11 month_weekday_last operator/(const month& m, const weekday_last& wdl) NOEXCEPT;
CONSTCD11 month_weekday_last operator/(int          m, const weekday_last& wdl) NOEXCEPT;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, const month& m) NOEXCEPT;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, int          m) NOEXCEPT;

CONSTCD11 year_month_day operator/(const year_month& ym, const day& d) NOEXCEPT;
CONSTCD11 year_month_day operator/(const year_month& ym, int        d) NOEXCEPT;
CONSTCD11 year_month_day operator/(const year& y, const month_day& md) NOEXCEPT;
CONSTCD11 year_month_day operator/(int         y, const month_day& md) NOEXCEPT;
CONSTCD11 year_month_day operator/(const month_day& md, const year& y) NOEXCEPT;
CONSTCD11 year_month_day operator/(const month_day& md, int         y) NOEXCEPT;

CONSTCD11
    year_month_day_last operator/(const year_month& ym,   last_spec) NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const year& y, const month_day_last& mdl) NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(int         y, const month_day_last& mdl) NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, const year& y) NOEXCEPT;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, int         y) NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const year&        y, const month_weekday&   mwd) NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(int                y, const month_weekday&   mwd) NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, const year&          y) NOEXCEPT;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, int                  y) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(int         y, const month_weekday_last& mwdl) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int         y) NOEXCEPT;

// Detailed interface

// day

class day
{
    unsigned char d_;

public:
    explicit CONSTCD11 day(unsigned d) NOEXCEPT;

    CONSTCD14 day& operator++()    NOEXCEPT;
    CONSTCD14 day  operator++(int) NOEXCEPT;
    CONSTCD14 day& operator--()    NOEXCEPT;
    CONSTCD14 day  operator--(int) NOEXCEPT;

    CONSTCD14 day& operator+=(const days& d) NOEXCEPT;
    CONSTCD14 day& operator-=(const days& d) NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const day& x, const day& y) NOEXCEPT;
CONSTCD11 bool operator!=(const day& x, const day& y) NOEXCEPT;
CONSTCD11 bool operator< (const day& x, const day& y) NOEXCEPT;
CONSTCD11 bool operator> (const day& x, const day& y) NOEXCEPT;
CONSTCD11 bool operator<=(const day& x, const day& y) NOEXCEPT;
CONSTCD11 bool operator>=(const day& x, const day& y) NOEXCEPT;

CONSTCD11 day  operator+(const day&  x, const days& y) NOEXCEPT;
CONSTCD11 day  operator+(const days& x, const day&  y) NOEXCEPT;
CONSTCD11 day  operator-(const day&  x, const days& y) NOEXCEPT;
CONSTCD11 days operator-(const day&  x, const day&  y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const day& d);

// month

class month
{
    unsigned char m_;

public:
    explicit CONSTCD11 month(unsigned m) NOEXCEPT;

    CONSTCD14 month& operator++()    NOEXCEPT;
    CONSTCD14 month  operator++(int) NOEXCEPT;
    CONSTCD14 month& operator--()    NOEXCEPT;
    CONSTCD14 month  operator--(int) NOEXCEPT;

    CONSTCD14 month& operator+=(const months& m) NOEXCEPT;
    CONSTCD14 month& operator-=(const months& m) NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const month& x, const month& y) NOEXCEPT;
CONSTCD11 bool operator!=(const month& x, const month& y) NOEXCEPT;
CONSTCD11 bool operator< (const month& x, const month& y) NOEXCEPT;
CONSTCD11 bool operator> (const month& x, const month& y) NOEXCEPT;
CONSTCD11 bool operator<=(const month& x, const month& y) NOEXCEPT;
CONSTCD11 bool operator>=(const month& x, const month& y) NOEXCEPT;

CONSTCD14 month  operator+(const month&  x, const months& y) NOEXCEPT;
CONSTCD14 month  operator+(const months& x,  const month& y) NOEXCEPT;
CONSTCD14 month  operator-(const month&  x, const months& y) NOEXCEPT;
CONSTCD14 months operator-(const month&  x,  const month& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month& m);

// year

class year
{
    short y_;

public:
    explicit CONSTCD11 year(int y) NOEXCEPT;

    CONSTCD14 year& operator++()    NOEXCEPT;
    CONSTCD14 year  operator++(int) NOEXCEPT;
    CONSTCD14 year& operator--()    NOEXCEPT;
    CONSTCD14 year  operator--(int) NOEXCEPT;

    CONSTCD14 year& operator+=(const years& y) NOEXCEPT;
    CONSTCD14 year& operator-=(const years& y) NOEXCEPT;

    CONSTCD11 bool is_leap() const NOEXCEPT;

    CONSTCD11 explicit operator int() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;

    static CONSTCD11 year min() NOEXCEPT;
    static CONSTCD11 year max() NOEXCEPT;
};

CONSTCD11 bool operator==(const year& x, const year& y) NOEXCEPT;
CONSTCD11 bool operator!=(const year& x, const year& y) NOEXCEPT;
CONSTCD11 bool operator< (const year& x, const year& y) NOEXCEPT;
CONSTCD11 bool operator> (const year& x, const year& y) NOEXCEPT;
CONSTCD11 bool operator<=(const year& x, const year& y) NOEXCEPT;
CONSTCD11 bool operator>=(const year& x, const year& y) NOEXCEPT;

CONSTCD11 year  operator+(const year&  x, const years& y) NOEXCEPT;
CONSTCD11 year  operator+(const years& x, const year&  y) NOEXCEPT;
CONSTCD11 year  operator-(const year&  x, const years& y) NOEXCEPT;
CONSTCD11 years operator-(const year&  x, const year&  y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year& y);

// weekday

class weekday
{
    unsigned char wd_;
public:
    explicit CONSTCD11 weekday(unsigned wd) NOEXCEPT;
    explicit weekday(int) = delete;
    CONSTCD11 weekday(const sys_days& dp) NOEXCEPT;
    CONSTCD11 explicit weekday(const local_days& dp) NOEXCEPT;

    CONSTCD14 weekday& operator++()    NOEXCEPT;
    CONSTCD14 weekday  operator++(int) NOEXCEPT;
    CONSTCD14 weekday& operator--()    NOEXCEPT;
    CONSTCD14 weekday  operator--(int) NOEXCEPT;

    CONSTCD14 weekday& operator+=(const days& d) NOEXCEPT;
    CONSTCD14 weekday& operator-=(const days& d) NOEXCEPT;

    CONSTCD11 explicit operator unsigned() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;

    CONSTCD11 weekday_indexed operator[](unsigned index) const NOEXCEPT;
    CONSTCD11 weekday_last    operator[](last_spec)      const NOEXCEPT;

private:
    static CONSTCD11 unsigned char weekday_from_days(int z) NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday& x, const weekday& y) NOEXCEPT;
CONSTCD11 bool operator!=(const weekday& x, const weekday& y) NOEXCEPT;

CONSTCD14 weekday operator+(const weekday& x, const days&    y) NOEXCEPT;
CONSTCD14 weekday operator+(const days&    x, const weekday& y) NOEXCEPT;
CONSTCD14 weekday operator-(const weekday& x, const days&    y) NOEXCEPT;
CONSTCD14 days    operator-(const weekday& x, const weekday& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday& wd);

// weekday_indexed

class weekday_indexed
{
    unsigned char wd_    : 4;
    unsigned char index_ : 4;

public:
    CONSTCD11 weekday_indexed(const date::weekday& wd, unsigned index) NOEXCEPT;

    CONSTCD11 date::weekday weekday() const NOEXCEPT;
    CONSTCD11 unsigned index() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday_indexed& x, const weekday_indexed& y) NOEXCEPT;
CONSTCD11 bool operator!=(const weekday_indexed& x, const weekday_indexed& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday_indexed& wdi);

// weekday_last

class weekday_last
{
    date::weekday wd_;

public:
    explicit CONSTCD11 weekday_last(const date::weekday& wd) NOEXCEPT;

    CONSTCD11 date::weekday weekday() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const weekday_last& x, const weekday_last& y) NOEXCEPT;
CONSTCD11 bool operator!=(const weekday_last& x, const weekday_last& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday_last& wdl);

// year_month

class year_month
{
    date::year  y_;
    date::month m_;

public:
    CONSTCD11 year_month(const date::year& y, const date::month& m) NOEXCEPT;

    CONSTCD11 date::year  year()  const NOEXCEPT;
    CONSTCD11 date::month month() const NOEXCEPT;

    CONSTCD14 year_month& operator+=(const months& dm) NOEXCEPT;
    CONSTCD14 year_month& operator-=(const months& dm) NOEXCEPT;
    CONSTCD14 year_month& operator+=(const years& dy) NOEXCEPT;
    CONSTCD14 year_month& operator-=(const years& dy) NOEXCEPT;

    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 bool operator!=(const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 bool operator< (const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 bool operator> (const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 bool operator<=(const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 bool operator>=(const year_month& x, const year_month& y) NOEXCEPT;

CONSTCD14 year_month operator+(const year_month& ym, const months& dm) NOEXCEPT;
CONSTCD14 year_month operator+(const months& dm, const year_month& ym) NOEXCEPT;
CONSTCD14 year_month operator-(const year_month& ym, const months& dm) NOEXCEPT;

CONSTCD11 months operator-(const year_month& x, const year_month& y) NOEXCEPT;
CONSTCD11 year_month operator+(const year_month& ym, const years& dy) NOEXCEPT;
CONSTCD11 year_month operator+(const years& dy, const year_month& ym) NOEXCEPT;
CONSTCD11 year_month operator-(const year_month& ym, const years& dy) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month& ym);

// month_day

class month_day
{
    date::month m_;
    date::day   d_;

public:
    CONSTCD11 month_day(const date::month& m, const date::day& d) NOEXCEPT;

    CONSTCD11 date::month month() const NOEXCEPT;
    CONSTCD11 date::day   day() const NOEXCEPT;

    CONSTCD14 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const month_day& x, const month_day& y) NOEXCEPT;
CONSTCD11 bool operator!=(const month_day& x, const month_day& y) NOEXCEPT;
CONSTCD11 bool operator< (const month_day& x, const month_day& y) NOEXCEPT;
CONSTCD11 bool operator> (const month_day& x, const month_day& y) NOEXCEPT;
CONSTCD11 bool operator<=(const month_day& x, const month_day& y) NOEXCEPT;
CONSTCD11 bool operator>=(const month_day& x, const month_day& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_day& md);

// month_day_last

class month_day_last
{
    date::month m_;

public:
    CONSTCD11 explicit month_day_last(const date::month& m) NOEXCEPT;

    CONSTCD11 date::month month() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const month_day_last& x, const month_day_last& y) NOEXCEPT;
CONSTCD11 bool operator!=(const month_day_last& x, const month_day_last& y) NOEXCEPT;
CONSTCD11 bool operator< (const month_day_last& x, const month_day_last& y) NOEXCEPT;
CONSTCD11 bool operator> (const month_day_last& x, const month_day_last& y) NOEXCEPT;
CONSTCD11 bool operator<=(const month_day_last& x, const month_day_last& y) NOEXCEPT;
CONSTCD11 bool operator>=(const month_day_last& x, const month_day_last& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_day_last& mdl);

// month_weekday

class month_weekday
{
    date::month           m_;
    date::weekday_indexed wdi_;
public:
    CONSTCD11 month_weekday(const date::month& m,
                            const date::weekday_indexed& wdi) NOEXCEPT;

    CONSTCD11 date::month           month()           const NOEXCEPT;
    CONSTCD11 date::weekday_indexed weekday_indexed() const NOEXCEPT;

    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11 bool operator==(const month_weekday& x, const month_weekday& y) NOEXCEPT;
CONSTCD11 bool operator!=(const month_weekday& x, const month_weekday& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_weekday& mwd);

// month_weekday_last

class month_weekday_last
{
    date::month        m_;
    date::weekday_last wdl_;

public:
    CONSTCD11 month_weekday_last(const date::month& m,
                                 const date::weekday_last& wd) NOEXCEPT;

    CONSTCD11 date::month        month()        const NOEXCEPT;
    CONSTCD11 date::weekday_last weekday_last() const NOEXCEPT;

    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11
    bool operator==(const month_weekday_last& x, const month_weekday_last& y) NOEXCEPT;
CONSTCD11
    bool operator!=(const month_weekday_last& x, const month_weekday_last& y) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_weekday_last& mwdl);

// class year_month_day

class year_month_day
{
    date::year  y_;
    date::month m_;
    date::day   d_;

public:
    CONSTCD11 year_month_day(const date::year& y, const date::month& m,
                             const date::day& d) NOEXCEPT;
    CONSTCD14 year_month_day(const year_month_day_last& ymdl) NOEXCEPT;

    CONSTCD14 year_month_day(sys_days dp) NOEXCEPT;
    CONSTCD14 explicit year_month_day(local_days dp) NOEXCEPT;

    CONSTCD14 year_month_day& operator+=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_day& operator-=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_day& operator+=(const years& y)  NOEXCEPT;
    CONSTCD14 year_month_day& operator-=(const years& y)  NOEXCEPT;

    CONSTCD11 date::year  year()  const NOEXCEPT;
    CONSTCD11 date::month month() const NOEXCEPT;
    CONSTCD11 date::day   day()   const NOEXCEPT;

    CONSTCD14 operator sys_days() const NOEXCEPT;
    CONSTCD14 explicit operator local_days() const NOEXCEPT;
    CONSTCD14 bool ok() const NOEXCEPT;

private:
    static CONSTCD14 year_month_day from_days(days dp) NOEXCEPT;
    CONSTCD14 days to_days() const NOEXCEPT;
};

CONSTCD11 bool operator==(const year_month_day& x, const year_month_day& y) NOEXCEPT;
CONSTCD11 bool operator!=(const year_month_day& x, const year_month_day& y) NOEXCEPT;
CONSTCD11 bool operator< (const year_month_day& x, const year_month_day& y) NOEXCEPT;
CONSTCD11 bool operator> (const year_month_day& x, const year_month_day& y) NOEXCEPT;
CONSTCD11 bool operator<=(const year_month_day& x, const year_month_day& y) NOEXCEPT;
CONSTCD11 bool operator>=(const year_month_day& x, const year_month_day& y) NOEXCEPT;

CONSTCD14 year_month_day operator+(const year_month_day& ymd, const months& dm) NOEXCEPT;
CONSTCD14 year_month_day operator+(const months& dm, const year_month_day& ymd) NOEXCEPT;
CONSTCD14 year_month_day operator-(const year_month_day& ymd, const months& dm) NOEXCEPT;
CONSTCD11 year_month_day operator+(const year_month_day& ymd, const years& dy)  NOEXCEPT;
CONSTCD11 year_month_day operator+(const years& dy, const year_month_day& ymd)  NOEXCEPT;
CONSTCD11 year_month_day operator-(const year_month_day& ymd, const years& dy)  NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_day& ymd);

// year_month_day_last

class year_month_day_last
{
    date::year           y_;
    date::month_day_last mdl_;

public:
    CONSTCD11 year_month_day_last(const date::year& y,
                                  const date::month_day_last& mdl) NOEXCEPT;

    CONSTCD14 year_month_day_last& operator+=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_day_last& operator-=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_day_last& operator+=(const years& y)  NOEXCEPT;
    CONSTCD14 year_month_day_last& operator-=(const years& y)  NOEXCEPT;

    CONSTCD11 date::year           year()           const NOEXCEPT;
    CONSTCD11 date::month          month()          const NOEXCEPT;
    CONSTCD11 date::month_day_last month_day_last() const NOEXCEPT;
    CONSTCD14 date::day            day()            const NOEXCEPT;

    CONSTCD14 operator sys_days() const NOEXCEPT;
    CONSTCD14 explicit operator local_days() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;
};

CONSTCD11
    bool operator==(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;
CONSTCD11
    bool operator!=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;
CONSTCD11
    bool operator< (const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;
CONSTCD11
    bool operator> (const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;
CONSTCD11
    bool operator<=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;
CONSTCD11
    bool operator>=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT;

CONSTCD14
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) NOEXCEPT;

CONSTCD14
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) NOEXCEPT;

CONSTCD11
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) NOEXCEPT;

CONSTCD11
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) NOEXCEPT;

CONSTCD14
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) NOEXCEPT;

CONSTCD11
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_day_last& ymdl);

// year_month_weekday

class year_month_weekday
{
    date::year            y_;
    date::month           m_;
    date::weekday_indexed wdi_;

public:
    CONSTCD11 year_month_weekday(const date::year& y, const date::month& m,
                                   const date::weekday_indexed& wdi) NOEXCEPT;
    CONSTCD14 year_month_weekday(const sys_days& dp) NOEXCEPT;
    CONSTCD14 explicit year_month_weekday(const local_days& dp) NOEXCEPT;

    CONSTCD14 year_month_weekday& operator+=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_weekday& operator-=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_weekday& operator+=(const years& y)  NOEXCEPT;
    CONSTCD14 year_month_weekday& operator-=(const years& y)  NOEXCEPT;

    CONSTCD11 date::year year() const NOEXCEPT;
    CONSTCD11 date::month month() const NOEXCEPT;
    CONSTCD11 date::weekday weekday() const NOEXCEPT;
    CONSTCD11 unsigned index() const NOEXCEPT;
    CONSTCD11 date::weekday_indexed weekday_indexed() const NOEXCEPT;

    CONSTCD14 operator sys_days() const NOEXCEPT;
    CONSTCD14 explicit operator local_days() const NOEXCEPT;
    CONSTCD14 bool ok() const NOEXCEPT;

private:
    static CONSTCD14 year_month_weekday from_days(days dp) NOEXCEPT;
    CONSTCD14 days to_days() const NOEXCEPT;
};

CONSTCD11
    bool operator==(const year_month_weekday& x, const year_month_weekday& y) NOEXCEPT;
CONSTCD11
    bool operator!=(const year_month_weekday& x, const year_month_weekday& y) NOEXCEPT;

CONSTCD14
year_month_weekday
operator+(const year_month_weekday& ymwd, const months& dm) NOEXCEPT;

CONSTCD14
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) NOEXCEPT;

CONSTCD11
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) NOEXCEPT;

CONSTCD11
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) NOEXCEPT;

CONSTCD14
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) NOEXCEPT;

CONSTCD11
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_weekday& ymwdi);

// year_month_weekday_last

class year_month_weekday_last
{
    date::year y_;
    date::month m_;
    date::weekday_last wdl_;

public:
    CONSTCD11 year_month_weekday_last(const date::year& y, const date::month& m,
                                      const date::weekday_last& wdl) NOEXCEPT;

    CONSTCD14 year_month_weekday_last& operator+=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_weekday_last& operator-=(const months& m) NOEXCEPT;
    CONSTCD14 year_month_weekday_last& operator+=(const years& y) NOEXCEPT;
    CONSTCD14 year_month_weekday_last& operator-=(const years& y) NOEXCEPT;

    CONSTCD11 date::year year() const NOEXCEPT;
    CONSTCD11 date::month month() const NOEXCEPT;
    CONSTCD11 date::weekday weekday() const NOEXCEPT;
    CONSTCD11 date::weekday_last weekday_last() const NOEXCEPT;

    CONSTCD14 operator sys_days() const NOEXCEPT;
    CONSTCD14 explicit operator local_days() const NOEXCEPT;
    CONSTCD11 bool ok() const NOEXCEPT;

private:
    CONSTCD14 days to_days() const NOEXCEPT;
};

CONSTCD11
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) NOEXCEPT;

CONSTCD11
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const months& dm) NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) NOEXCEPT;

CONSTCD14
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) NOEXCEPT;

CONSTCD11
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) NOEXCEPT;

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_weekday_last& ymwdl);

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
inline namespace literals
{

CONSTCD11 date::day  operator "" _d(unsigned long long d) NOEXCEPT;
CONSTCD11 date::year operator "" _y(unsigned long long y) NOEXCEPT;

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

}  // inline namespace literals
#endif // !defined(_MSC_VER) || (_MSC_VER >= 1900)

//----------------+
// Implementation |
//----------------+

// utilities
namespace detail {

template<class CharT, class Traits = std::char_traits<CharT>>
class save_stream
{
    std::basic_ostream<CharT, Traits>& os_;
    CharT fill_;
    std::ios::fmtflags flags_;
    std::locale loc_;

public:
    ~save_stream()
    {
        os_.fill(fill_);
        os_.flags(flags_);
        os_.imbue(loc_);
    }

    save_stream(const save_stream&) = delete;
    save_stream& operator=(const save_stream&) = delete;

    explicit save_stream(std::basic_ostream<CharT, Traits>& os)
        : os_(os)
        , fill_(os.fill())
        , flags_(os.flags())
        , loc_(os.getloc())
        {}
};

#ifdef __GNUC__
// GCC complains about __int128 with -pedantic or -pedantic-errors
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

template <class T>
struct choose_trunc_type
{
    static const int digits = std::numeric_limits<T>::digits;
    using type = typename std::conditional
                 <
                     digits < 32,
                     std::int32_t,
                     typename std::conditional
                     <
                         digits < 64,
                         std::int64_t,
#ifdef __SIZEOF_INT128__
                         __int128
#else
                         std::int64_t
#endif
                     >::type
                 >::type;
};

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

template <class T>
CONSTCD11
inline
typename std::enable_if
<
    !std::chrono::treat_as_floating_point<T>::value,
    T
>::type
trunc(T t) NOEXCEPT
{
    return t;
}

template <class T>
CONSTCD14
inline
typename std::enable_if
<
    std::chrono::treat_as_floating_point<T>::value,
    T
>::type
trunc(T t) NOEXCEPT
{
    using namespace std;
    using I = typename choose_trunc_type<T>::type;
    CONSTDATA auto digits = numeric_limits<T>::digits;
    static_assert(digits < numeric_limits<I>::digits, "");
    CONSTDATA auto max = I{1} << (digits-1);
    CONSTDATA auto min = -max;
    const auto negative = t < T{0};
    if (min <= t && t <= max && t != 0 && t == t)
    {
        t = static_cast<T>(static_cast<I>(t));
        if (t == 0 && negative)
            t = -t;
    }
    return t;
}

}  // detail

// trunc towards zero
template <class To, class Rep, class Period>
CONSTCD11
inline
To
trunc(const std::chrono::duration<Rep, Period>& d)
{
    return To{detail::trunc(std::chrono::duration_cast<To>(d).count())};
}

// VS Update 2 provides floor, ceil, round, abs in chrono.
#if !defined(_MSC_FULL_VER) || _MSC_FULL_VER < 190023918

// round down
template <class To, class Rep, class Period>
CONSTCD14
inline
To
floor(const std::chrono::duration<Rep, Period>& d)
{
    auto t = trunc<To>(d);
    if (t > d)
        return t - To{1};
    return t;
}

// round to nearest, to even on tie
template <class To, class Rep, class Period>
CONSTCD14
inline
To
round(const std::chrono::duration<Rep, Period>& d)
{
    auto t0 = floor<To>(d);
    auto t1 = t0 + To{1};
    if (t1 == To{0} && t0 < To{0})
        t1 = -t1;
    auto diff0 = d - t0;
    auto diff1 = t1 - d;
    if (diff0 == diff1)
    {
        if (t0 - trunc<To>(t0/2)*2 == To{0})
            return t0;
        return t1;
    }
    if (diff0 < diff1)
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
    auto t = trunc<To>(d);
    if (t < d)
        return t + To{1};
    return t;
}

template <class Rep, class Period,
          class = typename std::enable_if
          <
              std::numeric_limits<Rep>::is_signed
          >::type>
CONSTCD11
std::chrono::duration<Rep, Period>
abs(std::chrono::duration<Rep, Period> d)
{
    return d >= d.zero() ? d : -d;
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

#else  // !defined(_MSC_FULL_VER) || _MSC_FULL_VER < 190023918

using std::chrono::floor;
using std::chrono::ceil;
using std::chrono::round;
using std::chrono::abs;

#endif  // !defined(_MSC_FULL_VER) || _MSC_FULL_VER < 190023918

// trunc towards zero
template <class To, class Clock, class FromDuration>
CONSTCD11
inline
std::chrono::time_point<Clock, To>
trunc(const std::chrono::time_point<Clock, FromDuration>& tp)
{
    using std::chrono::time_point;
    return time_point<Clock, To>{trunc<To>(tp.time_since_epoch())};
}

// day

CONSTCD11 inline day::day(unsigned d) NOEXCEPT : d_(static_cast<unsigned char>(d)) {}
CONSTCD14 inline day& day::operator++() NOEXCEPT {++d_; return *this;}
CONSTCD14 inline day day::operator++(int) NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
CONSTCD14 inline day& day::operator--() NOEXCEPT {--d_; return *this;}
CONSTCD14 inline day day::operator--(int) NOEXCEPT {auto tmp(*this); --(*this); return tmp;}
CONSTCD14 inline day& day::operator+=(const days& d) NOEXCEPT {*this = *this + d; return *this;}
CONSTCD14 inline day& day::operator-=(const days& d) NOEXCEPT {*this = *this - d; return *this;}
CONSTCD11 inline day::operator unsigned() const NOEXCEPT {return d_;}
CONSTCD11 inline bool day::ok() const NOEXCEPT {return 1 <= d_ && d_ <= 31;}

CONSTCD11
inline
bool
operator==(const day& x, const day& y) NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const day& x, const day& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const day& x, const day& y) NOEXCEPT
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const day& x, const day& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const day& x, const day& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const day& x, const day& y) NOEXCEPT
{
    return !(x < y);
}

CONSTCD11
inline
days
operator-(const day& x, const day& y) NOEXCEPT
{
    return days{static_cast<days::rep>(static_cast<unsigned>(x)
                                     - static_cast<unsigned>(y))};
}

CONSTCD11
inline
day
operator+(const day& x, const days& y) NOEXCEPT
{
    return day{static_cast<unsigned>(x) + static_cast<unsigned>(y.count())};
}

CONSTCD11
inline
day
operator+(const days& x, const day& y) NOEXCEPT
{
    return y + x;
}

CONSTCD11
inline
day
operator-(const day& x, const days& y) NOEXCEPT
{
    return x + -y;
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const day& d)
{
    detail::save_stream<CharT, Traits> _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::right);
    os.width(2);
    os << static_cast<unsigned>(d);
    return os;
}

// month

CONSTCD11 inline month::month(unsigned m) NOEXCEPT : m_(static_cast<decltype(m_)>(m)) {}
CONSTCD14 inline month& month::operator++() NOEXCEPT {if (++m_ == 13) m_ = 1; return *this;}
CONSTCD14 inline month month::operator++(int) NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
CONSTCD14 inline month& month::operator--() NOEXCEPT {if (--m_ == 0) m_ = 12; return *this;}
CONSTCD14 inline month month::operator--(int) NOEXCEPT {auto tmp(*this); --(*this); return tmp;}

CONSTCD14
inline
month&
month::operator+=(const months& m) NOEXCEPT
{
    *this = *this + m;
    return *this;
}

CONSTCD14
inline
month&
month::operator-=(const months& m) NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD11 inline month::operator unsigned() const NOEXCEPT {return m_;}
CONSTCD11 inline bool month::ok() const NOEXCEPT {return 1 <= m_ && m_ <= 12;}

CONSTCD11
inline
bool
operator==(const month& x, const month& y) NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const month& x, const month& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month& x, const month& y) NOEXCEPT
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const month& x, const month& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month& x, const month& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month& x, const month& y) NOEXCEPT
{
    return !(x < y);
}

CONSTCD14
inline
months
operator-(const month& x, const month& y) NOEXCEPT
{
    auto const d = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return months(d <= 11 ? d : d + 12);
}

CONSTCD14
inline
month
operator+(const month& x, const months& y) NOEXCEPT
{
    auto const mu = static_cast<long long>(static_cast<unsigned>(x)) - 1 + y.count();
    auto const yr = (mu >= 0 ? mu : mu-11) / 12;
    return month{static_cast<unsigned>(mu - yr * 12 + 1)};
}

CONSTCD14
inline
month
operator+(const months& x, const month& y) NOEXCEPT
{
    return y + x;
}

CONSTCD14
inline
month
operator-(const month& x, const months& y) NOEXCEPT
{
    return x + -y;
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month& m)
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

CONSTCD11 inline year::year(int y) NOEXCEPT : y_(static_cast<decltype(y_)>(y)) {}
CONSTCD14 inline year& year::operator++() NOEXCEPT {++y_; return *this;}
CONSTCD14 inline year year::operator++(int) NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
CONSTCD14 inline year& year::operator--() NOEXCEPT {--y_; return *this;}
CONSTCD14 inline year year::operator--(int) NOEXCEPT {auto tmp(*this); --(*this); return tmp;}
CONSTCD14 inline year& year::operator+=(const years& y) NOEXCEPT {*this = *this + y; return *this;}
CONSTCD14 inline year& year::operator-=(const years& y) NOEXCEPT {*this = *this - y; return *this;}

CONSTCD11
inline
bool
year::is_leap() const NOEXCEPT
{
    return y_ % 4 == 0 && (y_ % 100 != 0 || y_ % 400 == 0);
}

CONSTCD11 inline year::operator int() const NOEXCEPT {return y_;}
CONSTCD11 inline bool year::ok() const NOEXCEPT {return true;}

CONSTCD11
inline
year
year::min() NOEXCEPT
{
    return year{std::numeric_limits<short>::min()};
}

CONSTCD11
inline
year
year::max() NOEXCEPT
{
    return year{std::numeric_limits<short>::max()};
}

CONSTCD11
inline
bool
operator==(const year& x, const year& y) NOEXCEPT
{
    return static_cast<int>(x) == static_cast<int>(y);
}

CONSTCD11
inline
bool
operator!=(const year& x, const year& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year& x, const year& y) NOEXCEPT
{
    return static_cast<int>(x) < static_cast<int>(y);
}

CONSTCD11
inline
bool
operator>(const year& x, const year& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year& x, const year& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year& x, const year& y) NOEXCEPT
{
    return !(x < y);
}

CONSTCD11
inline
years
operator-(const year& x, const year& y) NOEXCEPT
{
    return years{static_cast<int>(x) - static_cast<int>(y)};
}

CONSTCD11
inline
year
operator+(const year& x, const years& y) NOEXCEPT
{
    return year{static_cast<int>(x) + y.count()};
}

CONSTCD11
inline
year
operator+(const years& x, const year& y) NOEXCEPT
{
    return y + x;
}

CONSTCD11
inline
year
operator-(const year& x, const years& y) NOEXCEPT
{
    return year{static_cast<int>(x) - y.count()};
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year& y)
{
    detail::save_stream<CharT, Traits> _(os);
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
weekday::weekday_from_days(int z) NOEXCEPT
{
    return static_cast<unsigned char>(static_cast<unsigned>(
        z >= -4 ? (z+4) % 7 : (z+5) % 7 + 6));
}

CONSTCD11
inline
weekday::weekday(unsigned wd) NOEXCEPT
    : wd_(static_cast<decltype(wd_)>(wd))
    {}

CONSTCD11
inline
weekday::weekday(const sys_days& dp) NOEXCEPT
    : wd_(weekday_from_days(dp.time_since_epoch().count()))
    {}

CONSTCD11
inline
weekday::weekday(const local_days& dp) NOEXCEPT
    : wd_(weekday_from_days(dp.time_since_epoch().count()))
    {}

CONSTCD14 inline weekday& weekday::operator++() NOEXCEPT {if (++wd_ == 7) wd_ = 0; return *this;}
CONSTCD14 inline weekday weekday::operator++(int) NOEXCEPT {auto tmp(*this); ++(*this); return tmp;}
CONSTCD14 inline weekday& weekday::operator--() NOEXCEPT {if (wd_-- == 0) wd_ = 6; return *this;}
CONSTCD14 inline weekday weekday::operator--(int) NOEXCEPT {auto tmp(*this); --(*this); return tmp;}

CONSTCD14
inline
weekday&
weekday::operator+=(const days& d) NOEXCEPT
{
    *this = *this + d;
    return *this;
}

CONSTCD14
inline
weekday&
weekday::operator-=(const days& d) NOEXCEPT
{
    *this = *this - d;
    return *this;
}

CONSTCD11
inline
weekday::operator unsigned() const NOEXCEPT
{
    return static_cast<unsigned>(wd_);
}

CONSTCD11 inline bool weekday::ok() const NOEXCEPT {return wd_ <= 6;}

CONSTCD11
inline
bool
operator==(const weekday& x, const weekday& y) NOEXCEPT
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const weekday& x, const weekday& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD14
inline
days
operator-(const weekday& x, const weekday& y) NOEXCEPT
{
    auto const diff = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return days{diff <= 6 ? diff : diff + 7};
}

CONSTCD14
inline
weekday
operator+(const weekday& x, const days& y) NOEXCEPT
{
    auto const wdu = static_cast<long long>(static_cast<unsigned>(x)) + y.count();
    auto const wk = (wdu >= 0 ? wdu : wdu-6) / 7;
    return weekday{static_cast<unsigned>(wdu - wk * 7)};
}

CONSTCD14
inline
weekday
operator+(const days& x, const weekday& y) NOEXCEPT
{
    return y + x;
}

CONSTCD14
inline
weekday
operator-(const weekday& x, const days& y) NOEXCEPT
{
    return x + -y;
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday& wd)
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

CONSTCD11
inline
date::day
operator "" _d(unsigned long long d) NOEXCEPT
{
    return date::day{static_cast<unsigned>(d)};
}

CONSTCD11
inline
date::year
operator "" _y(unsigned long long y) NOEXCEPT
{
    return date::year(static_cast<int>(y));
}
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)

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
weekday_indexed::weekday() const NOEXCEPT
{
    return date::weekday{static_cast<unsigned>(wd_)};
}

CONSTCD11 inline unsigned weekday_indexed::index() const NOEXCEPT {return index_;}

CONSTCD11
inline
bool
weekday_indexed::ok() const NOEXCEPT
{
    return weekday().ok() && 1 <= index_ && index_ <= 5;
}

CONSTCD11
inline
weekday_indexed::weekday_indexed(const date::weekday& wd, unsigned index) NOEXCEPT
    : wd_(static_cast<decltype(wd_)>(static_cast<unsigned>(wd)))
    , index_(static_cast<decltype(index_)>(index))
    {}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday_indexed& wdi)
{
    return os << wdi.weekday() << '[' << wdi.index() << ']';
}

CONSTCD11
inline
weekday_indexed
weekday::operator[](unsigned index) const NOEXCEPT
{
    return {*this, index};
}

CONSTCD11
inline
bool
operator==(const weekday_indexed& x, const weekday_indexed& y) NOEXCEPT
{
    return x.weekday() == y.weekday() && x.index() == y.index();
}

CONSTCD11
inline
bool
operator!=(const weekday_indexed& x, const weekday_indexed& y) NOEXCEPT
{
    return !(x == y);
}

// weekday_last

CONSTCD11 inline date::weekday weekday_last::weekday() const NOEXCEPT {return wd_;}
CONSTCD11 inline bool weekday_last::ok() const NOEXCEPT {return wd_.ok();}
CONSTCD11 inline weekday_last::weekday_last(const date::weekday& wd) NOEXCEPT : wd_(wd) {}

CONSTCD11
inline
bool
operator==(const weekday_last& x, const weekday_last& y) NOEXCEPT
{
    return x.weekday() == y.weekday();
}

CONSTCD11
inline
bool
operator!=(const weekday_last& x, const weekday_last& y) NOEXCEPT
{
    return !(x == y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const weekday_last& wdl)
{
    return os << wdl.weekday() << "[last]";
}

CONSTCD11
inline
weekday_last
weekday::operator[](last_spec) const NOEXCEPT
{
    return weekday_last{*this};
}

// year_month

CONSTCD11
inline
year_month::year_month(const date::year& y, const date::month& m) NOEXCEPT
    : y_(y)
    , m_(m)
    {}

CONSTCD11 inline year year_month::year() const NOEXCEPT {return y_;}
CONSTCD11 inline month year_month::month() const NOEXCEPT {return m_;}
CONSTCD11 inline bool year_month::ok() const NOEXCEPT {return y_.ok() && m_.ok();}

CONSTCD14
inline
year_month&
year_month::operator+=(const months& dm) NOEXCEPT
{
    *this = *this + dm;
    return *this;
}

CONSTCD14
inline
year_month&
year_month::operator-=(const months& dm) NOEXCEPT
{
    *this = *this - dm;
    return *this;
}

CONSTCD14
inline
year_month&
year_month::operator+=(const years& dy) NOEXCEPT
{
    *this = *this + dy;
    return *this;
}

CONSTCD14
inline
year_month&
year_month::operator-=(const years& dy) NOEXCEPT
{
    *this = *this - dy;
    return *this;
}

CONSTCD11
inline
bool
operator==(const year_month& x, const year_month& y) NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const year_month& x, const year_month& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month& x, const year_month& y) NOEXCEPT
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month() < y.month()));
}

CONSTCD11
inline
bool
operator>(const year_month& x, const year_month& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month& x, const year_month& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month& x, const year_month& y) NOEXCEPT
{
    return !(x < y);
}

CONSTCD14
inline
year_month
operator+(const year_month& ym, const months& dm) NOEXCEPT
{
    auto dmi = static_cast<int>(static_cast<unsigned>(ym.month())) - 1 + dm.count();
    auto dy = (dmi >= 0 ? dmi : dmi-11) / 12;
    dmi = dmi - dy * 12 + 1;
    return (ym.year() + years(dy)) / month(static_cast<unsigned>(dmi));
}

CONSTCD14
inline
year_month
operator+(const months& dm, const year_month& ym) NOEXCEPT
{
    return ym + dm;
}

CONSTCD14
inline
year_month
operator-(const year_month& ym, const months& dm) NOEXCEPT
{
    return ym + -dm;
}

CONSTCD11
inline
months
operator-(const year_month& x, const year_month& y) NOEXCEPT
{
    return (x.year() - y.year()) +
            months(static_cast<unsigned>(x.month()) - static_cast<unsigned>(y.month()));
}

CONSTCD11
inline
year_month
operator+(const year_month& ym, const years& dy) NOEXCEPT
{
    return (ym.year() + dy) / ym.month();
}

CONSTCD11
inline
year_month
operator+(const years& dy, const year_month& ym) NOEXCEPT
{
    return ym + dy;
}

CONSTCD11
inline
year_month
operator-(const year_month& ym, const years& dy) NOEXCEPT
{
    return ym + -dy;
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month& ym)
{
    return os << ym.year() << '/' << ym.month();
}

// month_day

CONSTCD11
inline
month_day::month_day(const date::month& m, const date::day& d) NOEXCEPT
    : m_(m)
    , d_(d)
    {}

CONSTCD11 inline date::month month_day::month() const NOEXCEPT {return m_;}
CONSTCD11 inline date::day month_day::day() const NOEXCEPT {return d_;}

CONSTCD14
inline
bool
month_day::ok() const NOEXCEPT
{
    CONSTDATA date::day d[] =
    {
        date::day(31), date::day(29), date::day(31),
        date::day(30), date::day(31), date::day(30),
        date::day(31), date::day(31), date::day(30),
        date::day(31), date::day(30), date::day(31)
    };
    return m_.ok() && date::day{1} <= d_ && d_ <= d[static_cast<unsigned>(m_)-1];
}

CONSTCD11
inline
bool
operator==(const month_day& x, const month_day& y) NOEXCEPT
{
    return x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const month_day& x, const month_day& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day& x, const month_day& y) NOEXCEPT
{
    return x.month() < y.month() ? true
        : (x.month() > y.month() ? false
        : (x.day() < y.day()));
}

CONSTCD11
inline
bool
operator>(const month_day& x, const month_day& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day& x, const month_day& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day& x, const month_day& y) NOEXCEPT
{
    return !(x < y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_day& md)
{
    return os << md.month() << '/' << md.day();
}

// month_day_last

CONSTCD11 inline month month_day_last::month() const NOEXCEPT {return m_;}
CONSTCD11 inline bool month_day_last::ok() const NOEXCEPT {return m_.ok();}
CONSTCD11 inline month_day_last::month_day_last(const date::month& m) NOEXCEPT : m_(m) {}

CONSTCD11
inline
bool
operator==(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return x.month() < y.month();
}

CONSTCD11
inline
bool
operator>(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day_last& x, const month_day_last& y) NOEXCEPT
{
    return !(x < y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_day_last& mdl)
{
    return os << mdl.month() << "/last";
}

// month_weekday

CONSTCD11
inline
month_weekday::month_weekday(const date::month& m,
                             const date::weekday_indexed& wdi) NOEXCEPT
    : m_(m)
    , wdi_(wdi)
    {}

CONSTCD11 inline month month_weekday::month() const NOEXCEPT {return m_;}

CONSTCD11
inline
weekday_indexed
month_weekday::weekday_indexed() const NOEXCEPT
{
    return wdi_;
}

CONSTCD11
inline
bool
month_weekday::ok() const NOEXCEPT
{
    return m_.ok() && wdi_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday& x, const month_weekday& y) NOEXCEPT
{
    return x.month() == y.month() && x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const month_weekday& x, const month_weekday& y) NOEXCEPT
{
    return !(x == y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_weekday& mwd)
{
    return os << mwd.month() << '/' << mwd.weekday_indexed();
}

// month_weekday_last

CONSTCD11
inline
month_weekday_last::month_weekday_last(const date::month& m,
                                       const date::weekday_last& wdl) NOEXCEPT
    : m_(m)
    , wdl_(wdl)
    {}

CONSTCD11 inline month month_weekday_last::month() const NOEXCEPT {return m_;}

CONSTCD11
inline
weekday_last
month_weekday_last::weekday_last() const NOEXCEPT
{
    return wdl_;
}

CONSTCD11
inline
bool
month_weekday_last::ok() const NOEXCEPT
{
    return m_.ok() && wdl_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday_last& x, const month_weekday_last& y) NOEXCEPT
{
    return x.month() == y.month() && x.weekday_last() == y.weekday_last();
}

CONSTCD11
inline
bool
operator!=(const month_weekday_last& x, const month_weekday_last& y) NOEXCEPT
{
    return !(x == y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const month_weekday_last& mwdl)
{
    return os << mwdl.month() << '/' << mwdl.weekday_last();
}

// year_month_day_last

CONSTCD11
inline
year_month_day_last::year_month_day_last(const date::year& y,
                                         const date::month_day_last& mdl) NOEXCEPT
    : y_(y)
    , mdl_(mdl)
    {}

CONSTCD14
inline
year_month_day_last&
year_month_day_last::operator+=(const months& m) NOEXCEPT
{
    *this = *this + m;
    return *this;
}

CONSTCD14
inline
year_month_day_last&
year_month_day_last::operator-=(const months& m) NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD14
inline
year_month_day_last&
year_month_day_last::operator+=(const years& y) NOEXCEPT
{
    *this = *this + y;
    return *this;
}

CONSTCD14
inline
year_month_day_last&
year_month_day_last::operator-=(const years& y) NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_day_last::year() const NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_day_last::month() const NOEXCEPT {return mdl_.month();}

CONSTCD11
inline
month_day_last
year_month_day_last::month_day_last() const NOEXCEPT
{
    return mdl_;
}

CONSTCD14
inline
day
year_month_day_last::day() const NOEXCEPT
{
    CONSTDATA date::day d[] =
    {
        date::day(31), date::day(28), date::day(31),
        date::day(30), date::day(31), date::day(30),
        date::day(31), date::day(31), date::day(30),
        date::day(31), date::day(30), date::day(31)
    };
    return month() != feb || !y_.is_leap() ?
        d[static_cast<unsigned>(month()) - 1] : date::day{29};
}

CONSTCD14
inline
year_month_day_last::operator sys_days() const NOEXCEPT
{
    return sys_days(year()/month()/day());
}

CONSTCD14
inline
year_month_day_last::operator local_days() const NOEXCEPT
{
    return local_days(year()/month()/day());
}

CONSTCD11
inline
bool
year_month_day_last::ok() const NOEXCEPT
{
    return y_.ok() && mdl_.ok();
}

CONSTCD11
inline
bool
operator==(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return x.year() == y.year() && x.month_day_last() == y.month_day_last();
}

CONSTCD11
inline
bool
operator!=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month_day_last() < y.month_day_last()));
}

CONSTCD11
inline
bool
operator>(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day_last& x, const year_month_day_last& y) NOEXCEPT
{
    return !(x < y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_day_last& ymdl)
{
    return os << ymdl.year() << '/' << ymdl.month_day_last();
}

CONSTCD14
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) NOEXCEPT
{
    return (ymdl.year() / ymdl.month() + dm) / last;
}

CONSTCD14
inline
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) NOEXCEPT
{
    return ymdl + dm;
}

CONSTCD14
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) NOEXCEPT
{
    return ymdl + (-dm);
}

CONSTCD11
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) NOEXCEPT
{
    return {ymdl.year()+dy, ymdl.month_day_last()};
}

CONSTCD11
inline
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) NOEXCEPT
{
    return ymdl + dy;
}

CONSTCD11
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) NOEXCEPT
{
    return ymdl + (-dy);
}

// year_month_day

CONSTCD11
inline
year_month_day::year_month_day(const date::year& y, const date::month& m,
                               const date::day& d) NOEXCEPT
    : y_(y)
    , m_(m)
    , d_(d)
    {}

CONSTCD14
inline
year_month_day::year_month_day(const year_month_day_last& ymdl) NOEXCEPT
    : y_(ymdl.year())
    , m_(ymdl.month())
    , d_(ymdl.day())
    {}

CONSTCD14
inline
year_month_day::year_month_day(sys_days dp) NOEXCEPT
    : year_month_day(from_days(dp.time_since_epoch()))
    {}

CONSTCD14
inline
year_month_day::year_month_day(local_days dp) NOEXCEPT
    : year_month_day(from_days(dp.time_since_epoch()))
    {}

CONSTCD11 inline year year_month_day::year() const NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_day::month() const NOEXCEPT {return m_;}
CONSTCD11 inline day year_month_day::day() const NOEXCEPT {return d_;}

CONSTCD14
inline
year_month_day&
year_month_day::operator+=(const months& m) NOEXCEPT
{
    *this = *this + m;
    return *this;
}

CONSTCD14
inline
year_month_day&
year_month_day::operator-=(const months& m) NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD14
inline
year_month_day&
year_month_day::operator+=(const years& y) NOEXCEPT
{
    *this = *this + y;
    return *this;
}

CONSTCD14
inline
year_month_day&
year_month_day::operator-=(const years& y) NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD14
inline
days
year_month_day::to_days() const NOEXCEPT
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
    auto const doy = (153*(m > 2 ? m-3 : m+9) + 2)/5 + d-1;      // [0, 365]
    auto const doe = yoe * 365 + yoe/4 - yoe/100 + doy;          // [0, 146096]
    return days{era * 146097 + static_cast<int>(doe) - 719468};
}

CONSTCD14
inline
year_month_day::operator sys_days() const NOEXCEPT
{
    return sys_days{to_days()};
}

CONSTCD14
inline
year_month_day::operator local_days() const NOEXCEPT
{
    return local_days{to_days()};
}

CONSTCD14
inline
bool
year_month_day::ok() const NOEXCEPT
{
    if (!(y_.ok() && m_.ok()))
        return false;
    return date::day{1} <= d_ && d_ <= (y_ / m_ / last).day();
}

CONSTCD11
inline
bool
operator==(const year_month_day& x, const year_month_day& y) NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const year_month_day& x, const year_month_day& y) NOEXCEPT
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day& x, const year_month_day& y) NOEXCEPT
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
operator>(const year_month_day& x, const year_month_day& y) NOEXCEPT
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day& x, const year_month_day& y) NOEXCEPT
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day& x, const year_month_day& y) NOEXCEPT
{
    return !(x < y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_day& ymd)
{
    detail::save_stream<CharT, Traits> _(os);
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
year_month_day::from_days(days dp) NOEXCEPT
{
    static_assert(std::numeric_limits<unsigned>::digits >= 18,
             "This algorithm has not been ported to a 16 bit unsigned integer");
    static_assert(std::numeric_limits<int>::digits >= 20,
             "This algorithm has not been ported to a 16 bit signed integer");
    auto const z = dp.count() + 719468;
    auto const era = (z >= 0 ? z : z - 146096) / 146097;
    auto const doe = static_cast<unsigned>(z - era * 146097);          // [0, 146096]
    auto const yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;  // [0, 399]
    auto const y = static_cast<days::rep>(yoe) + era * 400;
    auto const doy = doe - (365*yoe + yoe/4 - yoe/100);                // [0, 365]
    auto const mp = (5*doy + 2)/153;                                   // [0, 11]
    auto const d = doy - (153*mp+2)/5 + 1;                             // [1, 31]
    auto const m = mp < 10 ? mp+3 : mp-9;                              // [1, 12]
    return year_month_day{date::year{y + (m <= 2)}, date::month(m), date::day(d)};
}

CONSTCD14
inline
year_month_day
operator+(const year_month_day& ymd, const months& dm) NOEXCEPT
{
    return (ymd.year() / ymd.month() + dm) / ymd.day();
}

CONSTCD14
inline
year_month_day
operator+(const months& dm, const year_month_day& ymd) NOEXCEPT
{
    return ymd + dm;
}

CONSTCD14
inline
year_month_day
operator-(const year_month_day& ymd, const months& dm) NOEXCEPT
{
    return ymd + (-dm);
}

CONSTCD11
inline
year_month_day
operator+(const year_month_day& ymd, const years& dy) NOEXCEPT
{
    return (ymd.year() + dy) / ymd.month() / ymd.day();
}

CONSTCD11
inline
year_month_day
operator+(const years& dy, const year_month_day& ymd) NOEXCEPT
{
    return ymd + dy;
}

CONSTCD11
inline
year_month_day
operator-(const year_month_day& ymd, const years& dy) NOEXCEPT
{
    return ymd + (-dy);
}

// year_month_weekday

CONSTCD11
inline
year_month_weekday::year_month_weekday(const date::year& y, const date::month& m,
                                       const date::weekday_indexed& wdi)
        NOEXCEPT
    : y_(y)
    , m_(m)
    , wdi_(wdi)
    {}

CONSTCD14
inline
year_month_weekday::year_month_weekday(const sys_days& dp) NOEXCEPT
    : year_month_weekday(from_days(dp.time_since_epoch()))
    {}

CONSTCD14
inline
year_month_weekday::year_month_weekday(const local_days& dp) NOEXCEPT
    : year_month_weekday(from_days(dp.time_since_epoch()))
    {}

CONSTCD14
inline
year_month_weekday&
year_month_weekday::operator+=(const months& m) NOEXCEPT
{
    *this = *this + m;
    return *this;
}

CONSTCD14
inline
year_month_weekday&
year_month_weekday::operator-=(const months& m) NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD14
inline
year_month_weekday&
year_month_weekday::operator+=(const years& y) NOEXCEPT
{
    *this = *this + y;
    return *this;
}

CONSTCD14
inline
year_month_weekday&
year_month_weekday::operator-=(const years& y) NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday::year() const NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_weekday::month() const NOEXCEPT {return m_;}

CONSTCD11
inline
weekday
year_month_weekday::weekday() const NOEXCEPT
{
    return wdi_.weekday();
}

CONSTCD11
inline
unsigned
year_month_weekday::index() const NOEXCEPT
{
    return wdi_.index();
}

CONSTCD11
inline
weekday_indexed
year_month_weekday::weekday_indexed() const NOEXCEPT
{
    return wdi_;
}

CONSTCD14
inline
year_month_weekday::operator sys_days() const NOEXCEPT
{
    return sys_days{to_days()};
}

CONSTCD14
inline
year_month_weekday::operator local_days() const NOEXCEPT
{
    return local_days{to_days()};
}

CONSTCD14
inline
bool
year_month_weekday::ok() const NOEXCEPT
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
year_month_weekday::from_days(days d) NOEXCEPT
{
    sys_days dp{d};
    auto const wd = date::weekday(dp);
    auto const ymd = year_month_day(dp);
    return {ymd.year(), ymd.month(), wd[(static_cast<unsigned>(ymd.day())-1)/7+1]};
}

CONSTCD14
inline
days
year_month_weekday::to_days() const NOEXCEPT
{
    auto d = sys_days(y_/m_/1);
    return (d + (wdi_.weekday() - date::weekday(d) + days{(wdi_.index()-1)*7})
           ).time_since_epoch();
}

CONSTCD11
inline
bool
operator==(const year_month_weekday& x, const year_month_weekday& y) NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday& x, const year_month_weekday& y) NOEXCEPT
{
    return !(x == y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_weekday& ymwdi)
{
    return os << ymwdi.year() << '/' << ymwdi.month()
              << '/' << ymwdi.weekday_indexed();
}

CONSTCD14
inline
year_month_weekday
operator+(const year_month_weekday& ymwd, const months& dm) NOEXCEPT
{
    return (ymwd.year() / ymwd.month() + dm) / ymwd.weekday_indexed();
}

CONSTCD14
inline
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) NOEXCEPT
{
    return ymwd + dm;
}

CONSTCD14
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) NOEXCEPT
{
    return ymwd + (-dm);
}

CONSTCD11
inline
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) NOEXCEPT
{
    return {ymwd.year()+dy, ymwd.month(), ymwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) NOEXCEPT
{
    return ymwd + dy;
}

CONSTCD11
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) NOEXCEPT
{
    return ymwd + (-dy);
}

// year_month_weekday_last

CONSTCD11
inline
year_month_weekday_last::year_month_weekday_last(const date::year& y,
                                                 const date::month& m,
                                                 const date::weekday_last& wdl) NOEXCEPT
    : y_(y)
    , m_(m)
    , wdl_(wdl)
    {}

CONSTCD14
inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const months& m) NOEXCEPT
{
    *this = *this + m;
    return *this;
}

CONSTCD14
inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const months& m) NOEXCEPT
{
    *this = *this - m;
    return *this;
}

CONSTCD14
inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const years& y) NOEXCEPT
{
    *this = *this + y;
    return *this;
}

CONSTCD14
inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const years& y) NOEXCEPT
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday_last::year() const NOEXCEPT {return y_;}
CONSTCD11 inline month year_month_weekday_last::month() const NOEXCEPT {return m_;}

CONSTCD11
inline
weekday
year_month_weekday_last::weekday() const NOEXCEPT
{
    return wdl_.weekday();
}

CONSTCD11
inline
weekday_last
year_month_weekday_last::weekday_last() const NOEXCEPT
{
    return wdl_;
}

CONSTCD14
inline
year_month_weekday_last::operator sys_days() const NOEXCEPT
{
    return sys_days{to_days()};
}

CONSTCD14
inline
year_month_weekday_last::operator local_days() const NOEXCEPT
{
    return local_days{to_days()};
}

CONSTCD11
inline
bool
year_month_weekday_last::ok() const NOEXCEPT
{
    return y_.ok() && m_.ok() && wdl_.ok();
}

CONSTCD14
inline
days
year_month_weekday_last::to_days() const NOEXCEPT
{
    auto const d = sys_days(y_/m_/last);
    return (d - (date::weekday{d} - wdl_.weekday())).time_since_epoch();
}

CONSTCD11
inline
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) NOEXCEPT
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_last() == y.weekday_last();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) NOEXCEPT
{
    return !(x == y);
}

template<class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const year_month_weekday_last& ymwdl)
{
    return os << ymwdl.year() << '/' << ymwdl.month() << '/' << ymwdl.weekday_last();
}

CONSTCD14
inline
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const months& dm) NOEXCEPT
{
    return (ymwdl.year() / ymwdl.month() + dm) / ymwdl.weekday_last();
}

CONSTCD14
inline
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) NOEXCEPT
{
    return ymwdl + dm;
}

CONSTCD14
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) NOEXCEPT
{
    return ymwdl + (-dm);
}

CONSTCD11
inline
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) NOEXCEPT
{
    return {ymwdl.year()+dy, ymwdl.month(), ymwdl.weekday_last()};
}

CONSTCD11
inline
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) NOEXCEPT
{
    return ymwdl + dy;
}

CONSTCD11
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) NOEXCEPT
{
    return ymwdl + (-dy);
}

// year_month from operator/()

CONSTCD11
inline
year_month
operator/(const year& y, const month& m) NOEXCEPT
{
    return {y, m};
}

CONSTCD11
inline
year_month
operator/(const year& y, int   m) NOEXCEPT
{
    return y / month(static_cast<unsigned>(m));
}

// month_day from operator/()

CONSTCD11
inline
month_day
operator/(const month& m, const day& d) NOEXCEPT
{
    return {m, d};
}

CONSTCD11
inline
month_day
operator/(const day& d, const month& m) NOEXCEPT
{
    return m / d;
}

CONSTCD11
inline
month_day
operator/(const month& m, int d) NOEXCEPT
{
    return m / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
month_day
operator/(int m, const day& d) NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / d;
}

CONSTCD11 inline month_day operator/(const day& d, int m) NOEXCEPT {return m / d;}

// month_day_last from operator/()

CONSTCD11
inline
month_day_last
operator/(const month& m, last_spec) NOEXCEPT
{
    return month_day_last{m};
}

CONSTCD11
inline
month_day_last
operator/(last_spec, const month& m) NOEXCEPT
{
    return m/last;
}

CONSTCD11
inline
month_day_last
operator/(int m, last_spec) NOEXCEPT
{
    return month(static_cast<unsigned>(m))/last;
}

CONSTCD11
inline
month_day_last
operator/(last_spec, int m) NOEXCEPT
{
    return m/last;
}

// month_weekday from operator/()

CONSTCD11
inline
month_weekday
operator/(const month& m, const weekday_indexed& wdi) NOEXCEPT
{
    return {m, wdi};
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, const month& m) NOEXCEPT
{
    return m / wdi;
}

CONSTCD11
inline
month_weekday
operator/(int m, const weekday_indexed& wdi) NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / wdi;
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, int m) NOEXCEPT
{
    return m / wdi;
}

// month_weekday_last from operator/()

CONSTCD11
inline
month_weekday_last
operator/(const month& m, const weekday_last& wdl) NOEXCEPT
{
    return {m, wdl};
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, const month& m) NOEXCEPT
{
    return m / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(int m, const weekday_last& wdl) NOEXCEPT
{
    return month(static_cast<unsigned>(m)) / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, int m) NOEXCEPT
{
    return m / wdl;
}

// year_month_day from operator/()

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, const day& d) NOEXCEPT
{
    return {ym.year(), ym.month(), d};
}

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, int d)  NOEXCEPT
{
    return ym / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
year_month_day
operator/(const year& y, const month_day& md) NOEXCEPT
{
    return y / md.month() / md.day();
}

CONSTCD11
inline
year_month_day
operator/(int y, const month_day& md) NOEXCEPT
{
    return year(y) / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, const year& y)  NOEXCEPT
{
    return y / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, int y) NOEXCEPT
{
    return year(y) / md;
}

// year_month_day_last from operator/()

CONSTCD11
inline
year_month_day_last
operator/(const year_month& ym, last_spec) NOEXCEPT
{
    return {ym.year(), month_day_last{ym.month()}};
}

CONSTCD11
inline
year_month_day_last
operator/(const year& y, const month_day_last& mdl) NOEXCEPT
{
    return {y, mdl};
}

CONSTCD11
inline
year_month_day_last
operator/(int y, const month_day_last& mdl) NOEXCEPT
{
    return year(y) / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, const year& y) NOEXCEPT
{
    return y / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, int y) NOEXCEPT
{
    return year(y) / mdl;
}

// year_month_weekday from operator/()

CONSTCD11
inline
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) NOEXCEPT
{
    return {ym.year(), ym.month(), wdi};
}

CONSTCD11
inline
year_month_weekday
operator/(const year& y, const month_weekday& mwd) NOEXCEPT
{
    return {y, mwd.month(), mwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator/(int y, const month_weekday& mwd) NOEXCEPT
{
    return year(y) / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, const year& y) NOEXCEPT
{
    return y / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, int y) NOEXCEPT
{
    return year(y) / mwd;
}

// year_month_weekday_last from operator/()

CONSTCD11
inline
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) NOEXCEPT
{
    return {ym.year(), ym.month(), wdl};
}

CONSTCD11
inline
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) NOEXCEPT
{
    return {y, mwdl.month(), mwdl.weekday_last()};
}

CONSTCD11
inline
year_month_weekday_last
operator/(int y, const month_weekday_last& mwdl) NOEXCEPT
{
    return year(y) / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) NOEXCEPT
{
    return y / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int y) NOEXCEPT
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
    static CONSTDATA classify value =
        std::ratio_greater_equal<
            typename Duration::period,
            days::period >::value
                ? classify::not_valid :
        std::ratio_greater_equal<
            typename Duration::period,
            std::chrono::hours::period>::value
                ? classify::hour :
        std::ratio_greater_equal<
            typename Duration::period,
            std::chrono::minutes::period>::value
                ? classify::minute :
        std::ratio_greater_equal<
            typename Duration::period,
            std::chrono::seconds::period>::value
                ? classify::second :
                classify::subsecond;
};

#endif // !defined(_MSC_VER) || (_MSC_VER >= 1900)

class time_of_day_base
{
protected:
    std::chrono::hours   h_;
    unsigned char mode_;

    enum {is24hr};

    CONSTCD11 time_of_day_base(std::chrono::hours h, unsigned m) NOEXCEPT
        : h_(h)
        , mode_(static_cast<decltype(mode_)>(m))
        {}

    CONSTCD14 void make24() NOEXCEPT;
    CONSTCD14 void make12() NOEXCEPT;

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
time_of_day_base::make24() NOEXCEPT
{
    h_ = to24hr();
    mode_ = is24hr;
}

CONSTCD14
inline
void
time_of_day_base::make12() NOEXCEPT
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

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours since_midnight) NOEXCEPT
        : base(since_midnight, is24hr)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, unsigned md) NOEXCEPT
        : base(h, md)
        {}

    CONSTCD11 std::chrono::hours hours() const NOEXCEPT {return h_;}
    CONSTCD11 unsigned mode() const NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const NOEXCEPT
    {
        return to24hr();
    }

    CONSTCD14 precision to_duration() const NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() NOEXCEPT {base::make12(); return *this;}

    template<class CharT, class Traits>
    friend
    std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream<CharT, Traits> _(os);
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

   CONSTCD11 explicit time_of_day_storage(std::chrono::minutes since_midnight) NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(since_midnight - h_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           unsigned md) NOEXCEPT
        : base(h, md)
        , m_(m)
        {}

    CONSTCD11 std::chrono::hours hours() const NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const NOEXCEPT {return m_;}
    CONSTCD11 unsigned mode() const NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const NOEXCEPT
    {
        return to24hr() + m_;
    }

    CONSTCD14 precision to_duration() const NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() NOEXCEPT {base::make12(); return *this;}

    template<class CharT, class Traits>
    friend
    std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream<CharT, Traits> _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << std::abs(t.h_.count()) << ':';
        os.width(2);
        os << std::abs(t.m_.count());
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

    CONSTCD11 explicit time_of_day_storage(std::chrono::seconds since_midnight) NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(since_midnight - h_ - m_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, unsigned md) NOEXCEPT
        : base(h, md)
        , m_(m)
        , s_(s)
        {}

    CONSTCD11 std::chrono::hours hours() const NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const NOEXCEPT {return m_;}
    CONSTCD14 std::chrono::seconds& seconds() NOEXCEPT {return s_;}
    CONSTCD11 std::chrono::seconds seconds() const NOEXCEPT {return s_;}
    CONSTCD11 unsigned mode() const NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const NOEXCEPT
    {
        return to24hr() + s_ + m_;
    }

    CONSTCD14 precision to_duration() const NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() NOEXCEPT {base::make12(); return *this;}

    template<class CharT, class Traits>
    friend
    std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream<CharT, Traits> _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << std::abs(t.h_.count()) << ':';
        os.width(2);
        os << std::abs(t.m_.count()) << ':';
        os.width(2);
        os << std::abs(t.s_.count());
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
    CONSTCD11 explicit time_of_day_storage(precision since_midnight) NOEXCEPT
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(std::chrono::duration_cast<std::chrono::seconds>(since_midnight - h_ - m_))
        , sub_s_(since_midnight - h_ - m_ - s_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, precision sub_s,
                                           unsigned md) NOEXCEPT
        : base(h, md)
        , m_(m)
        , s_(s)
        , sub_s_(sub_s)
        {}

    CONSTCD11 std::chrono::hours hours() const NOEXCEPT {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const NOEXCEPT {return m_;}
    CONSTCD14 std::chrono::seconds& seconds() NOEXCEPT {return s_;}
    CONSTCD11 std::chrono::seconds seconds() const NOEXCEPT {return s_;}
    CONSTCD11 precision subseconds() const NOEXCEPT {return sub_s_;}
    CONSTCD11 unsigned mode() const NOEXCEPT {return mode_;}

    CONSTCD14 explicit operator precision() const NOEXCEPT
    {
        return to24hr() + s_ + sub_s_ + m_;
    }

    CONSTCD14 precision to_duration() const NOEXCEPT
    {
        return static_cast<precision>(*this);
    }

    CONSTCD14 time_of_day_storage& make24() NOEXCEPT {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() NOEXCEPT {base::make12(); return *this;}

    template<class CharT, class Traits>
    friend
    std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, const time_of_day_storage& t)
    {
        using namespace std;
        detail::save_stream<CharT, Traits> _(os);
        if (static_cast<precision>(t) < std::chrono::hours{0})
            os << '-';
        os.fill('0');
        os.flags(std::ios::dec | std::ios::right);
        if (t.mode_ != am && t.mode_ != pm)
            os.width(2);
        os << std::abs(t.h_.count()) << ':';
        os.width(2);
        os << std::abs(t.m_.count()) << ':';
        os.width(2);
        os << std::abs(t.s_.count())
           << use_facet<numpunct<char>>(os.getloc()).decimal_point();
        os.imbue(locale{});
#if __cplusplus >= 201402
        CONSTDATA auto cl10 = ceil_log10(Period::den);
        using scale = std::ratio_multiply<Period, std::ratio<pow10(cl10)>>;
        os.width(cl10);
        os << std::abs(t.sub_s_.count()) * scale::num / scale::den;
#else  // __cplusplus >= 201402
        // inefficient sub-optimal run-time mess, but gets the job done
        const unsigned long long cl10 =
            static_cast<unsigned long long>(std::ceil(log10(Period::den)));
        const auto p10 = std::pow(10., cl10);
        os.width(cl10);
        os << static_cast<unsigned long long>(std::abs(t.sub_s_.count())
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
    CONSTCD11 static int ceil_log10(unsigned long long i) NOEXCEPT
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

    CONSTCD11 static unsigned long long pow10(unsigned y) NOEXCEPT
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
#if !(defined(_MSC_VER) && !defined(__clang__))
    // C++11
    using base::base;
#else
    // MS cl compiler workaround.
    template <class ...Args>
    explicit time_of_day(Args&& ...args)
        : base(std::forward<Args>(args)...)
        {}
#endif
};

template <class Rep, class Period,
          class = typename std::enable_if
              <!std::chrono::treat_as_floating_point<Rep>::value>::type>
CONSTCD11
inline
time_of_day<std::chrono::duration<Rep, Period>>
make_time(std::chrono::duration<Rep, Period> d) NOEXCEPT
{
    return time_of_day<std::chrono::duration<Rep, Period>>(d);
}

CONSTCD11
inline
time_of_day<std::chrono::hours>
make_time(std::chrono::hours h, unsigned md) NOEXCEPT
{
    return time_of_day<std::chrono::hours>(h, md);
}

CONSTCD11
inline
time_of_day<std::chrono::minutes>
make_time(std::chrono::hours h, std::chrono::minutes m, unsigned md) NOEXCEPT
{
    return time_of_day<std::chrono::minutes>(h, m, md);
}

CONSTCD11
inline
time_of_day<std::chrono::seconds>
make_time(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s,
          unsigned md) NOEXCEPT
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
          std::chrono::duration<Rep, Period> sub_s, unsigned md) NOEXCEPT
{
    return time_of_day<std::chrono::duration<Rep, Period>>(h, m, s, sub_s, md);
}

template <class CharT, class Traits, class Duration>
inline
typename std::enable_if
<
    !std::chrono::treat_as_floating_point<typename Duration::rep>::value &&
        std::ratio_less<typename Duration::period, days::period>::value
    , std::basic_ostream<CharT, Traits>&
>::type
operator<<(std::basic_ostream<CharT, Traits>& os, const sys_time<Duration>& tp)
{
    auto const dp = floor<days>(tp);
    return os << year_month_day(dp) << ' ' << make_time(tp-dp);
}

template <class CharT, class Traits>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const sys_days& dp)
{
    return os << year_month_day(dp);
}

template <class CharT, class Traits, class Duration>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const local_time<Duration>& ut)
{
    return os << sys_time<Duration>{ut.time_since_epoch()};
}

}  // namespace date

#endif  // DATE_H
