#ifndef DATE_H
#define DATE_H

// Howard Hinnant
// This work is licensed under a Creative Commons Attribution 4.0 International License.
// http://creativecommons.org/licenses/by/4.0/

#include <chrono>
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

#if __cplusplus >= 201402
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14 constexpr
#else
#  define CONSTDATA constexpr
#  define CONSTCD11 constexpr
#  define CONSTCD14
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

CONSTDATA struct last_spec {} last{};

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

CONSTCD11 year_month operator/(const year& y, const month& m) noexcept;
CONSTCD11 year_month operator/(const year& y, int          m) noexcept;

CONSTCD11 month_day operator/(const day& d, const month& m) noexcept;
CONSTCD11 month_day operator/(const day& d, int          m) noexcept;
CONSTCD11 month_day operator/(const month& m, const day& d) noexcept;
CONSTCD11 month_day operator/(const month& m, int        d) noexcept;
CONSTCD11 month_day operator/(int          m, const day& d) noexcept;

CONSTCD11 month_day_last operator/(const month& m, last_spec) noexcept;
CONSTCD11 month_day_last operator/(int          m, last_spec) noexcept;
CONSTCD11 month_day_last operator/(last_spec, const month& m) noexcept;
CONSTCD11 month_day_last operator/(last_spec, int          m) noexcept;

CONSTCD11 month_weekday operator/(const month& m, const weekday_indexed& wdi) noexcept;
CONSTCD11 month_weekday operator/(int          m, const weekday_indexed& wdi) noexcept;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, const month& m) noexcept;
CONSTCD11 month_weekday operator/(const weekday_indexed& wdi, int          m) noexcept;

CONSTCD11 month_weekday_last operator/(const month& m, const weekday_last& wdl) noexcept;
CONSTCD11 month_weekday_last operator/(int          m, const weekday_last& wdl) noexcept;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, const month& m) noexcept;
CONSTCD11 month_weekday_last operator/(const weekday_last& wdl, int          m) noexcept;

CONSTCD11 year_month_day operator/(const year_month& ym, const day& d) noexcept;
CONSTCD11 year_month_day operator/(const year_month& ym, int        d) noexcept;
CONSTCD11 year_month_day operator/(const year& y, const month_day& md) noexcept;
CONSTCD11 year_month_day operator/(int         y, const month_day& md) noexcept;
CONSTCD11 year_month_day operator/(const month_day& md, const year& y) noexcept;
CONSTCD11 year_month_day operator/(const month_day& md, int         y) noexcept;

CONSTCD11
    year_month_day_last operator/(const year_month& ym,   last_spec) noexcept;
CONSTCD11
    year_month_day_last operator/(const year& y, const month_day_last& mdl) noexcept;
CONSTCD11
    year_month_day_last operator/(int         y, const month_day_last& mdl) noexcept;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, const year& y) noexcept;
CONSTCD11
    year_month_day_last operator/(const month_day_last& mdl, int         y) noexcept;

CONSTCD11
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) noexcept;

CONSTCD11
year_month_weekday
operator/(const year&        y, const month_weekday&   mwd) noexcept;

CONSTCD11
year_month_weekday
operator/(int                y, const month_weekday&   mwd) noexcept;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, const year&          y) noexcept;

CONSTCD11
year_month_weekday
operator/(const month_weekday& mwd, int                  y) noexcept;

CONSTCD11
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) noexcept;

CONSTCD11
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) noexcept;

CONSTCD11
year_month_weekday_last
operator/(int         y, const month_weekday_last& mwdl) noexcept;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) noexcept;

CONSTCD11
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int         y) noexcept;

// Detailed interface

// day

class day
{
    unsigned char d_;
public:
    explicit CONSTCD11 day(unsigned d) noexcept;

    day& operator++()    noexcept;
    day  operator++(int) noexcept;
    day& operator--()    noexcept;
    day  operator--(int) noexcept;

    day& operator+=(const days& d) noexcept;
    day& operator-=(const days& d) noexcept;

    CONSTCD11 explicit operator unsigned() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const day& x, const day& y) noexcept;
CONSTCD11 bool operator!=(const day& x, const day& y) noexcept;
CONSTCD11 bool operator< (const day& x, const day& y) noexcept;
CONSTCD11 bool operator> (const day& x, const day& y) noexcept;
CONSTCD11 bool operator<=(const day& x, const day& y) noexcept;
CONSTCD11 bool operator>=(const day& x, const day& y) noexcept;

CONSTCD11 day  operator+(const day&  x, const days& y) noexcept;
CONSTCD11 day  operator+(const days& x, const day&  y) noexcept;
CONSTCD11 day  operator-(const day&  x, const days& y) noexcept;
CONSTCD11 days operator-(const day&  x, const day&  y) noexcept;

CONSTCD11 day operator "" _d(unsigned long long d) noexcept;
std::ostream& operator<<(std::ostream& os, const day& d);

// month

class month
{
    unsigned char m_;
public:
    explicit CONSTCD11 month(unsigned m) noexcept;

    month& operator++()    noexcept;
    month  operator++(int) noexcept;
    month& operator--()    noexcept;
    month  operator--(int) noexcept;

    month& operator+=(const months& m) noexcept;
    month& operator-=(const months& m) noexcept;

    CONSTCD11 explicit operator unsigned() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const month& x, const month& y) noexcept;
CONSTCD11 bool operator!=(const month& x, const month& y) noexcept;
CONSTCD11 bool operator< (const month& x, const month& y) noexcept;
CONSTCD11 bool operator> (const month& x, const month& y) noexcept;
CONSTCD11 bool operator<=(const month& x, const month& y) noexcept;
CONSTCD11 bool operator>=(const month& x, const month& y) noexcept;

CONSTCD14 month  operator+(const month&  x, const months& y) noexcept;
CONSTCD14 month  operator+(const months& x,  const month& y) noexcept;
CONSTCD14 month  operator-(const month&  x, const months& y) noexcept;
CONSTCD14 months operator-(const month&  x,  const month& y) noexcept;

std::ostream& operator<<(std::ostream& os, const month& m);

// constexpr month jan{1};
// constexpr month feb{2};
// constexpr month mar{3};
// constexpr month apr{4};
// constexpr month may{5};
// constexpr month jun{6};
// constexpr month jul{7};
// constexpr month aug{8};
// constexpr month sep{9};
// constexpr month oct{10};
// constexpr month nov{11};
// constexpr month dec{12};

// year

class year
{
    short y_;
public:
    explicit CONSTCD11 year(int y) noexcept;

    year& operator++()    noexcept;
    year  operator++(int) noexcept;
    year& operator--()    noexcept;
    year  operator--(int) noexcept;

    year& operator+=(const years& y) noexcept;
    year& operator-=(const years& y) noexcept;

    CONSTCD11 bool is_leap() const noexcept;

    CONSTCD11 explicit operator int() const noexcept;
    CONSTCD11 bool ok() const noexcept;

    static CONSTCD11 year min() noexcept;
    static CONSTCD11 year max() noexcept;
};

CONSTCD11 bool operator==(const year& x, const year& y) noexcept;
CONSTCD11 bool operator!=(const year& x, const year& y) noexcept;
CONSTCD11 bool operator< (const year& x, const year& y) noexcept;
CONSTCD11 bool operator> (const year& x, const year& y) noexcept;
CONSTCD11 bool operator<=(const year& x, const year& y) noexcept;
CONSTCD11 bool operator>=(const year& x, const year& y) noexcept;

CONSTCD11 year  operator+(const year&  x, const years& y) noexcept;
CONSTCD11 year  operator+(const years& x, const year&  y) noexcept;
CONSTCD11 year  operator-(const year&  x, const years& y) noexcept;
CONSTCD11 years operator-(const year&  x, const year&  y) noexcept;

CONSTCD11 year operator "" _y(unsigned long long y) noexcept;
std::ostream& operator<<(std::ostream& os, const year& y);

// weekday

class weekday
{
    unsigned char wd_;
public:
    explicit CONSTCD11 weekday(unsigned wd) noexcept;
    CONSTCD11 weekday(const day_point& dp) noexcept;

    weekday& operator++()    noexcept;
    weekday  operator++(int) noexcept;
    weekday& operator--()    noexcept;
    weekday  operator--(int) noexcept;

    weekday& operator+=(const days& d) noexcept;
    weekday& operator-=(const days& d) noexcept;

    CONSTCD11 explicit operator unsigned() const noexcept;
    CONSTCD11 bool ok() const noexcept;

    CONSTCD11 weekday_indexed operator[](unsigned index) const noexcept;
    CONSTCD11 weekday_last    operator[](last_spec)      const noexcept;

private:
    static CONSTCD11 unsigned char weekday_from_days(int z) noexcept;
};

CONSTCD11 bool operator==(const weekday& x, const weekday& y) noexcept;
CONSTCD11 bool operator!=(const weekday& x, const weekday& y) noexcept;

CONSTCD14 weekday operator+(const weekday& x, const days&    y) noexcept;
CONSTCD14 weekday operator+(const days&    x, const weekday& y) noexcept;
CONSTCD14 weekday operator-(const weekday& x, const days&    y) noexcept;
CONSTCD14 days    operator-(const weekday& x, const weekday& y) noexcept;

std::ostream& operator<<(std::ostream& os, const weekday& wd);

// constexpr weekday sun{0};
// constexpr weekday mon{1};
// constexpr weekday tue{2};
// constexpr weekday wed{3};
// constexpr weekday thu{4};
// constexpr weekday fri{5};
// constexpr weekday sat{6};

// weekday_indexed

class weekday_indexed
{
    unsigned char wd_    : 4;
    unsigned char index_ : 4;

public:
    CONSTCD11 weekday_indexed(const date::weekday& wd, unsigned index) noexcept;

    CONSTCD11 date::weekday weekday() const noexcept;
    CONSTCD11 unsigned index() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const weekday_indexed& x, const weekday_indexed& y) noexcept;
CONSTCD11 bool operator!=(const weekday_indexed& x, const weekday_indexed& y) noexcept;

std::ostream& operator<<(std::ostream& os, const weekday_indexed& wdi);

// weekday_last

class weekday_last
{
    date::weekday wd_;

public:
    explicit CONSTCD11 weekday_last(const date::weekday& wd) noexcept;

    CONSTCD11 date::weekday weekday() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const weekday_last& x, const weekday_last& y) noexcept;
CONSTCD11 bool operator!=(const weekday_last& x, const weekday_last& y) noexcept;

std::ostream& operator<<(std::ostream& os, const weekday_last& wdl);

// year_month

class year_month
{
    date::year  y_;
    date::month m_;

public:
    CONSTCD11 year_month(const date::year& y, const date::month& m) noexcept;

    CONSTCD11 date::year  year()  const noexcept;
    CONSTCD11 date::month month() const noexcept;

    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const year_month& x, const year_month& y) noexcept;
CONSTCD11 bool operator!=(const year_month& x, const year_month& y) noexcept;
CONSTCD11 bool operator< (const year_month& x, const year_month& y) noexcept;
CONSTCD11 bool operator> (const year_month& x, const year_month& y) noexcept;
CONSTCD11 bool operator<=(const year_month& x, const year_month& y) noexcept;
CONSTCD11 bool operator>=(const year_month& x, const year_month& y) noexcept;

CONSTCD14 year_month operator+(const year_month& ym, const months& dm) noexcept;
CONSTCD14 year_month operator+(const months& dm, const year_month& ym) noexcept;
CONSTCD14 year_month operator-(const year_month& ym, const months& dm) noexcept;

CONSTCD11 months operator-(const year_month& x, const year_month& y) noexcept;
CONSTCD11 year_month operator+(const year_month& ym, const years& dy) noexcept;
CONSTCD11 year_month operator+(const years& dy, const year_month& ym) noexcept;
CONSTCD11 year_month operator-(const year_month& ym, const years& dy) noexcept;

std::ostream& operator<<(std::ostream& os, const year_month& ym);

// month_day

class month_day
{
    date::month m_;
    date::day   d_;

public:
    CONSTCD11 month_day(const date::month& m, const date::day& d) noexcept;

    CONSTCD11 date::month month() const noexcept;
    CONSTCD11 date::day   day() const noexcept;

    CONSTCD14 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const month_day& x, const month_day& y) noexcept;
CONSTCD11 bool operator!=(const month_day& x, const month_day& y) noexcept;
CONSTCD11 bool operator< (const month_day& x, const month_day& y) noexcept;
CONSTCD11 bool operator> (const month_day& x, const month_day& y) noexcept;
CONSTCD11 bool operator<=(const month_day& x, const month_day& y) noexcept;
CONSTCD11 bool operator>=(const month_day& x, const month_day& y) noexcept;

std::ostream& operator<<(std::ostream& os, const month_day& md);

// month_day_last

class month_day_last
{
    date::month m_;

public:
    CONSTCD11 explicit month_day_last(const date::month& m) noexcept;

    CONSTCD11 date::month month() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const month_day_last& x, const month_day_last& y) noexcept;
CONSTCD11 bool operator!=(const month_day_last& x, const month_day_last& y) noexcept;
CONSTCD11 bool operator< (const month_day_last& x, const month_day_last& y) noexcept;
CONSTCD11 bool operator> (const month_day_last& x, const month_day_last& y) noexcept;
CONSTCD11 bool operator<=(const month_day_last& x, const month_day_last& y) noexcept;
CONSTCD11 bool operator>=(const month_day_last& x, const month_day_last& y) noexcept;

std::ostream& operator<<(std::ostream& os, const month_day_last& mdl);

// month_weekday

class month_weekday
{
    date::month           m_;
    date::weekday_indexed wdi_;
public:
    CONSTCD11 month_weekday(const date::month& m,
                              const date::weekday_indexed& wdi) noexcept;

    CONSTCD11 date::month           month()           const noexcept;
    CONSTCD11 date::weekday_indexed weekday_indexed() const noexcept;

    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11 bool operator==(const month_weekday& x, const month_weekday& y) noexcept;
CONSTCD11 bool operator!=(const month_weekday& x, const month_weekday& y) noexcept;

std::ostream& operator<<(std::ostream& os, const month_weekday& mwd);

// month_weekday_last

class month_weekday_last
{
    date::month   m_;
    date::weekday wd_;

public:
    CONSTCD11 month_weekday_last(const date::month& m, const date::weekday& wd) noexcept;

    CONSTCD11 date::month   month()   const noexcept;
    CONSTCD11 date::weekday weekday() const noexcept;

    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11
    bool operator==(const month_weekday_last& x, const month_weekday_last& y) noexcept;
CONSTCD11
    bool operator!=(const month_weekday_last& x, const month_weekday_last& y) noexcept;

std::ostream& operator<<(std::ostream& os, const month_weekday_last& mwdl);

// class year_month_day

class year_month_day
{
    date::year  y_;
    date::month m_;
    date::day   d_;

public:
    CONSTCD11 year_month_day(const date::year& y, const date::month& m,
                               const date::day& d) noexcept;
    CONSTCD14 year_month_day(const year_month_day_last& ymdl) noexcept;
    CONSTCD14 year_month_day(const day_point& dp) noexcept;

    year_month_day& operator+=(const months& m) noexcept;
    year_month_day& operator-=(const months& m) noexcept;
    year_month_day& operator+=(const years& y)  noexcept;
    year_month_day& operator-=(const years& y)  noexcept;

    CONSTCD11 date::year  year()  const noexcept;
    CONSTCD11 date::month month() const noexcept;
    CONSTCD11 date::day   day()   const noexcept;

    CONSTCD14 operator day_point() const noexcept;
    CONSTCD14 bool ok() const noexcept;

private:
    static CONSTCD14 year_month_day from_day_point(const day_point& dp) noexcept;
};

CONSTCD11 bool operator==(const year_month_day& x, const year_month_day& y) noexcept;
CONSTCD11 bool operator!=(const year_month_day& x, const year_month_day& y) noexcept;
CONSTCD11 bool operator< (const year_month_day& x, const year_month_day& y) noexcept;
CONSTCD11 bool operator> (const year_month_day& x, const year_month_day& y) noexcept;
CONSTCD11 bool operator<=(const year_month_day& x, const year_month_day& y) noexcept;
CONSTCD11 bool operator>=(const year_month_day& x, const year_month_day& y) noexcept;

CONSTCD14 year_month_day operator+(const year_month_day& ymd, const months& dm) noexcept;
CONSTCD14 year_month_day operator+(const months& dm, const year_month_day& ymd) noexcept;
CONSTCD14 year_month_day operator-(const year_month_day& ymd, const months& dm) noexcept;
CONSTCD11 year_month_day operator+(const year_month_day& ymd, const years& dy)  noexcept;
CONSTCD11 year_month_day operator+(const years& dy, const year_month_day& ymd)  noexcept;
CONSTCD11 year_month_day operator-(const year_month_day& ymd, const years& dy)  noexcept;

std::ostream& operator<<(std::ostream& os, const year_month_day& ymd);

// year_month_day_last

class year_month_day_last
{
    date::year  y_;
    date::month m_;

public:
    CONSTCD11 year_month_day_last(const date::year& y, const date::month& m) noexcept;

    year_month_day_last& operator+=(const months& m) noexcept;
    year_month_day_last& operator-=(const months& m) noexcept;
    year_month_day_last& operator+=(const years& y)  noexcept;
    year_month_day_last& operator-=(const years& y)  noexcept;

    CONSTCD11 date::year  year()  const noexcept;
    CONSTCD11 date::month month() const noexcept;
    CONSTCD14 date::day   day()   const noexcept;

    CONSTCD14 operator day_point() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11
    bool operator==(const year_month_day_last& x, const year_month_day_last& y) noexcept;
CONSTCD11
    bool operator!=(const year_month_day_last& x, const year_month_day_last& y) noexcept;
CONSTCD11
    bool operator< (const year_month_day_last& x, const year_month_day_last& y) noexcept;
CONSTCD11
    bool operator> (const year_month_day_last& x, const year_month_day_last& y) noexcept;
CONSTCD11
    bool operator<=(const year_month_day_last& x, const year_month_day_last& y) noexcept;
CONSTCD11
    bool operator>=(const year_month_day_last& x, const year_month_day_last& y) noexcept;

CONSTCD14
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) noexcept;

CONSTCD14
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) noexcept;

CONSTCD11
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) noexcept;

CONSTCD11
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) noexcept;

CONSTCD14
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) noexcept;

CONSTCD11
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) noexcept;

std::ostream& operator<<(std::ostream& os, const year_month_day_last& ymdl);

// year_month_weekday

class year_month_weekday
{
    date::year            y_;
    date::month           m_;
    date::weekday_indexed wdi_;

public:
    CONSTCD11 year_month_weekday(const date::year& y, const date::month& m,
                                   const date::weekday_indexed& wdi) noexcept;
    CONSTCD14 year_month_weekday(const day_point& dp) noexcept;

    year_month_weekday& operator+=(const months& m) noexcept;
    year_month_weekday& operator-=(const months& m) noexcept;
    year_month_weekday& operator+=(const years& y)  noexcept;
    year_month_weekday& operator-=(const years& y)  noexcept;

    CONSTCD11 date::year year() const noexcept;
    CONSTCD11 date::month month() const noexcept;
    CONSTCD11 date::weekday_indexed weekday_indexed() const noexcept;

    CONSTCD14 operator day_point() const noexcept;
    CONSTCD14 bool ok() const noexcept;

private:
    static CONSTCD14 year_month_weekday from_day_point(const day_point& dp) noexcept;
};

CONSTCD11
    bool operator==(const year_month_weekday& x, const year_month_weekday& y) noexcept;
CONSTCD11
    bool operator!=(const year_month_weekday& x, const year_month_weekday& y) noexcept;

CONSTCD14
year_month_weekday
operator+(const year_month_weekday& ymwd, const months& dm) noexcept;

CONSTCD14
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) noexcept;

CONSTCD11
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) noexcept;

CONSTCD11
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) noexcept;

CONSTCD14
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) noexcept;

CONSTCD11
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) noexcept;

std::ostream& operator<<(std::ostream& os, const year_month_weekday& ymwdi);

// year_month_weekday_last

class year_month_weekday_last
{
    date::year y_;
    date::month m_;
    date::weekday_last wdl_;

public:
    CONSTCD11 year_month_weekday_last(const date::year& y, const date::month& m,
                                        const date::weekday_last& wdl) noexcept;

    year_month_weekday_last& operator+=(const months& m) noexcept;
    year_month_weekday_last& operator-=(const months& m) noexcept;
    year_month_weekday_last& operator+=(const years& y) noexcept;
    year_month_weekday_last& operator-=(const years& y) noexcept;

    CONSTCD11 date::year year() const noexcept;
    CONSTCD11 date::month month() const noexcept;
    CONSTCD11 date::weekday_last weekday_last() const noexcept;

    CONSTCD14 operator day_point() const noexcept;
    CONSTCD11 bool ok() const noexcept;
};

CONSTCD11
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) noexcept;

CONSTCD11
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) noexcept;

CONSTCD14
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const months& dm) noexcept;

CONSTCD14
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) noexcept;

CONSTCD11
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) noexcept;

CONSTCD11
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) noexcept;

CONSTCD14
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) noexcept;

CONSTCD11
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) noexcept;

std::ostream& operator<<(std::ostream& os, const year_month_weekday_last& ymwdl);

//----------------+
// Implementation |
//----------------+

// utilities

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
    To t0 = std::chrono::duration_cast<To>(d);
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

CONSTCD11 inline day::day(unsigned d) noexcept : d_(static_cast<unsigned char>(d)) {}
inline day& day::operator++() noexcept {++d_; return *this;}
inline day day::operator++(int) noexcept {auto tmp(*this); ++(*this); return tmp;}
inline day& day::operator--() noexcept {--d_; return *this;}
inline day day::operator--(int) noexcept {auto tmp(*this); --(*this); return tmp;}
inline day& day::operator+=(const days& d) noexcept {*this = *this + d; return *this;}
inline day& day::operator-=(const days& d) noexcept {*this = *this - d; return *this;}
CONSTCD11 inline day::operator unsigned() const noexcept {return d_;}
CONSTCD11 inline bool day::ok() const noexcept {return 1 <= d_ && d_ <= 31;}

CONSTCD11
inline
bool
operator==(const day& x, const day& y) noexcept
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const day& x, const day& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const day& x, const day& y) noexcept
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const day& x, const day& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const day& x, const day& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const day& x, const day& y) noexcept
{
    return !(x < y);
}

CONSTCD11
inline
days
operator-(const day& x, const day& y) noexcept
{
    return days{static_cast<days::rep>(static_cast<unsigned>(x)
                                     - static_cast<unsigned>(y))};
}

CONSTCD11
inline
day
operator+(const day& x, const days& y) noexcept
{
    return day{static_cast<unsigned>(x) + static_cast<unsigned>(y.count())};
}

CONSTCD11
inline
day
operator+(const days& x, const day& y) noexcept
{
    return y + x;
}

CONSTCD11
inline
day
operator-(const day& x, const days& y) noexcept
{
    return x + -y;
}

inline
std::ostream&
operator<<(std::ostream& os, const day& d)
{
    save_stream _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::right);
    os.width(2);
    os << static_cast<unsigned>(d);
    return os;
}

CONSTCD11
inline
day
operator "" _d(unsigned long long d) noexcept
{
    return day{static_cast<unsigned>(d)};
}

// month

CONSTCD11 inline month::month(unsigned m) noexcept : m_(static_cast<decltype(m_)>(m)) {}
inline month& month::operator++() noexcept {if (++m_ == 13) m_ = 1; return *this;}
inline month month::operator++(int) noexcept {auto tmp(*this); ++(*this); return tmp;}
inline month& month::operator--() noexcept {if (--m_ == 0) m_ = 12; return *this;}
inline month month::operator--(int) noexcept {auto tmp(*this); --(*this); return tmp;}

inline
month&
month::operator+=(const months& m) noexcept
{
    *this = *this + m;
    return *this;
}

inline
month&
month::operator-=(const months& m) noexcept
{
    *this = *this - m;
    return *this;
}

CONSTCD11 inline month::operator unsigned() const noexcept {return m_;}
CONSTCD11 inline bool month::ok() const noexcept {return 1 <= m_ && m_ <= 12;}

CONSTCD11
inline
bool
operator==(const month& x, const month& y) noexcept
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const month& x, const month& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month& x, const month& y) noexcept
{
    return static_cast<unsigned>(x) < static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator>(const month& x, const month& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month& x, const month& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month& x, const month& y) noexcept
{
    return !(x < y);
}

CONSTCD14
inline
months
operator-(const month& x, const month& y) noexcept
{
    auto const d = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return months(d <= 11 ? d : d + 12);
}

CONSTCD14
inline
month
operator+(const month& x, const months& y) noexcept
{
    auto const mu = static_cast<long long>(static_cast<unsigned>(x)) - 1 + y.count();
    auto const yr = (mu >= 0 ? mu : mu-11) / 12;
    return month{static_cast<unsigned>(mu - yr * 12 + 1)};
}

CONSTCD14
inline
month
operator+(const months& x, const month& y) noexcept
{
    return y + x;
}

CONSTCD14
inline
month
operator-(const month& x, const months& y) noexcept
{
    return x + -y;
}

CONSTDATA month jan{1};
CONSTDATA month feb{2};
CONSTDATA month mar{3};
CONSTDATA month apr{4};
CONSTDATA month may{5};
CONSTDATA month jun{6};
CONSTDATA month jul{7};
CONSTDATA month aug{8};
CONSTDATA month sep{9};
CONSTDATA month oct{10};
CONSTDATA month nov{11};
CONSTDATA month dec{12};

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

CONSTCD11 inline year::year(int y) noexcept : y_(static_cast<decltype(y_)>(y)) {}
inline year& year::operator++() noexcept {++y_; return *this;}
inline year year::operator++(int) noexcept {auto tmp(*this); ++(*this); return tmp;}
inline year& year::operator--() noexcept {--y_; return *this;}
inline year year::operator--(int) noexcept {auto tmp(*this); --(*this); return tmp;}
inline year& year::operator+=(const years& y) noexcept {*this = *this + y; return *this;}
inline year& year::operator-=(const years& y) noexcept {*this = *this - y; return *this;}

CONSTCD11
inline
bool
year::is_leap() const noexcept
{
    return y_ % 4 == 0 && (y_ % 100 != 0 || y_ % 400 == 0);
}

CONSTCD11 inline year::operator int() const noexcept {return y_;}
CONSTCD11 inline bool year::ok() const noexcept {return true;}

CONSTCD11
inline
year
year::min() noexcept
{
    return year{std::numeric_limits<short>::min()};
}

CONSTCD11
inline
year
year::max() noexcept
{
    return year{std::numeric_limits<short>::max()};
}

CONSTCD11
inline
bool
operator==(const year& x, const year& y) noexcept
{
    return static_cast<int>(x) == static_cast<int>(y);
}

CONSTCD11
inline
bool
operator!=(const year& x, const year& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year& x, const year& y) noexcept
{
    return static_cast<int>(x) < static_cast<int>(y);
}

CONSTCD11
inline
bool
operator>(const year& x, const year& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year& x, const year& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year& x, const year& y) noexcept
{
    return !(x < y);
}

CONSTCD11
inline
years
operator-(const year& x, const year& y) noexcept
{
    return years{static_cast<int>(x) - static_cast<int>(y)};
}

CONSTCD11
inline
year
operator+(const year& x, const years& y) noexcept
{
    return year{static_cast<int>(x) + y.count()};
}

CONSTCD11
inline
year
operator+(const years& x, const year& y) noexcept
{
    return y + x;
}

CONSTCD11
inline
year
operator-(const year& x, const years& y) noexcept
{
    return year{static_cast<int>(x) - y.count()};
}

inline
std::ostream&
operator<<(std::ostream& os, const year& y)
{
    save_stream _(os);
    os.fill('0');
    os.flags(std::ios::dec | std::ios::internal);
    os.width(4 + (y < year{0}));
    os << static_cast<int>(y);
    return os;
}

CONSTCD11
inline
year
operator "" _y(unsigned long long y) noexcept
{
    return year(static_cast<int>(y));
}

// weekday

CONSTCD11
inline
unsigned char
weekday::weekday_from_days(int z) noexcept
{
    return static_cast<unsigned char>(static_cast<unsigned>(
        z >= -4 ? (z+4) % 7 : (z+5) % 7 + 6));
}

CONSTCD11
inline
weekday::weekday(unsigned wd) noexcept
    : wd_(static_cast<decltype(wd_)>(wd))
    {}

CONSTCD11
inline
weekday::weekday(const day_point& dp) noexcept
    : wd_(weekday_from_days(dp.time_since_epoch().count()))
    {}

inline weekday& weekday::operator++() noexcept {if (++wd_ == 7) wd_ = 0; return *this;}
inline weekday weekday::operator++(int) noexcept {auto tmp(*this); ++(*this); return tmp;}
inline weekday& weekday::operator--() noexcept {if (wd_-- == 0) wd_ = 6; return *this;}
inline weekday weekday::operator--(int) noexcept {auto tmp(*this); --(*this); return tmp;}

inline
weekday&
weekday::operator+=(const days& d) noexcept
{
    *this = *this + d;
    return *this;
}

inline
weekday&
weekday::operator-=(const days& d) noexcept
{
    *this = *this - d;
    return *this;
}

CONSTCD11
inline
weekday::operator unsigned() const noexcept
{
    return static_cast<unsigned>(wd_);
}

CONSTCD11 inline bool weekday::ok() const noexcept {return wd_ <= 6;}

CONSTCD11
inline
bool
operator==(const weekday& x, const weekday& y) noexcept
{
    return static_cast<unsigned>(x) == static_cast<unsigned>(y);
}

CONSTCD11
inline
bool
operator!=(const weekday& x, const weekday& y) noexcept
{
    return !(x == y);
}

CONSTCD14
inline
days
operator-(const weekday& x, const weekday& y) noexcept
{
    auto const diff = static_cast<unsigned>(x) - static_cast<unsigned>(y);
    return days{diff <= 6 ? diff : diff + 7};
}

CONSTCD14
inline
weekday
operator+(const weekday& x, const days& y) noexcept
{
    auto const wdu = static_cast<long long>(static_cast<unsigned>(x)) + y.count();
    auto const wk = (wdu >= 0 ? wdu : wdu-6) / 7;
    return weekday{static_cast<unsigned>(wdu - wk * 7)};
}

CONSTCD14
inline
weekday
operator+(const days& x, const weekday& y) noexcept
{
    return y + x;
}

CONSTCD14
inline
weekday
operator-(const weekday& x, const days& y) noexcept
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

CONSTDATA weekday sun{0};
CONSTDATA weekday mon{1};
CONSTDATA weekday tue{2};
CONSTDATA weekday wed{3};
CONSTDATA weekday thu{4};
CONSTDATA weekday fri{5};
CONSTDATA weekday sat{6};

// weekday_indexed

CONSTCD11
inline
weekday
weekday_indexed::weekday() const noexcept
{
    return date::weekday{wd_};
}

CONSTCD11 inline unsigned weekday_indexed::index() const noexcept {return index_;}

CONSTCD11
inline
bool
weekday_indexed::ok() const noexcept
{
    return weekday().ok() && 1 <= index_ && index_ <= 5;
}

CONSTCD11
inline
weekday_indexed::weekday_indexed(const date::weekday& wd, unsigned index) noexcept
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
weekday::operator[](unsigned index) const noexcept
{
    return {*this, index};
}

CONSTCD11
inline
bool
operator==(const weekday_indexed& x, const weekday_indexed& y) noexcept
{
    return x.weekday() == y.weekday() && x.index() == y.index();
}

CONSTCD11
inline
bool
operator!=(const weekday_indexed& x, const weekday_indexed& y) noexcept
{
    return !(x == y);
}

// weekday_last

CONSTCD11 inline date::weekday weekday_last::weekday() const noexcept {return wd_;}
CONSTCD11 inline bool weekday_last::ok() const noexcept {return wd_.ok();}
CONSTCD11 inline weekday_last::weekday_last(const date::weekday& wd) noexcept : wd_(wd) {}

CONSTCD11
inline
bool
operator==(const weekday_last& x, const weekday_last& y) noexcept
{
    return x.weekday() == y.weekday();
}

CONSTCD11
inline
bool
operator!=(const weekday_last& x, const weekday_last& y) noexcept
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
weekday::operator[](last_spec) const noexcept
{
    return weekday_last{*this};
}

// year_month

CONSTCD11
inline
year_month::year_month(const date::year& y, const date::month& m) noexcept
    : y_(y)
    , m_(m)
    {}

CONSTCD11 inline year year_month::year() const noexcept {return y_;}
CONSTCD11 inline month year_month::month() const noexcept {return m_;}
CONSTCD11 inline bool year_month::ok() const noexcept {return y_.ok() && m_.ok();}

CONSTCD11
inline
bool
operator==(const year_month& x, const year_month& y) noexcept
{
    return x.year() == y.year() && x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const year_month& x, const year_month& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month& x, const year_month& y) noexcept
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month() < y.month()));
}

CONSTCD11
inline
bool
operator>(const year_month& x, const year_month& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month& x, const year_month& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month& x, const year_month& y) noexcept
{
    return !(x < y);
}

CONSTCD14
inline
year_month
operator+(const year_month& ym, const months& dm) noexcept
{
    auto dmi = static_cast<int>(static_cast<unsigned>(ym.month())) - 1 + dm.count();
    auto dy = (dmi >= 0 ? dmi : dmi-11) / 12;
    dmi = dmi - dy * 12 + 1;
    return (ym.year() + years(dy)) / month(static_cast<unsigned>(dmi));
}

CONSTCD14
inline
year_month
operator+(const months& dm, const year_month& ym) noexcept
{
    return ym + dm;
}

CONSTCD14
inline
year_month
operator-(const year_month& ym, const months& dm) noexcept
{
    return ym + -dm;
}

CONSTCD11
inline
months
operator-(const year_month& x, const year_month& y) noexcept
{
    return (x.year() - y.year()) +
            months(static_cast<unsigned>(x.month()) - static_cast<unsigned>(y.month()));
}

CONSTCD11
inline
year_month
operator+(const year_month& ym, const years& dy) noexcept
{
    return (ym.year() + dy) / ym.month();
}

CONSTCD11
inline
year_month
operator+(const years& dy, const year_month& ym) noexcept
{
    return ym + dy;
}

CONSTCD11
inline
year_month
operator-(const year_month& ym, const years& dy) noexcept
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
month_day::month_day(const date::month& m, const date::day& d) noexcept
    : m_(m)
    , d_(d)
    {}

CONSTCD11 inline date::month month_day::month() const noexcept {return m_;}
CONSTCD11 inline date::day month_day::day() const noexcept {return d_;}

CONSTCD14
inline
bool
month_day::ok() const noexcept
{
    CONSTDATA date::day d[] =
        {31_d, 29_d, 31_d, 30_d, 31_d, 30_d, 31_d, 31_d, 30_d, 31_d, 30_d, 31_d};
    return m_.ok() && 1_d <= d_ && d_ <= d[static_cast<unsigned>(m_)-1];
}

CONSTCD11
inline
bool
operator==(const month_day& x, const month_day& y) noexcept
{
    return x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const month_day& x, const month_day& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day& x, const month_day& y) noexcept
{
    return x.month() < y.month() ? true
        : (x.month() > y.month() ? false
        : (x.day() < y.day()));
}

CONSTCD11
inline
bool
operator>(const month_day& x, const month_day& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day& x, const month_day& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day& x, const month_day& y) noexcept
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

CONSTCD11 inline month month_day_last::month() const noexcept {return m_;}
CONSTCD11 inline bool month_day_last::ok() const noexcept {return m_.ok();}
CONSTCD11 inline month_day_last::month_day_last(const date::month& m) noexcept : m_(m) {}

CONSTCD11
inline
bool
operator==(const month_day_last& x, const month_day_last& y) noexcept
{
    return x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const month_day_last& x, const month_day_last& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const month_day_last& x, const month_day_last& y) noexcept
{
    return x.month() < y.month();
}

CONSTCD11
inline
bool
operator>(const month_day_last& x, const month_day_last& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const month_day_last& x, const month_day_last& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const month_day_last& x, const month_day_last& y) noexcept
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
                             const date::weekday_indexed& wdi) noexcept
    : m_(m)
    , wdi_(wdi)
    {}

CONSTCD11 inline month month_weekday::month() const noexcept {return m_;}

CONSTCD11
inline
weekday_indexed
month_weekday::weekday_indexed() const noexcept
{
    return wdi_;
}

CONSTCD11
inline
bool
month_weekday::ok() const noexcept
{
    return m_.ok() && wdi_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday& x, const month_weekday& y) noexcept
{
    return x.month() == y.month() && x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const month_weekday& x, const month_weekday& y) noexcept
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
                                       const date::weekday& wd) noexcept
    : m_(m)
    , wd_(wd)
    {}

CONSTCD11 inline month month_weekday_last::month() const noexcept {return m_;}
CONSTCD11 inline weekday month_weekday_last::weekday() const noexcept {return wd_;}

CONSTCD11
inline
bool
month_weekday_last::ok() const noexcept
{
    return m_.ok() && wd_.ok();
}

CONSTCD11
inline
bool
operator==(const month_weekday_last& x, const month_weekday_last& y) noexcept
{
    return x.month() == y.month() && x.weekday() == y.weekday();
}

CONSTCD11
inline
bool
operator!=(const month_weekday_last& x, const month_weekday_last& y) noexcept
{
    return !(x == y);
}

inline
std::ostream&
operator<<(std::ostream& os, const month_weekday_last& mwdl)
{
    return os << mwdl.month() << '/' << mwdl.weekday() << "[last]";
}

// year_month_day_last

CONSTCD11
inline
year_month_day_last::year_month_day_last(const date::year& y,
                                         const date::month& m) noexcept
    : y_(y)
    , m_(m)
    {}

inline
year_month_day_last&
year_month_day_last::operator+=(const months& m) noexcept
{
    *this = *this + m;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator-=(const months& m) noexcept
{
    *this = *this - m;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator+=(const years& y) noexcept
{
    *this = *this + y;
    return *this;
}

inline
year_month_day_last&
year_month_day_last::operator-=(const years& y) noexcept
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_day_last::year() const noexcept {return y_;}
CONSTCD11 inline month year_month_day_last::month() const noexcept {return m_;}

CONSTCD14
inline
day
year_month_day_last::day() const noexcept
{
    CONSTDATA date::day d[] =
        {31_d, 28_d, 31_d, 30_d, 31_d, 30_d, 31_d, 31_d, 30_d, 31_d, 30_d, 31_d};
    return m_ != feb || !y_.is_leap() ? d[static_cast<unsigned>(m_)-1] : 29_d;
}

CONSTCD11 inline bool year_month_day_last::ok() const noexcept {return m_.ok();}

CONSTCD11
inline
bool
operator==(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return x.year() == y.year() && x.month() == y.month();
}

CONSTCD11
inline
bool
operator!=(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return x.year() < y.year() ? true
        : (x.year() > y.year() ? false
        : (x.month() < y.month()));
}

CONSTCD11
inline
bool
operator>(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day_last& x, const year_month_day_last& y) noexcept
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_day_last& ymdl)
{
    return os << ymdl.year() << '/' << ymdl.month() << "/last";
}

CONSTCD14
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const months& dm) noexcept
{
    return (ymdl.year() / ymdl.month() + dm) / last;
}

CONSTCD14
inline
year_month_day_last
operator+(const months& dm, const year_month_day_last& ymdl) noexcept
{
    return ymdl + dm;
}

CONSTCD14
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const months& dm) noexcept
{
    return ymdl + (-dm);
}

CONSTCD11
inline
year_month_day_last
operator+(const year_month_day_last& ymdl, const years& dy) noexcept
{
    return {ymdl.year()+dy, ymdl.month()};
}

CONSTCD11
inline
year_month_day_last
operator+(const years& dy, const year_month_day_last& ymdl) noexcept
{
    return ymdl + dy;
}

CONSTCD11
inline
year_month_day_last
operator-(const year_month_day_last& ymdl, const years& dy) noexcept
{
    return ymdl + (-dy);
}

// year_month_day

CONSTCD11
inline
year_month_day::year_month_day(const date::year& y, const date::month& m,
                               const date::day& d) noexcept
    : y_(y)
    , m_(m)
    , d_(d)
    {}

CONSTCD14
inline
year_month_day::year_month_day(const year_month_day_last& ymdl) noexcept
    : y_(ymdl.year())
    , m_(ymdl.month())
    , d_(ymdl.day())
    {}

CONSTCD14
inline
year_month_day::year_month_day(const day_point& dp) noexcept
    : year_month_day(from_day_point(dp))
    {}

CONSTCD11 inline year year_month_day::year() const noexcept {return y_;}
CONSTCD11 inline month year_month_day::month() const noexcept {return m_;}
CONSTCD11 inline day year_month_day::day() const noexcept {return d_;}

inline
year_month_day&
year_month_day::operator+=(const months& m) noexcept
{
    *this = *this + m;
    return *this;
}

inline
year_month_day&
year_month_day::operator-=(const months& m) noexcept
{
    *this = *this - m;
    return *this;
}

inline
year_month_day&
year_month_day::operator+=(const years& y) noexcept
{
    *this = *this + y;
    return *this;
}

inline
year_month_day&
year_month_day::operator-=(const years& y) noexcept
{
    *this = *this - y;
    return *this;
}

CONSTCD14
inline
year_month_day::operator day_point() const noexcept
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
    auto const doy = (153*(m + (m > 2 ? -3u : 9)) + 2)/5 + d-1;  // [0, 365]
    auto const doe = yoe * 365 + yoe/4 - yoe/100 + doy;          // [0, 146096]
    return day_point{days{era * 146097 + static_cast<int>(doe) - 719468}};
}

CONSTCD14
inline
year_month_day_last::operator day_point() const noexcept
{
    return day_point(y_/m_/day());
}

CONSTCD14
inline
bool
year_month_day::ok() const noexcept
{
    if (!m_.ok())
        return false;
    return 1_d <= d_ && d_ <= (y_/m_/last).day();
}

CONSTCD11
inline
bool
operator==(const year_month_day& x, const year_month_day& y) noexcept
{
    return x.year() == y.year() && x.month() == y.month() && x.day() == y.day();
}

CONSTCD11
inline
bool
operator!=(const year_month_day& x, const year_month_day& y) noexcept
{
    return !(x == y);
}

CONSTCD11
inline
bool
operator<(const year_month_day& x, const year_month_day& y) noexcept
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
operator>(const year_month_day& x, const year_month_day& y) noexcept
{
    return y < x;
}

CONSTCD11
inline
bool
operator<=(const year_month_day& x, const year_month_day& y) noexcept
{
    return !(y < x);
}

CONSTCD11
inline
bool
operator>=(const year_month_day& x, const year_month_day& y) noexcept
{
    return !(x < y);
}

inline
std::ostream&
operator<<(std::ostream& os, const year_month_day& ymd)
{
    save_stream _(os);
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
year_month_day::from_day_point(const day_point& dp) noexcept
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
    auto const m = mp + (mp < 10 ? 3 : -9u);                           // [1, 12]
    return year_month_day{date::year{y + (m <= 2)}, date::month(m), date::day(d)};
}

CONSTCD14
inline
year_month_day
operator+(const year_month_day& ymd, const months& dm) noexcept
{
    return (ymd.year() / ymd.month() + dm) / ymd.day();
}

CONSTCD14
inline
year_month_day
operator+(const months& dm, const year_month_day& ymd) noexcept
{
    return ymd + dm;
}

CONSTCD14
inline
year_month_day
operator-(const year_month_day& ymd, const months& dm) noexcept
{
    return ymd + (-dm);
}

CONSTCD11
inline
year_month_day
operator+(const year_month_day& ymd, const years& dy) noexcept
{
    return (ymd.year() + dy) / ymd.month() / ymd.day();
}

CONSTCD11
inline
year_month_day
operator+(const years& dy, const year_month_day& ymd) noexcept
{
    return ymd + dy;
}

CONSTCD11
inline
year_month_day
operator-(const year_month_day& ymd, const years& dy) noexcept
{
    return ymd + (-dy);
}

// year_month_weekday

CONSTCD11
inline
year_month_weekday::year_month_weekday(const date::year& y, const date::month& m,
                                       const date::weekday_indexed& wdi)
        noexcept
    : y_(y)
    , m_(m)
    , wdi_(wdi)
    {}

CONSTCD14
inline
year_month_weekday::year_month_weekday(const day_point& dp) noexcept
    : year_month_weekday(from_day_point(dp))
    {}

inline
year_month_weekday&
year_month_weekday::operator+=(const months& m) noexcept
{
    *this = *this + m;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator-=(const months& m) noexcept
{
    *this = *this - m;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator+=(const years& y) noexcept
{
    *this = *this + y;
    return *this;
}

inline
year_month_weekday&
year_month_weekday::operator-=(const years& y) noexcept
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday::year() const noexcept {return y_;}
CONSTCD11 inline month year_month_weekday::month() const noexcept {return m_;}

CONSTCD11
inline
weekday_indexed
year_month_weekday::weekday_indexed() const noexcept
{
    return wdi_;
}

CONSTCD14
inline
year_month_weekday::operator day_point() const noexcept
{
    auto d = day_point(y_/m_/1);
    return d + (wdi_.weekday() - weekday(d) + days{(wdi_.index()-1)*7});
}

CONSTCD14
inline
bool
year_month_weekday::ok() const noexcept
{
    if (!m_.ok() || !wdi_.weekday().ok() || wdi_.index() < 1)
        return false;
    if (wdi_.index() <= 4)
        return true;
    auto d2 = wdi_.weekday() - weekday(y_/m_/1) + days((wdi_.index()-1)*7 + 1);
    return static_cast<unsigned>(d2.count()) <= static_cast<unsigned>((y_/m_/last).day());
}

CONSTCD14
inline
year_month_weekday
year_month_weekday::from_day_point(const day_point& dp) noexcept
{
    auto const wd = weekday(dp);
    auto const ymd = year_month_day(dp);
    return {ymd.year(), ymd.month(), wd[(static_cast<unsigned>(ymd.day())-1)/7+1]};
}

CONSTCD11
inline
bool
operator==(const year_month_weekday& x, const year_month_weekday& y) noexcept
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_indexed() == y.weekday_indexed();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday& x, const year_month_weekday& y) noexcept
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
operator+(const year_month_weekday& ymwd, const months& dm) noexcept
{
    return (ymwd.year() / ymwd.month() + dm) / ymwd.weekday_indexed();
}

CONSTCD14
inline
year_month_weekday
operator+(const months& dm, const year_month_weekday& ymwd) noexcept
{
    return ymwd + dm;
}

CONSTCD14
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const months& dm) noexcept
{
    return ymwd + (-dm);
}

CONSTCD11
inline
year_month_weekday
operator+(const year_month_weekday& ymwd, const years& dy) noexcept
{
    return {ymwd.year()+dy, ymwd.month(), ymwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator+(const years& dy, const year_month_weekday& ymwd) noexcept
{
    return ymwd + dy;
}

CONSTCD11
inline
year_month_weekday
operator-(const year_month_weekday& ymwd, const years& dy) noexcept
{
    return ymwd + (-dy);
}

// year_month_weekday_last

CONSTCD11
inline
year_month_weekday_last::year_month_weekday_last(const date::year& y,
                                                 const date::month& m,
                                                 const date::weekday_last& wdl) noexcept
    : y_(y)
    , m_(m)
    , wdl_(wdl)
    {}

inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const months& m) noexcept
{
    *this = *this + m;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const months& m) noexcept
{
    *this = *this - m;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator+=(const years& y) noexcept
{
    *this = *this + y;
    return *this;
}

inline
year_month_weekday_last&
year_month_weekday_last::operator-=(const years& y) noexcept
{
    *this = *this - y;
    return *this;
}

CONSTCD11 inline year year_month_weekday_last::year() const noexcept {return y_;}
CONSTCD11 inline month year_month_weekday_last::month() const noexcept {return m_;}

CONSTCD11
inline
weekday_last
year_month_weekday_last::weekday_last() const noexcept
{
    return wdl_;
}

CONSTCD14
inline
year_month_weekday_last::operator day_point() const noexcept
{
    auto const d = day_point(y_/m_/last);
    return d - (weekday{d} - wdl_.weekday());
}

CONSTCD11
inline
bool
year_month_weekday_last::ok() const noexcept
{
    return m_.ok() && wdl_.ok();
}

CONSTCD11
inline
bool
operator==(const year_month_weekday_last& x, const year_month_weekday_last& y) noexcept
{
    return x.year() == y.year() && x.month() == y.month() &&
           x.weekday_last() == y.weekday_last();
}

CONSTCD11
inline
bool
operator!=(const year_month_weekday_last& x, const year_month_weekday_last& y) noexcept
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
operator+(const year_month_weekday_last& ymwdl, const months& dm) noexcept
{
    return (ymwdl.year() / ymwdl.month() + dm) / ymwdl.weekday_last();
}

CONSTCD14
inline
year_month_weekday_last
operator+(const months& dm, const year_month_weekday_last& ymwdl) noexcept
{
    return ymwdl + dm;
}

CONSTCD14
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const months& dm) noexcept
{
    return ymwdl + (-dm);
}

CONSTCD11
inline
year_month_weekday_last
operator+(const year_month_weekday_last& ymwdl, const years& dy) noexcept
{
    return {ymwdl.year()+dy, ymwdl.month(), ymwdl.weekday_last()};
}

CONSTCD11
inline
year_month_weekday_last
operator+(const years& dy, const year_month_weekday_last& ymwdl) noexcept
{
    return ymwdl + dy;
}

CONSTCD11
inline
year_month_weekday_last
operator-(const year_month_weekday_last& ymwdl, const years& dy) noexcept
{
    return ymwdl + (-dy);
}

// year_month from operator/()

CONSTCD11
inline
year_month
operator/(const year& y, const month& m) noexcept
{
    return {y, m};
}

CONSTCD11
inline
year_month
operator/(const year& y, int   m) noexcept
{
    return y / month(static_cast<unsigned>(m));
}

// month_day from operator/()

CONSTCD11
inline
month_day
operator/(const month& m, const day& d) noexcept
{
    return {m, d};
}

CONSTCD11
inline
month_day
operator/(const day& d, const month& m) noexcept
{
    return m / d;
}

CONSTCD11
inline
month_day
operator/(const month& m, int d) noexcept
{
    return m / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
month_day
operator/(int m, const day& d) noexcept
{
    return month(static_cast<unsigned>(m)) / d;
}

CONSTCD11 inline month_day operator/(const day& d, int m) noexcept {return m / d;}

// month_day_last from operator/()

CONSTCD11
inline
month_day_last
operator/(const month& m, last_spec) noexcept
{
    return month_day_last{m};
}

CONSTCD11
inline
month_day_last
operator/(last_spec, const month& m) noexcept
{
    return m/last;
}

CONSTCD11
inline
month_day_last
operator/(int m, last_spec) noexcept
{
    return month(static_cast<unsigned>(m))/last;
}

CONSTCD11
inline
month_day_last
operator/(last_spec, int m) noexcept
{
    return m/last;
}

// month_weekday from operator/()

CONSTCD11
inline
month_weekday
operator/(const month& m, const weekday_indexed& wdi) noexcept
{
    return {m, wdi};
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, const month& m) noexcept
{
    return m / wdi;
}

CONSTCD11
inline
month_weekday
operator/(int m, const weekday_indexed& wdi) noexcept
{
    return month(static_cast<unsigned>(m)) / wdi;
}

CONSTCD11
inline
month_weekday
operator/(const weekday_indexed& wdi, int m) noexcept
{
    return m / wdi;
}

// month_weekday_last from operator/()

CONSTCD11
inline
month_weekday_last
operator/(const month& m, const weekday_last& wdl) noexcept
{
    return {m, wdl.weekday()};
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, const month& m) noexcept
{
    return m / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(int m, const weekday_last& wdl) noexcept
{
    return month(static_cast<unsigned>(m)) / wdl;
}

CONSTCD11
inline
month_weekday_last
operator/(const weekday_last& wdl, int m) noexcept
{
    return m / wdl;
}

// year_month_day from operator/()

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, const day& d) noexcept
{
    return {ym.year(), ym.month(), d};
}

CONSTCD11
inline
year_month_day
operator/(const year_month& ym, int d)  noexcept
{
    return ym / day(static_cast<unsigned>(d));
}

CONSTCD11
inline
year_month_day
operator/(const year& y, const month_day& md) noexcept
{
    return y / md.month() / md.day();
}

CONSTCD11
inline
year_month_day
operator/(int y, const month_day& md) noexcept
{
    return year(y) / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, const year& y)  noexcept
{
    return y / md;
}

CONSTCD11
inline
year_month_day
operator/(const month_day& md, int y) noexcept
{
    return year(y) / md;
}

// year_month_day_last from operator/()

CONSTCD11
inline
year_month_day_last
operator/(const year_month& ym, last_spec) noexcept
{
    return {ym.year(), ym.month()};
}

CONSTCD11
inline
year_month_day_last
operator/(const year& y, const month_day_last& mdl) noexcept
{
    return {y, mdl.month()};
}

CONSTCD11
inline
year_month_day_last
operator/(int y, const month_day_last& mdl) noexcept
{
    return year(y) / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, const year& y) noexcept
{
    return y / mdl;
}

CONSTCD11
inline
year_month_day_last
operator/(const month_day_last& mdl, int y) noexcept
{
    return year(y) / mdl;
}

// year_month_weekday from operator/()

CONSTCD11
inline
year_month_weekday
operator/(const year_month& ym, const weekday_indexed& wdi) noexcept
{
    return {ym.year(), ym.month(), wdi};
}

CONSTCD11
inline
year_month_weekday
operator/(const year& y, const month_weekday& mwd) noexcept
{
    return {y, mwd.month(), mwd.weekday_indexed()};
}

CONSTCD11
inline
year_month_weekday
operator/(int y, const month_weekday& mwd) noexcept
{
    return year(y) / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, const year& y) noexcept
{
    return y / mwd;
}

CONSTCD11
inline
year_month_weekday
operator/(const month_weekday& mwd, int y) noexcept
{
    return year(y) / mwd;
}

// year_month_weekday_last from operator/()

CONSTCD11
inline
year_month_weekday_last
operator/(const year_month& ym, const weekday_last& wdl) noexcept
{
    return {ym.year(), ym.month(), wdl};
}

CONSTCD11
inline
year_month_weekday_last
operator/(const year& y, const month_weekday_last& mwdl) noexcept
{
    return {y, mwdl.month(), mwdl.weekday()[last]};
}

CONSTCD11
inline
year_month_weekday_last
operator/(int y, const month_weekday_last& mwdl) noexcept
{
    return year(y) / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, const year& y) noexcept
{
    return y / mwdl;
}

CONSTCD11
inline
year_month_weekday_last
operator/(const month_weekday_last& mwdl, int y) noexcept
{
    return year(y) / mwdl;
}

// time_of_day

enum {am = 1, pm};

namespace detail
{

enum class classify
{
    hour,
    minute,
    second,
    subsecond
};

template <class Duration>
struct classify_duration
{
    static CONSTDATA classify value = 
        Duration{1} >= std::chrono::hours{1}   ? classify::hour :
        Duration{1} >= std::chrono::minutes{1} ? classify::minute :
        Duration{1} >= std::chrono::seconds{1} ? classify::second :
                                                 classify::subsecond;
};

class time_of_day_base
{
protected:
    std::chrono::hours   h_;
    unsigned char mode_;

    enum {is24hr};

    CONSTCD11 time_of_day_base(std::chrono::hours h, unsigned m) noexcept
        : h_(h)
        , mode_(static_cast<decltype(mode_)>(m))
        {}

    CONSTCD14 void make24() noexcept;
    CONSTCD14 void make12() noexcept;

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
time_of_day_base::make24() noexcept
{
    h_ = to24hr();
    mode_ = is24hr;
}

CONSTCD14
inline
void
time_of_day_base::make12() noexcept
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

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours since_midnight) noexcept
        : base(since_midnight, is24hr)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, unsigned md) noexcept
        : base(h, md)
        {}

    CONSTCD11 std::chrono::hours hours() const noexcept {return h_;}
    CONSTCD11 unsigned mode() const noexcept {return mode_;}

    CONSTCD14 explicit operator precision() const noexcept
    {
        return to24hr();
    }

    CONSTCD14 time_of_day_storage& make24() noexcept {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() noexcept {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        save_stream _(os);
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

   CONSTCD11 explicit time_of_day_storage(std::chrono::minutes since_midnight) noexcept
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(since_midnight - h_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           unsigned md) noexcept
        : base(h, md)
        , m_(m)
        {}

    CONSTCD11 std::chrono::hours hours() const noexcept {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const noexcept {return m_;}
    CONSTCD11 unsigned mode() const noexcept {return mode_;}

    CONSTCD14 explicit operator precision() const noexcept
    {
        return to24hr() + m_;
    }

    CONSTCD14 time_of_day_storage& make24() noexcept {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() noexcept {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        save_stream _(os);
        if (t.h_ < std::chrono::hours{0})
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

    CONSTCD11 explicit time_of_day_storage(std::chrono::seconds since_midnight) noexcept
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(since_midnight - h_ - m_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, unsigned md) noexcept
        : base(h, md)
        , m_(m)
        , s_(s)
        {}

    CONSTCD11 std::chrono::hours hours() const noexcept {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const noexcept {return m_;}
    CONSTCD11 std::chrono::seconds seconds() const noexcept {return s_;}
    CONSTCD11 unsigned mode() const noexcept {return mode_;}

    CONSTCD14 explicit operator precision() const noexcept
    {
        return to24hr() + m_ + s_;
    }

    CONSTCD14 time_of_day_storage& make24() noexcept {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() noexcept {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        save_stream _(os);
        if (t.h_ < std::chrono::hours{0})
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
    CONSTCD11 explicit time_of_day_storage(precision since_midnight) noexcept
        : base(std::chrono::duration_cast<std::chrono::hours>(since_midnight), is24hr)
        , m_(std::chrono::duration_cast<std::chrono::minutes>(since_midnight - h_))
        , s_(std::chrono::duration_cast<std::chrono::seconds>(since_midnight - h_ - m_))
        , sub_s_(since_midnight - h_ - m_ - s_)
        {}

    CONSTCD11 explicit time_of_day_storage(std::chrono::hours h, std::chrono::minutes m,
                                           std::chrono::seconds s, precision sub_s,
                                           unsigned md) noexcept
        : base(h, md)
        , m_(m)
        , s_(s)
        , sub_s_(sub_s)
        {}

    CONSTCD11 std::chrono::hours hours() const noexcept {return h_;}
    CONSTCD11 std::chrono::minutes minutes() const noexcept {return m_;}
    CONSTCD11 std::chrono::seconds seconds() const noexcept {return s_;}
    CONSTCD11 precision subseconds() const noexcept {return sub_s_;}
    CONSTCD11 unsigned mode() const noexcept {return mode_;}

    CONSTCD14 explicit operator precision() const noexcept
    {
        return to24hr() + m_ + s_ + sub_s_;
    }

    CONSTCD14 time_of_day_storage& make24() noexcept {base::make24(); return *this;}
    CONSTCD14 time_of_day_storage& make12() noexcept {base::make12(); return *this;}

    friend
    std::ostream&
    operator<<(std::ostream& os, const time_of_day_storage& t)
    {
        using namespace std;
        save_stream _(os);
        if (t.h_ < std::chrono::hours{0})
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
    CONSTCD11 static int ceil_log10(unsigned long long i) noexcept
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

    CONSTCD11 static unsigned long long pow10(unsigned y) noexcept
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
    using base::base;
};

template <class Rep, class Period,
          class = typename std::enable_if
              <!std::chrono::treat_as_floating_point<Rep>::value>::type>
CONSTCD11
inline
time_of_day<std::chrono::duration<Rep, Period>>
make_time(std::chrono::duration<Rep, Period> d) noexcept
{
    return time_of_day<std::chrono::duration<Rep, Period>>(d);
}

CONSTCD11
inline
time_of_day<std::chrono::hours>
make_time(std::chrono::hours h, unsigned md) noexcept
{
    return time_of_day<std::chrono::hours>(h, md);
}

CONSTCD11
inline
time_of_day<std::chrono::minutes>
make_time(std::chrono::hours h, std::chrono::minutes m, unsigned md) noexcept
{
    return time_of_day<std::chrono::minutes>(h, m, md);
}

CONSTCD11
inline
time_of_day<std::chrono::seconds>
make_time(std::chrono::hours h, std::chrono::minutes m, std::chrono::seconds s,
          unsigned md) noexcept
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
          std::chrono::duration<Rep, Period> sub_s, unsigned md) noexcept
{
    return time_of_day<std::chrono::duration<Rep, Period>>(h, m, s, sub_s, md);
}

template <class Rep, std::intmax_t N, std::intmax_t D,
          class = typename std::enable_if
              <!std::chrono::treat_as_floating_point<Rep>::value>::type>
inline
std::ostream&
operator<<(std::ostream& os,
           const std::chrono::time_point
               <std::chrono::system_clock,
                std::chrono::duration<Rep, std::ratio<N, D>>>& tp)
{
    auto const dp = floor<days>(tp);
    return os << year_month_day(dp) << ' ' << make_time(tp-dp);
}

}  // namespace date

#endif  // DATE_H
