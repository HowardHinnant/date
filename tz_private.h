#ifndef TZ_PRIVATE_H
#define TZ_PRIVATE_H

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

#include "tz.h"

namespace date
{

enum class tz {utc, local, standard};

class MonthDayTime
{
private:
    struct pair
    {
#if defined(_MSC_VER) && (_MSC_VER < 1900)
        pair() : month_day_(date::jan / 1), weekday_(0U) {}

        pair(const date::month_day& month_day, const date::weekday& weekday)
            : month_day_(month_day), weekday_(weekday) {}
#endif

        date::month_day month_day_;
        date::weekday   weekday_;
    };

    enum Type {month_day, month_last_dow, lteq, gteq};

    Type                         type_{month_day};

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    union U
#else
    struct U
#endif
    {
        date::month_day          month_day_;
        date::month_weekday_last month_weekday_last_;
        pair                     month_day_weekday_;

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
        U() : month_day_{date::jan/1} {}
#else
        U() :
            month_day_(date::jan/1),
            month_weekday_last_(date::month(0U), date::weekday_last(date::weekday(0U)))
        {}

#endif // !defined(_MSC_VER) || (_MSC_VER >= 1900)

        U& operator=(const date::month_day& x);
        U& operator=(const date::month_weekday_last& x);
        U& operator=(const pair& x);
    } u;

    std::chrono::hours           h_{0};
    std::chrono::minutes         m_{0};
    std::chrono::seconds         s_{0};
    tz                           zone_{tz::local};

public:
    MonthDayTime() = default;
    MonthDayTime(local_seconds tp, tz timezone);
    MonthDayTime(const date::month_day& md, tz timezone);

    date::day day() const;
    date::month month() const;
    tz zone() const {return zone_;}

    void canonicalize(date::year y);

    sys_seconds
       to_sys(date::year y, std::chrono::seconds offset, std::chrono::seconds save) const;
    sys_days to_sys_days(date::year y) const;

    sys_seconds to_time_point(date::year y) const;
    int compare(date::year y, const MonthDayTime& x, date::year yx,
                std::chrono::seconds offset, std::chrono::minutes prev_save) const;

    friend std::istream& operator>>(std::istream& is, MonthDayTime& x);
    friend std::ostream& operator<<(std::ostream& os, const MonthDayTime& x);
};

// A Rule specifies one or more set of datetimes without using an offset.
// Multiple dates are specified with multiple years.  The years in effect
// go from starting_year_ to ending_year_, inclusive.  starting_year_ <=
// ending_year_. save_ is ineffect for times from the specified time
// onward, including the specified time. When the specified time is
// local, it uses the save_ from the chronologically previous Rule, or if
// there is none, 0.

class Rule
{
private:
    std::string          name_;
    date::year           starting_year_{0};
    date::year           ending_year_{0};
    MonthDayTime         starting_at_;
    std::chrono::minutes save_{0};
    std::string          abbrev_;

public:
    Rule() = default;
    explicit Rule(const std::string& s);
    Rule(const Rule& r, date::year starting_year, date::year ending_year);

    const std::string& name() const {return name_;}
    const std::string& abbrev() const {return abbrev_;}

    const MonthDayTime&         mdt()           const {return starting_at_;}
    const date::year&           starting_year() const {return starting_year_;}
    const date::year&           ending_year()   const {return ending_year_;}
    const std::chrono::minutes& save()          const {return save_;}

    static void split_overlaps(std::vector<Rule>& rules);

    friend bool operator==(const Rule& x, const Rule& y);
    friend bool operator<(const Rule& x, const Rule& y);
    friend bool operator==(const Rule& x, const date::year& y);
    friend bool operator<(const Rule& x, const date::year& y);
    friend bool operator==(const date::year& x, const Rule& y);
    friend bool operator<(const date::year& x, const Rule& y);
    friend bool operator==(const Rule& x, const std::string& y);
    friend bool operator<(const Rule& x, const std::string& y);
    friend bool operator==(const std::string& x, const Rule& y);
    friend bool operator<(const std::string& x, const Rule& y);

    friend std::ostream& operator<<(std::ostream& os, const Rule& r);

private:
    date::day day() const;
    date::month month() const;
    static void split_overlaps(std::vector<Rule>& rules, std::size_t i, std::size_t& e);
    static bool overlaps(const Rule& x, const Rule& y);
    static void split(std::vector<Rule>& rules, std::size_t i, std::size_t k,
                      std::size_t& e);
};

inline bool operator!=(const Rule& x, const Rule& y) {return !(x == y);}
inline bool operator> (const Rule& x, const Rule& y) {return   y < x;}
inline bool operator<=(const Rule& x, const Rule& y) {return !(y < x);}
inline bool operator>=(const Rule& x, const Rule& y) {return !(x < y);}

inline bool operator!=(const Rule& x, const date::year& y) {return !(x == y);}
inline bool operator> (const Rule& x, const date::year& y) {return   y < x;}
inline bool operator<=(const Rule& x, const date::year& y) {return !(y < x);}
inline bool operator>=(const Rule& x, const date::year& y) {return !(x < y);}

inline bool operator!=(const date::year& x, const Rule& y) {return !(x == y);}
inline bool operator> (const date::year& x, const Rule& y) {return   y < x;}
inline bool operator<=(const date::year& x, const Rule& y) {return !(y < x);}
inline bool operator>=(const date::year& x, const Rule& y) {return !(x < y);}

inline bool operator!=(const Rule& x, const std::string& y) {return !(x == y);}
inline bool operator> (const Rule& x, const std::string& y) {return   y < x;}
inline bool operator<=(const Rule& x, const std::string& y) {return !(y < x);}
inline bool operator>=(const Rule& x, const std::string& y) {return !(x < y);}

inline bool operator!=(const std::string& x, const Rule& y) {return !(x == y);}
inline bool operator> (const std::string& x, const Rule& y) {return   y < x;}
inline bool operator<=(const std::string& x, const Rule& y) {return !(y < x);}
inline bool operator>=(const std::string& x, const Rule& y) {return !(x < y);}

struct time_zone::zonelet
{
    enum tag {has_rule, has_save, is_empty};

    std::chrono::seconds gmtoff_;
    tag tag_ = has_rule;

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    union U
#else
    struct U
#endif
    {
        std::string          rule_;
        std::chrono::minutes save_;

        ~U() {}
        U() {}
        U(const U&) {}
        U& operator=(const U&) = delete;
    } u;

    std::string                        format_;
    date::year                         until_year_{0};
    MonthDayTime                       until_date_;
    sys_seconds                        until_utc_;
    local_seconds                      until_std_;
    local_seconds                      until_loc_;
    std::chrono::minutes               initial_save_{};
    std::string                        initial_abbrev_;
    std::pair<const Rule*, date::year> first_rule_{nullptr, date::year::min()};
    std::pair<const Rule*, date::year> last_rule_{nullptr, date::year::max()};

    ~zonelet();
    zonelet();
    zonelet(const zonelet& i);
    zonelet& operator=(const zonelet&) = delete;
};

}  // namespace date

#endif  // TZ_PRIVATE_H
