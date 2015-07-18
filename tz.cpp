// Howard Hinnant
// This work is licensed under a Creative Commons Attribution 4.0 International License.
// http://creativecommons.org/licenses/by/4.0/

#include "tz_private.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace date
{

// +---------------------+
// | Begin Configuration |
// +---------------------+

static std::string install{"/Users/howardhinnant/Downloads/tzdata2015e"};

static const std::vector<const std::string> files =
{
    "africa", "antarctica", "asia", "australasia", "backward", "etcetera", "europe",
    "pacificnew", "northamerica", "southamerica", "systemv", "leapseconds"
};

// These can be used to reduce the range of the database to save memory
CONSTDATA auto min_year = date::year::min();
CONSTDATA auto max_year = date::year::max();

// Arbitrary day of the year that will be away from any limits.
// Used with year::min() and year::max().
CONSTDATA auto boring_day = date::aug/18;

// +-------------------+
// | End Configuration |
// +-------------------+

static_assert(min_year <= max_year, "Configuration error");
#if __cplusplus >= 201402
static_assert(boring_day.ok(), "Configuration error");
#endif

// Parsing helpers

static
std::string
parse3(std::istream& in)
{
    std::string r(3, ' ');
    ws(in);
    r[0] = static_cast<char>(in.get());
    r[1] = static_cast<char>(in.get());
    r[2] = static_cast<char>(in.get());
    return r;
}

static
unsigned
parse_dow(std::istream& in)
{
    CONSTDATA const char* dow_names[] =
        {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    auto s = parse3(in);
    auto dow = std::find(std::begin(dow_names), std::end(dow_names), s) - dow_names;
    if (dow >= std::end(dow_names) - std::begin(dow_names))
        throw std::runtime_error("oops: bad dow name: " + s);
    return static_cast<unsigned>(dow);
}

static
unsigned
parse_month(std::istream& in)
{
    CONSTDATA const char* month_names[] =
        {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    auto s = parse3(in);
    auto m = std::find(std::begin(month_names), std::end(month_names), s) - month_names;
    if (m >= std::end(month_names) - std::begin(month_names))
        throw std::runtime_error("oops: bad month name: " + s);
    return static_cast<unsigned>(++m);
}

static
std::chrono::seconds
parse_unsigned_time(std::istream& in)
{
    using namespace std::chrono;
    int x;
    in >> x;
    auto r = seconds{hours{x}};
    if (!in.eof() && in.peek() == ':')
    {
        in.get();
        in >> x;
        r += minutes{x};
        if (!in.eof() && in.peek() == ':')
        {
            in.get();
            in >> x;
            r += seconds{x};
        }
    }
    return r;
}

static
std::chrono::seconds
parse_signed_time(std::istream& in)
{
    ws(in);
    auto sign = 1;
    if (in.peek() == '-')
    {
        sign = -1;
        in.get();
    }
    else if (in.peek() == '+')
        in.get();
    return sign * parse_unsigned_time(in);
}

// MonthDayTime

MonthDayTime::MonthDayTime(seconds_point tp, tz timezone)
    : zone_(timezone)
{
    using namespace date;
    const auto dp = floor<days>(tp);
    const auto hms = make_time(tp - dp);
    const auto ymd = year_month_day(dp);
    u = ymd.month() / ymd.day();
    h_ = hms.hours();
    m_ = hms.minutes();
    s_ = hms.seconds();
}

MonthDayTime::MonthDayTime(const date::month_day& md, tz timezone)
    : zone_(timezone)
{
    u = md;
}

date::day
MonthDayTime::day() const
{
    switch (type_)
    {
    case month_day:
        return u.month_day_.day();
    case month_last_dow:
        return date::day{31};
    case lteq:
    case gteq:
        return u.month_day_weekday_.month_day_.day();
    }
}

date::month
MonthDayTime::month() const
{
    switch (type_)
    {
    case month_day:
        return u.month_day_.month();
    case month_last_dow:
        return u.month_weekday_last_.month();
    case lteq:
    case gteq:
        return u.month_day_weekday_.month_day_.month();
    }
}

int
MonthDayTime::compare(date::year y, const MonthDayTime& x, date::year yx,
                      std::chrono::seconds offset, std::chrono::minutes prev_save) const
{
    if (zone_ != x.zone_)
    {
        auto dp0 = to_day_point(y);
        auto dp1 = x.to_day_point(yx);
        if (std::abs((dp0-dp1).count()) > 1)
            return dp0 < dp1 ? -1 : 1;
        if (zone_ == tz::local)
        {
            auto tp0 = to_time_point(y) - prev_save;
            if (x.zone_ == tz::utc)
                tp0 -= offset;
            auto tp1 = x.to_time_point(yx);
            return tp0 < tp1 ? -1 : tp0 == tp1 ? 0 : 1;
        }
        else if (zone_ == tz::standard)
        {
            auto tp0 = to_time_point(y);
            auto tp1 = x.to_time_point(yx);
            if (x.zone_ == tz::local)
                tp1 -= prev_save;
            else
                tp0 -= offset;
            return tp0 < tp1 ? -1 : tp0 == tp1 ? 0 : 1;
        }
        // zone_ == tz::utc
        auto tp0 = to_time_point(y);
        auto tp1 = x.to_time_point(yx);
        if (x.zone_ == tz::local)
            tp1 -= offset + prev_save;
        else
            tp1 -= offset;
        return tp0 < tp1 ? -1 : tp0 == tp1 ? 0 : 1;
    }
    auto const t0 = to_time_point(y);
    auto const t1 = x.to_time_point(yx);
    return t0 < t1 ? -1 : t0 == t1 ? 0 : 1;
}

seconds_point
MonthDayTime::to_sys(date::year y, std::chrono::seconds offset,
                     std::chrono::seconds save) const
{
    using namespace date;
    using namespace std::chrono;
    auto until_utc = to_time_point(y);
    if (zone_ == tz::standard)
        until_utc -= offset;
    else if (zone_ == tz::local)
        until_utc -= offset + save;
    return until_utc;
}

MonthDayTime::U&
MonthDayTime::U::operator=(const date::month_day& x)
{
    month_day_ = x;
    return *this;
}

MonthDayTime::U&
MonthDayTime::U::operator=(const date::month_weekday_last& x)
{
    month_weekday_last_ = x;
    return *this;
}

MonthDayTime::U&
MonthDayTime::U::operator=(const pair& x)
{
    month_day_weekday_ = x;
    return *this;
}

date::day_point
MonthDayTime::to_day_point(date::year y) const
{
    using namespace std::chrono;
    using namespace date;
    switch (type_)
    {
    case month_day:
        return day_point(y/u.month_day_);
    case month_last_dow:
        return day_point(y/u.month_weekday_last_);
    case lteq:
        {
            auto const x = y/u.month_day_weekday_.month_day_;
            auto const wd1 = weekday(x);
            auto const wd0 = u.month_day_weekday_.weekday_;
            return day_point(x) - (wd1-wd0);
        }
    case gteq:
        {
            auto const x = y/u.month_day_weekday_.month_day_;
            auto const wd1 = u.month_day_weekday_.weekday_;
            auto const wd0 = weekday(x);
            return day_point(x) + (wd1-wd0);
        }
    }
}

seconds_point
MonthDayTime::to_time_point(date::year y) const
{
    return to_day_point(y) + h_ + m_ + s_;
}

void
MonthDayTime::canonicalize(date::year y)
{
    using namespace std::chrono;
    using namespace date;
    switch (type_)
    {
    case month_day:
        return;
    case month_last_dow:
        {
            auto const ymd = year_month_day(y/u.month_weekday_last_);
            u.month_day_ = ymd.month()/ymd.day();
            type_ = month_day;
            return;
        }
    case lteq:
        {
            auto const x = y/u.month_day_weekday_.month_day_;
            auto const wd1 = weekday(x);
            auto const wd0 = u.month_day_weekday_.weekday_;
            auto const ymd = year_month_day(day_point(x) - (wd1-wd0));
            u.month_day_ = ymd.month()/ymd.day();
            type_ = month_day;
            return;
        }
    case gteq:
        {
            auto const x = y/u.month_day_weekday_.month_day_;
            auto const wd1 = u.month_day_weekday_.weekday_;
            auto const wd0 = weekday(x);
            auto const ymd = year_month_day(day_point(x) + (wd1-wd0));
            u.month_day_ = ymd.month()/ymd.day();
            type_ = month_day;
            return;
        }
    }
}

std::istream&
operator>>(std::istream& is, MonthDayTime& x)
{
    using namespace date;
    using namespace std::chrono;
    x = MonthDayTime{};
    if (!is.eof() && ws(is) && !is.eof() && is.peek() != '#')
    {
        auto m = parse_month(is);
        if (!is.eof() && ws(is) && !is.eof() && is.peek() != '#')
        {
            if (is.peek() == 'l')
            {
                for (int i = 0; i < 4; ++i)
                    is.get();
                auto dow = parse_dow(is);
                x.type_ = MonthDayTime::month_last_dow;
                x.u = date::month(m)/weekday(dow)[last];
            }
            else if (std::isalpha(is.peek()))
            {
                auto dow = parse_dow(is);
                char c;
                is >> c;
                if (c == '<' || c == '>')
                {
                    char c2;
                    is >> c2;
                    if (c2 != '=')
                        throw std::runtime_error(std::string("bad operator: ") + c + c2);
                    int d;
                    is >> d;
                    if (d < 1 || d > 31)
                        throw std::runtime_error(std::string("bad operator: ") + c + c2
                                 + std::to_string(d));
                    x.type_ = c == '<' ? MonthDayTime::lteq : MonthDayTime::gteq;
                    x.u = {date::month(m)/d, weekday(dow)};
                }
                else
                    throw std::runtime_error(std::string("bad operator: ") + c);
            }
            else  // if (std::isdigit(is.peek())
            {
                int d;
                is >> d;
                if (d < 1 || d > 31)
                    throw std::runtime_error(std::string("day of month: ")
                             + std::to_string(d));
                x.type_ = MonthDayTime::month_day;
                x.u = date::month(m)/d;
            }
            if (!is.eof() && ws(is) && !is.eof() && is.peek() != '#')
            {
                int t;
                is >> t;
                x.h_ = hours{t};
                if (!is.eof() && is.peek() == ':')
                {
                    is.get();
                    is >> t;
                    x.m_ = minutes{t};
                    if (!is.eof() && is.peek() == ':')
                    {
                        is.get();
                        is >> t;
                        x.s_ = seconds{t};
                    }
                }
                if (!is.eof() && std::isalpha(is.peek()))
                {
                    char c;
                    is >> c;
                    switch (c)
                    {
                    case 's':
                        x.zone_ = tz::standard;
                        break;
                    case 'u':
                        x.zone_ = tz::utc;
                        break;
                    }
                }
            }
        }
        else
        {
            x.u = month{m}/1;
        }
    }
    return is;
}

std::ostream&
operator<<(std::ostream& os, const MonthDayTime& x)
{
    switch (x.type_)
    {
    case MonthDayTime::month_day:
        os << x.u.month_day_ << "                  ";
        break;
    case MonthDayTime::month_last_dow:
        os << x.u.month_weekday_last_ << "           ";
        break;
    case MonthDayTime::lteq:
        os << x.u.month_day_weekday_.weekday_ << " on or before "
           << x.u.month_day_weekday_.month_day_ << "  ";
        break;
    case MonthDayTime::gteq:
        if ((static_cast<unsigned>(x.day()) - 1) % 7 == 0)
        {
            os << (x.u.month_day_weekday_.month_day_.month() /
                   x.u.month_day_weekday_.weekday_[
                       (static_cast<unsigned>(x.day()) - 1)/7+1]) << "              ";
        }
        else
        {
            os << x.u.month_day_weekday_.weekday_ << " on or after "
               << x.u.month_day_weekday_.month_day_ << "  ";
        }
        break;
    }
    os << date::make_time(x.h_ + x.m_ + x.s_);
    if (x.zone_ == tz::utc)
        os << "UTC   ";
    else if (x.zone_ == tz::standard)
        os << "STD   ";
    else
        os << "      ";
    return os;
}

// Rule

Rule::Rule(const std::string& s)
{
    try
    {
        using namespace date;
        using namespace std::chrono;
        std::istringstream in(s);
        in.exceptions(std::ios::failbit | std::ios::badbit);
        std::string word;
        in >> word >> name_;
        int x;
        ws(in);
        if (std::isalpha(in.peek()))
        {
            in >> word;
            if (word == "min")
            {
                starting_year_ = year::min();
            }
            else
                throw std::runtime_error("Didn't find expected word: " + word);
        }
        else
        {
            in >> x;
            starting_year_ = year{x};
        }
        std::ws(in);
        if (std::isalpha(in.peek()))
        {
            in >> word;
            if (word == "only")
            {
                ending_year_ = starting_year_;
            }
            else if (word == "max")
            {
                ending_year_ = year::max();
            }
            else
                throw std::runtime_error("Didn't find expected word: " + word);
        }
        else
        {
            in >> x;
            ending_year_ = year{x};
        }
        in >> word;  // TYPE (always "-")
        assert(word == "-");
        in >> starting_at_;
        save_ = duration_cast<minutes>(parse_signed_time(in));
        in >> abbrev_;
        if (abbrev_ == "-")
            abbrev_.clear();
        assert(hours{0} <= save_ && save_ <= hours{2});
    }
    catch (...)
    {
        std::cerr << s << '\n';
        std::cerr << *this << '\n';
        throw;
    }
}

Rule::Rule(const Rule& r, date::year starting_year, date::year ending_year)
    : name_(r.name_)
    , starting_year_(starting_year)
    , ending_year_(ending_year)
    , starting_at_(r.starting_at_)
    , save_(r.save_)
    , abbrev_(r.abbrev_)
{
}

bool
operator==(const Rule& x, const Rule& y)
{
    if (std::tie(x.name_, x.save_, x.starting_year_, x.ending_year_) ==
        std::tie(y.name_, y.save_, y.starting_year_, y.ending_year_))
        return x.month() == y.month() && x.day() == y.day();
    return false;
}

bool
operator<(const Rule& x, const Rule& y)
{
    using namespace std::chrono;
    auto const xm = x.month();
    auto const ym = y.month();
    if (std::tie(x.name_, x.starting_year_, xm, x.ending_year_) <
        std::tie(y.name_, y.starting_year_, ym, y.ending_year_))
        return true;
    if (std::tie(x.name_, x.starting_year_, xm, x.ending_year_) >
        std::tie(y.name_, y.starting_year_, ym, y.ending_year_))
        return false;
    return x.day() < y.day();
}

bool
operator==(const Rule& x, const date::year& y)
{
    return x.starting_year_ <= y && y <= x.ending_year_;
}

bool
operator<(const Rule& x, const date::year& y)
{
    return x.ending_year_ < y;
}

bool
operator==(const date::year& x, const Rule& y)
{
    return y.starting_year_ <= x && x <= y.ending_year_;
}

bool
operator<(const date::year& x, const Rule& y)
{
    return x < y.starting_year_;
}

bool
operator==(const Rule& x, const std::string& y)
{
    return x.name() == y;
}

bool
operator<(const Rule& x, const std::string& y)
{
    return x.name() < y;
}

bool
operator==(const std::string& x, const Rule& y)
{
    return y.name() == x;
}

bool
operator<(const std::string& x, const Rule& y)
{
    return x < y.name();
}

std::ostream&
operator<<(std::ostream& os, const Rule& r)
{
    using namespace date;
    using namespace std::chrono;
    save_stream _(os);
    os.fill(' ');
    os.flags(std::ios::dec | std::ios::left);
    os.width(15);
    os << r.name_;
    os << r.starting_year_ << "    " << r.ending_year_ << "    ";
    os << r.starting_at_;
    if (r.save_ >= minutes{0})
        os << ' ';
    os << date::make_time(r.save_) << "   ";
    os << r.abbrev_;
    return os;
}

date::day
Rule::day() const
{
    return starting_at_.day();
}

date::month
Rule::month() const
{
    return starting_at_.month();
}

struct find_rule_by_name
{
    bool operator()(const Rule& x, const std::string& nm) const
    {
        return x.name() < nm;
    }

    bool operator()(const std::string& nm, const Rule& x) const
    {
        return nm < x.name();
    }
};

bool
Rule::overlaps(const Rule& x, const Rule& y)
{
    // assume x.starting_year_ <= y.starting_year_;
    if (!(x.starting_year_ <= y.starting_year_))
    {
        std::cerr << x << '\n';
        std::cerr << y << '\n';
        assert(x.starting_year_ <= y.starting_year_);
    }
    if (y.starting_year_ > x.ending_year_)
        return false;
    return !(x.starting_year_ == y.starting_year_ && x.ending_year_ == y.ending_year_);
}

void
Rule::split(std::vector<Rule>& rules, std::size_t i, std::size_t k, std::size_t& e)
{
    using namespace date;
    using difference_type = std::vector<Rule>::iterator::difference_type;
    // rules[i].starting_year_ <= rules[k].starting_year_ &&
    //     rules[i].ending_year_ >= rules[k].starting_year_ &&
    //     (rules[i].starting_year_ != rules[k].starting_year_ ||
    //      rules[i].ending_year_ != rules[k].ending_year_)
    assert(rules[i].starting_year_ <= rules[k].starting_year_ &&
           rules[i].ending_year_ >= rules[k].starting_year_ &&
           (rules[i].starting_year_ != rules[k].starting_year_ ||
            rules[i].ending_year_ != rules[k].ending_year_));
    if (rules[i].starting_year_ == rules[k].starting_year_)
    {
        if (rules[k].ending_year_ < rules[i].ending_year_)
        {
            rules.insert(rules.begin() + static_cast<difference_type>(k+1),
                         Rule(rules[i], rules[k].ending_year_ + years{1},
                              std::move(rules[i].ending_year_)));
            ++e;
            rules[i].ending_year_ = rules[k].ending_year_;
        }
        else  // rules[k].ending_year_ > rules[i].ending_year_
        {
            rules.insert(rules.begin() + static_cast<difference_type>(k+1),
                         Rule(rules[k], rules[i].ending_year_ + years{1},
                              std::move(rules[k].ending_year_)));
            ++e;
            rules[k].ending_year_ = rules[i].ending_year_;
        }
    }
    else  // rules[i].starting_year_ < rules[k].starting_year_
    {
        if (rules[k].ending_year_ < rules[i].ending_year_)
        {
            rules.insert(rules.begin() + static_cast<difference_type>(k),
                         Rule(rules[i], rules[k].starting_year_, rules[k].ending_year_));
            ++k;
            rules.insert(rules.begin() + static_cast<difference_type>(k+1),
                         Rule(rules[i], rules[k].ending_year_ + years{1},
                              std::move(rules[i].ending_year_)));
            rules[i].ending_year_ = rules[k].starting_year_ - years{1};
            e += 2;
        }
        else if (rules[k].ending_year_ > rules[i].ending_year_)
        {
            rules.insert(rules.begin() + static_cast<difference_type>(k),
                         Rule(rules[i], rules[k].starting_year_, rules[i].ending_year_));
            ++k;
            rules.insert(rules.begin() + static_cast<difference_type>(k+1),
                         Rule(rules[k], rules[i].ending_year_ + years{1},
                         std::move(rules[k].ending_year_)));
            e += 2;
            rules[k].ending_year_ = std::move(rules[i].ending_year_);
            rules[i].ending_year_ = rules[k].starting_year_ - years{1};
        }
        else  // rules[k].ending_year_ == rules[i].ending_year_
        {
            rules.insert(rules.begin() + static_cast<difference_type>(k),
                         Rule(rules[i], rules[k].starting_year_,
                         std::move(rules[i].ending_year_)));
            ++k;
            ++e;
            rules[i].ending_year_ = rules[k].starting_year_ - years{1};
        }
    }
}

void
Rule::split_overlaps(std::vector<Rule>& rules, std::size_t i, std::size_t& e)
{
    using difference_type = std::vector<Rule>::iterator::difference_type;
    auto j = i;
    for (; i + 1 < e; ++i)
    {
        for (auto k = i + 1; k < e; ++k)
        {
            if (overlaps(rules[i], rules[k]))
            {
                split(rules, i, k, e);
                std::sort(rules.begin() + static_cast<difference_type>(i),
                          rules.begin() + static_cast<difference_type>(e));
            }
        }
    }
    for (; j < e; ++j)
    {
        if (rules[j].starting_year() == rules[j].ending_year())
            rules[j].starting_at_.canonicalize(rules[j].starting_year());
    }
}

void
Rule::split_overlaps(std::vector<Rule>& rules)
{
    using difference_type = std::vector<Rule>::iterator::difference_type;
    for (std::size_t i = 0; i < rules.size();)
    {
        auto e = static_cast<std::size_t>(std::upper_bound(
            rules.cbegin()+static_cast<difference_type>(i), rules.cend(), rules[i].name(),
            [](const std::string& nm, const Rule& x)
            {
                return nm < x.name();
            }) - rules.cbegin());
        split_overlaps(rules, i, e);
        auto first = rules.cbegin() + static_cast<difference_type>(i);
        auto last = rules.cbegin() + static_cast<difference_type>(e);
        auto t = std::lower_bound(first, last, min_year);
        if (t > first+1)
        {
            if (t == last || t->starting_year() >= min_year)
                --t;
            auto d = static_cast<std::size_t>(t - first);
            rules.erase(first, t);
            e -= d;
        }
        first = rules.cbegin() + static_cast<difference_type>(i);
        last = rules.cbegin() + static_cast<difference_type>(e);
        t = std::upper_bound(first, last, max_year);
        if (t != last)
        {
            auto d = static_cast<std::size_t>(last - t);
            rules.erase(t, last);
            e -= d;
        }
        i = e;
    }
    rules.shrink_to_fit();
}

// Zone

Zone::zonelet::~zonelet()
{
    if (tag_ == has_save)
        u.save_.~decltype(u.save_)();
    else
        u.rule_.~decltype(u.rule_)();
}

Zone::zonelet::zonelet()
{
    ::new(&u.rule_) std::string();
}

Zone::zonelet::zonelet(const zonelet& i)
    : gmtoff_(i.gmtoff_)
    , tag_(i.tag_)
    , format_(i.format_)
    , until_year_(i.until_year_)
    , until_date_(i.until_date_)
    , until_utc_(i.until_utc_)
    , until_std_(i.until_std_)
    , until_loc_(i.until_loc_)
    , initial_save_(i.initial_save_)
    , initial_abbrev_(i.initial_abbrev_)
    , first_rule_(i.first_rule_)
    , last_rule_(i.last_rule_)
{
    if (tag_ == has_save)
        ::new(&u.save_) std::chrono::minutes(i.u.save_);
    else
        ::new(&u.rule_) std::string(i.u.rule_);
}

Zone::Zone(const std::string& s)
{
    try
    {
        using namespace date;
        std::istringstream in(s);
        in.exceptions(std::ios::failbit | std::ios::badbit);
        std::string word;
        in >> word >> name_;
        parse_info(in);
    }
    catch (...)
    {
        std::cerr << s << '\n';
        std::cerr << *this << '\n';
        zonelets_.pop_back();
        throw;
    }
}

void
Zone::add(const std::string& s)
{
    try
    {
        std::istringstream in(s);
        in.exceptions(std::ios::failbit | std::ios::badbit);
        ws(in);
        if (!in.eof() && in.peek() != '#')
            parse_info(in);
    }
    catch (...)
    {
        std::cerr << s << '\n';
        std::cerr << *this << '\n';
        zonelets_.pop_back();
        throw;
    }
}

void
Zone::parse_info(std::istream& in)
{
    using namespace date;
    using namespace std::chrono;
    zonelets_.emplace_back();
    auto& zonelet = zonelets_.back();
    zonelet.gmtoff_ = parse_signed_time(in);
    in >> zonelet.u.rule_;
    if (zonelet.u.rule_ == "-")
        zonelet.u.rule_.clear();
    in >> zonelet.format_;
    if (!in.eof())
        ws(in);
    if (in.eof() || in.peek() == '#')
    {
        zonelet.until_year_ = year::max();
        zonelet.until_date_ = MonthDayTime(boring_day, tz::utc);
    }
    else
    {
        int y;
        in >> y;
        zonelet.until_year_ = year{y};
        in >> zonelet.until_date_;
        zonelet.until_date_.canonicalize(zonelet.until_year_);
    }
    if ((zonelet.until_year_ < min_year) ||
            (zonelets_.size() > 1 && zonelets_.end()[-2].until_year_ > max_year))
        zonelets_.pop_back();
}

// Find the rule that comes chronologically before Rule r.  For multi-year rules,
// y specifies which rules in r.  For single year rules, y is assumed to be equal
// to the year specified by r.
// Returns a pointer to the chronologically previous rule, and the year within
// that rule.  If there is no previous rule, returns nullptr and year::min().
// Preconditions:
//     r->starting_year() <= y && y <= r->ending_year()
static
std::pair<const Rule*, date::year>
find_previous_rule(const Rule* r, date::year y)
{
    using namespace date;
    auto const& rules = get_tzdb().rules;
    if (y == r->starting_year())
    {
        if (r == &rules.front() || r->name() != r[-1].name())
            return {nullptr, year::min()};
        --r;
        if (y == r->starting_year())
            return {r, y};
        return {r, r->ending_year()};
    }
    if (r == &rules.front() || r->name() != r[-1].name() ||
        r[-1].starting_year() < r->starting_year())
    {
        while (r < &rules.back() && r->name() == r[1].name() &&
               r->starting_year() == r[1].starting_year())
            ++r;
        return {r, --y};
    }
    --r;
    return {r, y};
}

// Find the rule that comes chronologically after Rule r.  For multi-year rules,
// y specifies which rules in r.  For single year rules, y is assumed to be equal
// to the year specified by r.
// Returns a pointer to the chronologically next rule, and the year within
// that rule.  If there is no next rule, return a pointer to a defaulted rule
// and y+1.
// Preconditions:
//     first <= r && r < last && r->starting_year() <= y && y <= r->ending_year()
//     [first, last) all have the same name
static
std::pair<const Rule*, date::year>
find_next_rule(const Rule* first, const Rule* last, const Rule* r, date::year y)
{
    using namespace date;
    if (y == r->ending_year())
    {
        if (r == last-1)
            return {nullptr, year::max()};
        ++r;
        if (y == r->ending_year())
            return {r, y};
        return {r, r->starting_year()};
    }
    if (r == last-1 || r->ending_year() < r[1].ending_year())
    {
        while (r > first && r->starting_year() == r[-1].starting_year())
            --r;
        return {r, ++y};
    }
    ++r;
    return {r, y};
}

// Find the rule that comes chronologically after Rule r.  For multi-year rules,
// y specifies which rules in r.  For single year rules, y is assumed to be equal
// to the year specified by r.
// Returns a pointer to the chronologically next rule, and the year within
// that rule.  If there is no next rule, return nullptr and year::max().
// Preconditions:
//     r->starting_year() <= y && y <= r->ending_year()
static
std::pair<const Rule*, date::year>
find_next_rule(const Rule* r, date::year y)
{
    using namespace date;
    auto const& rules = get_tzdb().rules;
    if (y == r->ending_year())
    {
        if (r == &rules.back() || r->name() != r[1].name())
            return {nullptr, year::max()};
        ++r;
        if (y == r->ending_year())
            return {r, y};
        return {r, r->starting_year()};
    }
    if (r == &rules.back() || r->name() != r[1].name() ||
        r->ending_year() < r[1].ending_year())
    {
        while (r > &rules.front() && r->name() == r[-1].name() &&
               r->starting_year() == r[-1].starting_year())
            --r;
        return {r, ++y};
    }
    ++r;
    return {r, y};
}

static
std::pair<const Rule*, date::year>
find_rule_for_zone(const std::pair<const Rule*, const Rule*>& eqr,
                   const date::year& y, const std::chrono::seconds& offset,
                   const MonthDayTime& mdt)
{
    using namespace std::chrono;
    using namespace date;
    auto r = eqr.first;
    auto ry = r->starting_year();
    auto prev_save = minutes{0};
    auto prev_year = year::min();
    const Rule* prev_rule = nullptr;
    while (r != nullptr)
    {
        if (mdt.compare(y, r->mdt(), ry, offset, prev_save) <= 0)
            break;
        prev_rule = r;
        prev_year = ry;
        prev_save = prev_rule->save();
        std::tie(r, ry) = find_next_rule(eqr.first, eqr.second, r, ry);
    }
    return {prev_rule, prev_year};
}

static
std::pair<const Rule*, date::year>
find_rule_for_zone(const std::pair<const Rule*, const Rule*>& eqr,
                   const seconds_point& tp_utc, const seconds_point& tp_std,
                   const seconds_point& tp_loc)
{
    using namespace std::chrono;
    using namespace date;
    auto r = eqr.first;
    auto ry = r->starting_year();
    auto prev_save = minutes{0};
    auto prev_year = year::min();
    const Rule* prev_rule = nullptr;
    while (r != nullptr)
    {
        bool found;
        switch (r->mdt().zone())
        {
        case tz::utc:
            found = tp_utc < r->mdt().to_time_point(ry);
            break;
        case tz::standard:
            found = tp_std < r->mdt().to_time_point(ry);
            break;
        case tz::local:
            found = tp_loc < r->mdt().to_time_point(ry);
            break;
        default:
            assert(false);
        }
        if (found)
            break;
        prev_rule = r;
        prev_year = ry;
        prev_save = prev_rule->save();
        std::tie(r, ry) = find_next_rule(eqr.first, eqr.second, r, ry);
    }
    return {prev_rule, prev_year};
}

static
Info
find_rule(const std::pair<const Rule*, date::year>& first,
          const std::pair<const Rule*, date::year>& last,
          const date::year& y, const std::chrono::seconds& offset,
          const MonthDayTime& mdt, const std::chrono::minutes& initial_save,
          const std::string& initial_abbrev)
{
    using namespace std::chrono;
    using namespace date;
    auto r = first.first;
    auto ry = first.second;
    Info x{day_point(year::min()/boring_day), day_point(year::max()/boring_day),
           seconds{0}, initial_save, initial_abbrev};
    while (r != nullptr)
    {
        auto tr = r->mdt().to_sys(ry, offset, x.save);
        auto tx = mdt.to_sys(y, offset, x.save);
        // Find last rule where tx >= tr
        if (tx <= tr || (r == last.first && ry == last.second))
        {
            if (tx < tr && r == first.first && ry == first.second)
            {
                x.end = r->mdt().to_sys(ry, offset, x.save);
                break;
            }
            if (tx < tr)
            {
                std::tie(r, ry) = find_previous_rule(r, ry);  // can't return nullptr for r
                assert(r != nullptr);
            }
            // r != nullptr && tx >= tr (if tr were to be recomputed)
            auto prev_save = initial_save;
            if (!(r == first.first && ry == first.second))
                prev_save = find_previous_rule(r, ry).first->save();
            x.begin = r->mdt().to_sys(ry, offset, prev_save);
            x.save = r->save();
            x.abbrev = r->abbrev();
            if (!(r == last.first && ry == last.second))
            {
                std::tie(r, ry) = find_next_rule(r, ry);  // can't return nullptr for r
                assert(r != nullptr);
                x.end = r->mdt().to_sys(ry, offset, x.save);
            }
            else
                x.end = day_point(year::max()/boring_day);
            break;
        }
        x.save = r->save();
        std::tie(r, ry) = find_next_rule(r, ry);  // Can't return nullptr for r
        assert(r != nullptr);
    }
    return x;
}

void
Zone::adjust_infos(const std::vector<Rule>& rules)
{
    using namespace std::chrono;
    using namespace date;
    const zonelet* prev_zonelet = nullptr;
    for (auto& z : zonelets_)
    {
        // Classify info as rule-based, has save, or neither
        if (!z.u.rule_.empty())
        {
            // Find out if this zonelet has a rule or a save
            auto i = std::lower_bound(rules.begin(), rules.end(), z.u.rule_,
                [](const Rule& r, const std::string& nm)
                {
                    return r.name() < nm;
                });
            if (i == rules.end() || i->name() != z.u.rule_)
            {
                // The rule doesn't exist.  Assume this is a save
                try
                {
                    using namespace std::chrono;
                    std::istringstream in(z.u.rule_);
                    in.exceptions(std::ios::failbit | std::ios::badbit);
                    auto tmp = duration_cast<minutes>(parse_signed_time(in));
                    z.u.rule_.~decltype(z.u.rule_)();
                    z.tag_ = zonelet::has_save;
                    ::new(&z.u.save_) minutes(tmp);
                }
                catch (...)
                {
                    std::cerr << name_ << " : " << z.u.rule_ << '\n';
                    throw;
                }
            }
        }
        else
        {
            // This zone::zonelet has no rule and no save
            z.tag_ = zonelet::is_empty;
        }

        std::pair<const Rule*, const Rule*> eqr{};
        if (z.tag_ == zonelet::has_rule)
        {
            eqr = std::equal_range(rules.data(), rules.data() + rules.size(), z.u.rule_);
            assert(eqr.first != eqr.second);
        }

        minutes final_save{0};
        if (z.tag_ == zonelet::has_save)
        {
            final_save = z.u.save_;
        }
        else if (z.tag_ == zonelet::has_rule)
        {
            z.last_rule_ = find_rule_for_zone(eqr, z.until_year_, z.gmtoff_,
                                              z.until_date_);
            if (z.last_rule_.first != nullptr)
                final_save = z.last_rule_.first->save();
        }
        z.until_utc_ = z.until_date_.to_sys(z.until_year_, z.gmtoff_, final_save);
        z.until_std_ = z.until_utc_ + z.gmtoff_;
        z.until_loc_ = z.until_std_ + final_save;

        if (z.tag_ == zonelet::has_rule)
        {
            if (prev_zonelet != nullptr)
            {
                z.first_rule_ = find_rule_for_zone(eqr, prev_zonelet->until_utc_,
                                                        prev_zonelet->until_std_,
                                                        prev_zonelet->until_loc_);
                if (z.first_rule_.first != nullptr)
                {
                    z.initial_save_ = z.first_rule_.first->save();
                    z.initial_abbrev_ = z.first_rule_.first->abbrev();
                    if (z.first_rule_ != z.last_rule_)
                    {
                        z.first_rule_ = find_next_rule(eqr.first, eqr.second,
                                                       z.first_rule_.first,
                                                       z.first_rule_.second);
                    }
                    else
                    {
                        z.first_rule_ = std::make_pair(nullptr, year::min());
                        z.last_rule_ = std::make_pair(nullptr, year::max());
                    }
                }
            }
            if (z.first_rule_.first == nullptr && z.last_rule_.first != nullptr)
                z.first_rule_ = std::make_pair(eqr.first, eqr.first->starting_year());
        }

#ifndef NDEBUG
        if (z.first_rule_.first == nullptr)
        {
            assert(z.first_rule_.second == year::min());
            assert(z.last_rule_.first == nullptr);
            assert(z.last_rule_.second == year::max());
        }
        else
        {
            assert(z.last_rule_.first != nullptr);
        }
#endif
        prev_zonelet = &z;
    }
}

Info
Zone::get_info(std::chrono::system_clock::time_point tp, tz timezone) const
{
    using namespace std::chrono;
    using namespace date;
    assert(timezone != tz::standard);
    auto y = year_month_day(floor<days>(tp)).year();
    if (y < min_year || y > max_year)
        throw std::runtime_error("The year " + std::to_string(static_cast<int>(y)) +
            " is out of range:[" + std::to_string(static_cast<int>(min_year)) + ", "
                                 + std::to_string(static_cast<int>(max_year)) + "]");
    auto i = std::upper_bound(zonelets_.begin(), zonelets_.end(), tp,
        [timezone](std::chrono::system_clock::time_point t, const zonelet& zl)
        {
            return timezone == tz::utc ? t < zl.until_utc_ : t < zl.until_loc_;
        });
    
    Info r{};
    if (i != zonelets_.end())
    {
        if (i->tag_ == zonelet::has_save)
        {
            r.begin = i != zonelets_.begin() ? i[-1].until_utc_
                                             : day_point(year::min()/boring_day);
            r.end = i->until_utc_;
            r.offset = i->gmtoff_ + i->u.save_;
            r.save = i->u.save_;
            r.abbrev = i->format_;
        }
        else if (i->u.rule_.empty())
        {
            r.begin = i != zonelets_.begin() ? i[-1].until_utc_
                                             : day_point(year::min()/boring_day);
            r.end = i->until_utc_;
            r.offset = i->gmtoff_;
            r.abbrev = i->format_;
        }
        else
        {
            r = find_rule(i->first_rule_, i->last_rule_, y, i->gmtoff_,
                          MonthDayTime(floor<seconds>(tp), timezone), i->initial_save_,
                          i->initial_abbrev_);
            auto k = i->format_.find("%s");
            if (k != std::string::npos)
            {
                std::string abbrev = r.abbrev;
                r.abbrev = i->format_;
                r.abbrev.replace(k, 2, abbrev);
            }
            else
            {
                k = i->format_.find('/');
                if (k != std::string::npos)
                {
                    if (r.save == seconds{0})
                        r.abbrev = i->format_.substr(0, k);
                    else
                        r.abbrev = i->format_.substr(k+1);
                }
                else
                {
                    r.abbrev = i->format_;
                }
            }
            r.offset = i->gmtoff_ + r.save;
            if (i != zonelets_.begin() && r.begin < i[-1].until_utc_)
                r.begin = i[-1].until_utc_;
            if (r.end > i->until_utc_)
                r.end = i->until_utc_;
        }
        assert(r.begin < r.end);
    }
    return r;
}

std::ostream&
operator<<(std::ostream& os, const Zone& z)
{
    using namespace date;
    using namespace std::chrono;
    save_stream _(os);
    os.fill(' ');
    os.flags(std::ios::dec | std::ios::left);
    os.width(35);
    os << z.name_;
    std::string indent;
    for (auto const& s : z.zonelets_)
    {
        os << indent;
        if (s.gmtoff_ >= seconds{0})
            os << ' ';
        os << make_time(s.gmtoff_) << "   ";
        os.width(15);
        if (s.tag_ != Zone::zonelet::has_save)
            os << s.u.rule_;
        else
        {
            std::ostringstream tmp;
            tmp << make_time(s.u.save_);
            os <<  tmp.str();
        }
        os.width(8);
        os << s.format_ << "   ";
        os << s.until_year_ << ' ' << s.until_date_;
        os << "   " << s.until_utc_ << " UTC";
        os << "   " << s.until_std_ << " STD";
        os << "   " << s.until_loc_;
        os << "   " << make_time(s.initial_save_);
        os << "   " << s.initial_abbrev_;
        if (s.first_rule_.first != nullptr)
            os << "   {" << *s.first_rule_.first << ", " << s.first_rule_.second << '}';
        else
            os << "   {" << "nullptr" << ", " << s.first_rule_.second << '}';
        if (s.last_rule_.first != nullptr)
            os << "   {" << *s.last_rule_.first << ", " << s.last_rule_.second << '}';
        else
            os << "   {" << "nullptr" << ", " << s.last_rule_.second << '}';
        os << '\n';
        if (indent.empty())
            indent = std::string(35, ' ');
    }
    return os;
}

// Link

Link::Link(const std::string& s)
{
    using namespace date;
    std::istringstream in(s);
    in.exceptions(std::ios::failbit | std::ios::badbit);
    std::string word;
    in >> word >> target_ >> name_;
}

std::ostream&
operator<<(std::ostream& os, const Link& x)
{
    using namespace date;
    save_stream _(os);
    os.fill(' ');
    os.flags(std::ios::dec | std::ios::left);
    os.width(35);
    return os << x.name_ << " --> " << x.target_;
}

// Leap

Leap::Leap(const std::string& s)
{
    using namespace date;
    std::istringstream in(s);
    in.exceptions(std::ios::failbit | std::ios::badbit);
    std::string word;
    int y;
    MonthDayTime date;
    in >> word >> y >> date;
    date_ = date.to_time_point(year(y));
}

std::ostream&
operator<<(std::ostream& os, const Leap& x)
{
    using namespace date;
    return os << x.date_ << "  +";
}

static
TZ_DB
init_tzdb()
{
    using namespace date;
    const std::string path = install + "/";
    std::string line;
    bool continue_zone = false;
    TZ_DB db;
    for (const auto& filename : files)
    {
        std::ifstream infile(path + filename);
        while (infile)
        {
            std::getline(infile, line);
            if (!line.empty() && line[0] != '#')
            {
                std::istringstream in(line);
                std::string word;
                in >> word;
                if (word == "Rule")
                {
                    db.rules.push_back(Rule(line));
                    continue_zone = false;
                }
                else if (word == "Link")
                {
                    db.links.push_back(Link(line));
                    continue_zone = false;
                }
                else if (word == "Leap")
                {
                    db.leaps.push_back(Leap(line));
                    continue_zone = false;
                }
                else if (word == "Zone")
                {
                    db.zones.push_back(Zone(line));
                    continue_zone = true;
                }
                else if (line[0] == '\t' && continue_zone)
                {
                    db.zones.back().add(line);
                }
                else
                {
                    std::cerr << line << '\n';
                }
            }
        }
    }
    std::sort(db.rules.begin(), db.rules.end());
    Rule::split_overlaps(db.rules);
    std::sort(db.zones.begin(), db.zones.end());
    for (auto& z : db.zones)
        z.adjust_infos(db.rules);
    db.zones.shrink_to_fit();
    std::sort(db.links.begin(), db.links.end());
    db.links.shrink_to_fit();
    std::sort(db.leaps.begin(), db.leaps.end());
    db.leaps.shrink_to_fit();
    return db;
}

static
TZ_DB&
access_tzdb()
{
    static TZ_DB tz_db;
    return tz_db;
}

const TZ_DB&
reload_tzdb()
{
    return access_tzdb() = init_tzdb();
}

const TZ_DB&
reload_tzdb(const std::string& new_install)
{
    install = new_install;
    return access_tzdb() = init_tzdb();
}

const TZ_DB&
get_tzdb()
{
    static const TZ_DB& ref = access_tzdb() = init_tzdb();
    return ref;
}

const Zone*
locate_zone(const std::string& tz_name)
{
    const auto& db = get_tzdb();
    auto zi = std::lower_bound(db.zones.begin(), db.zones.end(), tz_name,
        [](const Zone& z, const std::string& nm)
        {
            return z.name() < nm;
        });
    if (zi == db.zones.end() || zi->name() != tz_name)
    {
        auto li = std::lower_bound(db.links.begin(), db.links.end(), tz_name,
        [](const Link& z, const std::string& nm)
        {
            return z.name() < nm;
        });
        if (li != db.links.end() && li->name() == tz_name)
        {
            zi = std::lower_bound(db.zones.begin(), db.zones.end(), li->target(),
                [](const Zone& z, const std::string& nm)
                {
                    return z.name() < nm;
                });
            if (zi != db.zones.end() && zi->name() == li->target())
                return &*zi;
        }
        throw std::runtime_error(tz_name + " not found in timezone database");
    }
    return &*zi;
}

std::ostream&
operator<<(std::ostream& os, const TZ_DB& db)
{
    std::string title("--------------------------------------------"
                      "--------------------------------------------\n"
                      "Name           ""Start Y ""End Y   "
                      "Beginning                              ""Offset  "
                      "Designator\n"
                      "--------------------------------------------"
                      "--------------------------------------------\n");
    int count = 0;
    for (const auto& x : db.rules)
    {
        if (count++ % 50 == 0)
            os << title;
        os << x << '\n';
    }
    os << '\n';
    title = std::string("---------------------------------------------------------"
                        "--------------------------------------------------------\n"
                        "Name                               ""Offset      "
                        "Rule           ""Abrev      ""Until\n"
                        "---------------------------------------------------------"
                        "--------------------------------------------------------\n");
    count = 0;
    for (const auto& x : db.zones)
    {
        if (count++ % 10 == 0)
            os << title;
        os << x << '\n';
    }
    os << '\n';
    title = std::string("---------------------------------------------------------"
                        "--------------------------------------------------------\n"
                        "Alias                                   ""To\n"
                        "---------------------------------------------------------"
                        "--------------------------------------------------------\n");
    count = 0;
    for (const auto& x : db.links)
    {
        if (count++ % 45 == 0)
            os << title;
        os << x << '\n';
    }
    os << '\n';
    title = std::string("---------------------------------------------------------"
                        "--------------------------------------------------------\n"
                        "Leap second on\n"
                        "---------------------------------------------------------"
                        "--------------------------------------------------------\n");
    os << title;
    for (const auto& x : db.leaps)
        os << x << '\n';
    return os;
}

// -----------------------

std::ostream&
operator<<(std::ostream& os, const Info& r)
{
    using namespace date;
    os << r.begin << '\n';
    os << r.end << '\n';
    os << make_time(r.offset) << "\n";
    os << make_time(r.save) << "\n";
    os << r.abbrev << '\n';
    return os;
}

const Zone*
current_timezone()
{
    struct stat sb;
    CONSTDATA auto timezone = "/etc/localtime";
    if (lstat(timezone, &sb) == -1 || sb.st_size == 0)
        throw std::runtime_error("Could not get lstat on /etc/localtime");
    std::string result(sb.st_size, '\0');
    while (true)
    {
        auto sz = readlink(timezone, &result.front(), result.size());
        if (sz == -1)
            throw std::runtime_error("readlink failure");
        auto tmp = result.size();
        result.resize(sz);
        if (sz <= tmp)
            break;
    }
    result.erase(0, 20);
    return locate_zone(result);
}

}  // namespace date
