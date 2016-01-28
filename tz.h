#ifndef TZ_H
#define TZ_H

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

// Get more recent database at http://www.iana.org/time-zones

// Questions:
// 1.  Reload database.
// 4.  Is the utc to sys renaming complete?  Was it done correctly?

/*
The notion of "current timezone" is something the operating system is expected
to "just know". How it knows this is system specific. It's often a value
set by the user at OS intallation time and recorded by the OS somewhere.
On Linux and Mac systems the current timezone name is obtained by looking at
the name or contents of a particular file on disk.
On Windows the current timzeone name comes from the registry.
In either method, there is no guarantee that the "native" current timezone name obtained
will match any of the "Standard" names in this library's "database".
On Linux, the names usually do seem to match so mapping functions to map from
native to "Standard" are typically not required.
On Windows, the names are never "Standard" so mapping is always required.
Technically any OS may use the mapping process but currently only Windows does use it.
*/

#ifdef _WIN32
#ifndef TIMEZONE_MAPPING
#define TIMEZONE_MAPPING 1
#endif
#endif

#include "date.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <istream>
#include <ostream>
#include <ratio>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace date
{

using second_point = std::chrono::time_point<std::chrono::system_clock,
                                             std::chrono::seconds>;

enum class tz {utc, local, standard};
enum class choose {earliest, latest};

class nonexistent_local_time
    : public std::runtime_error
{
public:
    template <class Rep, class Period>
    nonexistent_local_time(std::chrono::time_point<std::chrono::system_clock,
                               std::chrono::duration<Rep, Period>> tp,
                           second_point first, const std::string& first_abbrev,
                           second_point last, const std::string& last_abbrev,
                           second_point time_sys);

private:
    template <class Rep, class Period>
    static
    std::string
    make_msg(std::chrono::time_point<std::chrono::system_clock,
                 std::chrono::duration<Rep, Period>> tp,
             second_point first, const std::string& first_abbrev,
             second_point last, const std::string& last_abbrev,
             second_point time_sys);
};

template <class Rep, class Period>
inline
nonexistent_local_time::nonexistent_local_time(
    std::chrono::time_point<std::chrono::system_clock,
        std::chrono::duration<Rep, Period>> tp,
    second_point first, const std::string& first_abbrev,
    second_point last, const std::string& last_abbrev,
    second_point time_sys)
    : std::runtime_error(make_msg(tp, first, first_abbrev, last, last_abbrev, time_sys))
    {}

template <class Rep, class Period>
std::string
nonexistent_local_time::make_msg(std::chrono::time_point<std::chrono::system_clock,
                                     std::chrono::duration<Rep, Period>> tp,
                                 second_point first, const std::string& first_abbrev,
                                 second_point last, const std::string& last_abbrev,
                                 second_point time_sys)
{
    using namespace date;
    std::ostringstream os;
    os << tp << " is in a gap between\n"
       << first << ' ' << first_abbrev << " and\n"
       << last  << ' ' << last_abbrev
       << " which are both equivalent to\n"
       << time_sys << " UTC";
    return os.str();
}

class ambiguous_local_time
    : public std::runtime_error
{
public:
    template <class Rep, class Period>
    ambiguous_local_time(std::chrono::time_point<std::chrono::system_clock,
                             std::chrono::duration<Rep, Period>> tp,
                         std::chrono::seconds first_offset,
                         const std::string& first_abbrev,
                         std::chrono::seconds second_offset,
                         const std::string& second_abbrev);

private:
    template <class Rep, class Period>
    static
    std::string
    make_msg(std::chrono::time_point<std::chrono::system_clock,
                 std::chrono::duration<Rep, Period>> tp,
             std::chrono::seconds first_offset, const std::string& first_abbrev,
             std::chrono::seconds second_offset, const std::string& second_abbrev);
};

template <class Rep, class Period>
inline
ambiguous_local_time::ambiguous_local_time(
    std::chrono::time_point<std::chrono::system_clock,
        std::chrono::duration<Rep, Period>> tp,
    std::chrono::seconds first_offset,
    const std::string& first_abbrev,
    std::chrono::seconds second_offset,
    const std::string& second_abbrev)
    : std::runtime_error(make_msg(tp, first_offset, first_abbrev, second_offset,
                                  second_abbrev))
    {}

template <class Rep, class Period>
std::string
ambiguous_local_time::make_msg(std::chrono::time_point<std::chrono::system_clock,
                                   std::chrono::duration<Rep, Period>> tp,
                               std::chrono::seconds first_offset,
                               const std::string& first_abbrev,
                               std::chrono::seconds second_offset,
                               const std::string& second_abbrev)
{
    using namespace date;
    std::ostringstream os;
    os << tp << " is ambiguous.  It could be\n"
       << tp << ' ' << first_abbrev << " == " << tp - first_offset << " UTC or\n" 
       << tp << ' ' << second_abbrev  << " == " << tp - second_offset  << " UTC";
    return os.str();
}

class Rule;

struct Info
{
    second_point         begin;
    second_point         end;
    std::chrono::seconds offset;
    std::chrono::minutes save;
    std::string          abbrev;
};

std::ostream&
operator<<(std::ostream& os, const Info& r);

class Zone
{
private:
    struct zonelet;

    std::string          name_;
    std::vector<zonelet> zonelets_;

public:
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    Zone(Zone&&) = default;
    Zone& operator=(Zone&&) = default;
#else  // defined(_MSC_VER) || (_MSC_VER >= 1900)
    Zone(Zone&& src)
    :
        name_(std::move(src.name_)),
        zonelets_(std::move(zonelets_))
    {}

    Zone& operator=(Zone&& src)
    {
        name_ = std::move(src.name_);
        zonelets_ = std::move(src.zonelets_);
        return *this;
    }
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)

    explicit Zone(const std::string& s);

    const std::string& name() const {return name_;}
    Info get_info(std::chrono::system_clock::time_point tp, tz timezone) const;

    template <class Rep, class Period>
    Info
    get_info(std::chrono::time_point<std::chrono::system_clock,
                                     std::chrono::duration<Rep, Period>> tp,
             tz timezone) const
    {
        using namespace std::chrono;
        return get_info(floor<system_clock::duration>(tp), timezone);
    }

    template <class Rep, class Period>
    std::chrono::time_point<std::chrono::system_clock,
        typename std::common_type<std::chrono::duration<Rep, Period>,
                                  std::chrono::seconds>::type>
    to_sys(std::chrono::time_point<std::chrono::system_clock,
                                   std::chrono::duration<Rep, Period>> tp) const;

    template <class Rep, class Period>
    std::chrono::time_point<std::chrono::system_clock,
        typename std::common_type<std::chrono::duration<Rep, Period>,
                                  std::chrono::seconds>::type>
    to_sys(std::chrono::time_point<std::chrono::system_clock,
                                   std::chrono::duration<Rep, Period>> tp,
           choose z) const;

    template <class Rep, class Period>
    std::pair
    <
        std::chrono::time_point<std::chrono::system_clock,
            typename std::common_type<std::chrono::duration<Rep, Period>,
                                      std::chrono::seconds>::type>,
        std::string
    >
    to_local(std::chrono::time_point<std::chrono::system_clock,
                                   std::chrono::duration<Rep, Period>> tp) const;

    friend bool operator==(const Zone& x, const Zone& y);
    friend bool operator< (const Zone& x, const Zone& y);
    friend std::ostream& operator<<(std::ostream& os, const Zone& z);

    void add(const std::string& s);
    void adjust_infos(const std::vector<Rule>& rules);

private:
    void parse_info(std::istream& in);

    template <class Rep, class Period, bool b>
    std::chrono::time_point<std::chrono::system_clock,
        typename std::common_type<std::chrono::duration<Rep, Period>,
                                  std::chrono::seconds>::type>
    to_sys_impl(std::chrono::time_point<std::chrono::system_clock,
                                        std::chrono::duration<Rep, Period>> tp,
                choose z, std::integral_constant<bool, b> do_throw) const;
};

template <class Rep, class Period>
inline
std::chrono::time_point<std::chrono::system_clock,
    typename std::common_type<std::chrono::duration<Rep, Period>,
                              std::chrono::seconds>::type>
Zone::to_sys(std::chrono::time_point<std::chrono::system_clock,
             std::chrono::duration<Rep, Period>> tp) const
{
    return to_sys_impl(tp, choose{}, std::true_type{});
}

template <class Rep, class Period>
inline
std::chrono::time_point<std::chrono::system_clock,
    typename std::common_type<std::chrono::duration<Rep, Period>,
                              std::chrono::seconds>::type>
Zone::to_sys(std::chrono::time_point<std::chrono::system_clock,
             std::chrono::duration<Rep, Period>> tp, choose z) const
{
    return to_sys_impl(tp, z, std::false_type{});
}

template <class Rep, class Period>
inline
std::pair
<
    std::chrono::time_point<std::chrono::system_clock,
        typename std::common_type<std::chrono::duration<Rep, Period>,
                                  std::chrono::seconds>::type>,
    std::string
>
Zone::to_local(std::chrono::time_point<std::chrono::system_clock,
               std::chrono::duration<Rep, Period>> tp) const
{
    auto const i = get_info(tp, tz::utc);
    return {tp + i.offset, i.abbrev};
}

inline bool operator==(const Zone& x, const Zone& y) {return x.name_ == y.name_;}
inline bool operator< (const Zone& x, const Zone& y) {return x.name_ < y.name_;}

inline bool operator!=(const Zone& x, const Zone& y) {return !(x == y);}
inline bool operator> (const Zone& x, const Zone& y) {return   y < x;}
inline bool operator<=(const Zone& x, const Zone& y) {return !(y < x);}
inline bool operator>=(const Zone& x, const Zone& y) {return !(x < y);}

template <class Rep, class Period, bool b>
std::chrono::time_point<std::chrono::system_clock,
    typename std::common_type<std::chrono::duration<Rep, Period>,
                              std::chrono::seconds>::type>
Zone::to_sys_impl(std::chrono::time_point<std::chrono::system_clock,
                  std::chrono::duration<Rep, Period>> tp,
                  choose z, std::integral_constant<bool, b> do_throw) const
{
    using namespace date;
    using namespace std::chrono;
    auto i = get_info(tp, tz::local);
    auto tp_sys = tp - i.offset;
    if (floor<seconds>(tp_sys) - i.begin <= days{1})
    {
        if (floor<seconds>(tp) < i.begin + i.offset)
        {
            if (do_throw)
            {
                auto prev = get_info(i.begin - seconds{1}, tz::utc);
                throw nonexistent_local_time(tp, i.begin + prev.offset, prev.abbrev,
                                             i.begin + i.offset, i.abbrev, i.begin);
            }
            return i.begin;
        }
        assert(floor<seconds>(tp) >= 
                i.begin + get_info(i.begin - seconds{1}, tz::utc).offset);
    }
    if (i.end - floor<seconds>(tp_sys) <= days{1})
    {
        assert(floor<seconds>(tp) < i.end + i.offset);
        auto next = get_info(i.end, tz::utc);
        if (floor<seconds>(tp) >= i.end + next.offset)
        {
            if (do_throw)
                throw ambiguous_local_time(tp, i.offset, i.abbrev,
                                               next.offset, next.abbrev);
            if (z == choose::earliest)
                return tp_sys;
            return tp - next.offset;
        }
    }
    return tp_sys;
}

class Link
{
private:
    std::string name_;
    std::string target_;
public:
    explicit Link(const std::string& s);

    const std::string& name() const {return name_;}
    const std::string& target() const {return target_;}

    friend bool operator==(const Link& x, const Link& y) {return x.name_ == y.name_;}
    friend bool operator< (const Link& x, const Link& y) {return x.name_ < y.name_;}

    friend std::ostream& operator<<(std::ostream& os, const Link& x);
};

inline bool operator!=(const Link& x, const Link& y) {return !(x == y);}
inline bool operator> (const Link& x, const Link& y) {return   y < x;}
inline bool operator<=(const Link& x, const Link& y) {return !(y < x);}
inline bool operator>=(const Link& x, const Link& y) {return !(x < y);}

class Leap
{
private:
    second_point date_;

public:
    explicit Leap(const std::string& s);

    second_point date() const {return date_;}

    friend bool operator==(const Leap& x, const Leap& y) {return x.date_ == y.date_;}
    friend bool operator< (const Leap& x, const Leap& y) {return x.date_ < y.date_;}

    template <class Duration>
    friend
    bool
    operator==(const Leap& x,
               const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
    {
        return x.date_ == y;
    }

    template <class Duration>
    friend
    bool
    operator< (const Leap& x,
               const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
    {
        return x.date_ < y;
    }

    template <class Duration>
    friend
    bool
    operator< (const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
               const Leap& y)
    {
        return x < y.date_;
    }

    friend std::ostream& operator<<(std::ostream& os, const Leap& x);
};

inline bool operator!=(const Leap& x, const Leap& y) {return !(x == y);}
inline bool operator> (const Leap& x, const Leap& y) {return   y < x;}
inline bool operator<=(const Leap& x, const Leap& y) {return !(y < x);}
inline bool operator>=(const Leap& x, const Leap& y) {return !(x < y);}

template <class Duration>
inline
bool
operator==(const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
           const Leap& y)
{
    return y == x;
}

template <class Duration>
inline
bool
operator!=(const Leap& x,
           const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
{
    return !(x == y);
}

template <class Duration>
inline
bool
operator!=(const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
           const Leap& y)
{
    return !(x == y);
}

template <class Duration>
inline
bool
operator> (const Leap& x,
           const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
{
    return y < x;
}

template <class Duration>
inline
bool
operator> (const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
           const Leap& y)
{
    return y < x;
}

template <class Duration>
inline
bool
operator<=(const Leap& x,
           const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
{
    return !(y < x);
}

template <class Duration>
inline
bool
operator<=(const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
           const Leap& y)
{
    return !(y < x);
}

template <class Duration>
inline
bool
operator>=(const Leap& x,
           const std::chrono::time_point<std::chrono::system_clock, Duration>& y)
{
    return !(x < y);
}

template <class Duration>
inline
bool
operator>=(const std::chrono::time_point<std::chrono::system_clock, Duration>& x,
           const Leap& y)
{
    return !(x < y);
}

#if TIMEZONE_MAPPING

// TODO! Ensure all these types aren't exposed.

// The time zone mapping is modelled after this data file:
// http://unicode.org/repos/cldr/trunk/common/supplemental/windowsZones.xml
// and the field names match the element names from the mapZone element
// of windowsZones.xml.
// The website displays this file here:
// http://www.unicode.org/cldr/charts/latest/supplemental/zone_tzid.html
// The html view is sorted before being displayed but is otherwise the same
// There is a mapping between the os centric view (in this case windows)
// the html displays uses and the generic view the xml file.
// That mapping is this:
// display column "windows" -> xml field "other".
// display column "region"  -> xml field "territory".
// display column "tzid"    -> xml field "type".
// This structure uses the generic terminology because it could be
// used to to support other os/native name conversions, not just windows,
// and using the same generic names helps retain the connection to the
// origin of the data that we are using.
struct timezone_mapping
{
    timezone_mapping(const char* other, const char* territory, const char* type)
        : other(other), territory(territory), type(type)
    {
    }
    timezone_mapping() = default;
    std::string other;
    std::string territory;
    std::string type;
};

struct timezone_info
{
    timezone_info() = default;
    std::string timezone_id;
    std::string standard_name;
};

#endif  // TIMEZONE_MAPPING

struct TZ_DB
{
    std::string       version;
    std::vector<Zone> zones;
    std::vector<Link> links;
    std::vector<Leap> leaps;
    std::vector<Rule> rules;
#if TIMEZONE_MAPPING
    // TODO! These need some protection.
    std::vector<timezone_mapping> mappings;
    std::vector<timezone_info> native_zones;
#endif
    
    TZ_DB() = default;
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    TZ_DB(TZ_DB&&) = default;
    TZ_DB& operator=(TZ_DB&&) = default;
#else  // defined(_MSC_VER) || (_MSC_VER >= 1900)
    TZ_DB(TZ_DB&& src)
    :
        zones(std::move(src.zones)),
        links(std::move(links)),
        leaps(std::move(leaps)),
        rules(std::move(rules))
#if TIMEZONE_MAPPING
        ,
        mappings(std::move(mappings)),
        native_zones(std::move(native_zones))
#endif
    {}

    TZ_DB& operator=(TZ_DB&& src)
    {
        zones = std::move(src.zones);
        links = std::move(links);
        leaps = std::move(leaps);
        rules = std::move(rules);
#if TIMEZONE_MAPPING
        mappings = std::move(mappings);
        native_zones = std::move(native_zones);
#endif
        return *this;
    }
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)
};

std::ostream& operator<<(std::ostream& os, const TZ_DB& db);

const TZ_DB& get_tzdb();
const TZ_DB& reload_tzdb();
const TZ_DB& reload_tzdb(const std::string& new_install);

const Zone* locate_zone(const std::string& tz_name);
#ifdef TZ_TEST
#ifdef _WIN32
const Zone* locate_native_zone(const std::string& native_tz_name);
#endif
#endif
const Zone* current_zone();

class utc_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<utc_clock>;
    static CONSTDATA bool is_steady = true;

    static time_point now() NOEXCEPT;

    template <class Duration>
        static
        std::chrono::time_point<utc_clock,
            typename std::common_type<Duration, std::chrono::seconds>::type>
        sys_to_utc(std::chrono::time_point<std::chrono::system_clock, Duration> t);

    template <class Duration>
        static
        std::chrono::time_point<std::chrono::system_clock,
            typename std::common_type<Duration, std::chrono::seconds>::type>
        utc_to_sys(std::chrono::time_point<utc_clock, Duration> t);
};

inline
utc_clock::time_point
utc_clock::now() NOEXCEPT
{
    using namespace std::chrono;
    return sys_to_utc(system_clock::now());
}

template <class Duration>
std::chrono::time_point<utc_clock,
    typename std::common_type<Duration, std::chrono::seconds>::type>
utc_clock::sys_to_utc(std::chrono::time_point<std::chrono::system_clock, Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    using time_point = std::chrono::time_point<utc_clock, duration>;
    auto const& leaps = get_tzdb().leaps;
    auto const lt = std::upper_bound(leaps.begin(), leaps.end(), t);
    return time_point{t.time_since_epoch() + seconds{lt-leaps.begin()}};
}

template <class Duration>
std::chrono::time_point<std::chrono::system_clock,
    typename std::common_type<Duration, std::chrono::seconds>::type>
utc_clock::utc_to_sys(std::chrono::time_point<utc_clock, Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    using time_point = std::chrono::time_point<system_clock, duration>;
    auto const& leaps = get_tzdb().leaps;
    auto tp = time_point{t.time_since_epoch()};
    auto const lt = std::upper_bound(leaps.begin(), leaps.end(), tp);
    tp -= seconds{lt-leaps.begin()};
    if (lt != leaps.begin() && tp + seconds{1} < lt[-1])
        tp += seconds{1};
    return tp;
}

}  // namespace date

#endif  // TZ_H
