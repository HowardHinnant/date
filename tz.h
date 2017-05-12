#ifndef TZ_H
#define TZ_H

// The MIT License (MIT)
//
// Copyright (c) 2015, 2016, 2017 Howard Hinnant
// Copyright (c) 2017 Jiangang Zhuang
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
// been invented (that would involve another several millennia of evolution).
// We did not mean to shout.

// Get more recent database at http://www.iana.org/time-zones

// The notion of "current timezone" is something the operating system is expected to "just
// know". How it knows this is system specific. It's often a value set by the user at OS
// installation time and recorded by the OS somewhere. On Linux and Mac systems the current
// timezone name is obtained by looking at the name or contents of a particular file on
// disk. On Windows the current timezone name comes from the registry. In either method,
// there is no guarantee that the "native" current timezone name obtained will match any
// of the "Standard" names in this library's "database". On Linux, the names usually do
// seem to match so mapping functions to map from native to "Standard" are typically not
// required. On Windows, the names are never "Standard" so mapping is always required.
// Technically any OS may use the mapping process but currently only Windows does use it.

#ifdef _WIN32
#  ifndef TIMEZONE_MAPPING
#    define TIMEZONE_MAPPING 1
#    define TIMEZONE_RULES 1
#  endif
#else
#  ifdef TIMEZONE_MAPPING
#    error "Timezone mapping is not required or not implemented for this platform."
#  endif
#  if !defined(TIMEZONE_FILES) && !defined(TIMEZONE_RULES)
#    define TIMEZONE_FILES 1
#  endif
#endif

#ifndef TIMEZONE_MAPPING
#  define TIMEZONE_MAPPING 0
#endif
#ifndef TIMEZONE_RULES
#  define TIMEZONE_RULES 0
#  define TIMEZONE_MAPPING 0
#endif
#ifndef TIMEZONE_FILES
#  define TIMEZONE_FILES 0
#endif

#ifndef LAZY_INIT
#  define LAZY_INIT 1
#endif

#if TIMEZONE_RULES
#  ifndef HAS_REMOTE_API
#    ifdef _WIN32
#      define HAS_REMOTE_API 0
#    else
#      define HAS_REMOTE_API 1
#    endif
#  endif

#  ifndef AUTO_DOWNLOAD
#    define AUTO_DOWNLOAD HAS_REMOTE_API
#  endif

static_assert(HAS_REMOTE_API == 0 ? AUTO_DOWNLOAD == 0 : true,
              "AUTO_DOWNLOAD can not be turned on without HAS_REMOTE_API");

#  ifndef USE_SHELL_API
#    define USE_SHELL_API 1
#  endif
#endif // TIMEZONE_RULES

#if TIMEZONE_FILES
#  ifndef TZLEAP_FILE
#    define TZLEAP_FILE "right/UTC"
#  endif
#  include <map>
#endif // TIMEZONE_FILES

#if !defined(TZDIR) && (TIMEZONE_FILES || !defined(_WIN32))
#  define TZDIR "/usr/share/zoneinfo"
#endif

#ifndef TIMEZONE_DEFAULT
#  if TIMEZONE_FILES
#    define TIMEZONE_DEFAULT 0
#  else
#    define TIMEZONE_DEFAULT 1
#  endif
#endif

#if TIMEZONE_DEFAULT == 0 && !defined(TIMEZONE_FILES)
#  error "Cannot use TIMEZONE_FILES as TIMEZONE_DEFAULT if TIMEZONE_FILES isn't defined!"
#elif TIMEZONE_DEFAULT == 1 && !defined(TIMEZONE_MAPPING)
#  error "Cannot use TIMEZONE_MAPPING as TIMEZONE_DEFAULT if TIMEZONE_MAPPING isn't defined!"
#elif TIMEZONE_DEFAULT == 2 && !defined(TIMEZONE_RULES)
#  error "Cannot use TIMEZONE_RULES as TIMEZONE_DEFAULT if TIMEZONE_RULES isn't defined!"
#endif

#if defined(__APPLE__) && !defined(DATE_TIMEZONE_FILES_NO_LEAP)
#  define DATE_TIMEZONE_FILES_NO_LEAP 1
#endif

#ifndef DATE_TIMEZONE_FILES_NO_LEAP
#  define DATE_TIMEZONE_FILES_NO_LEAP 0
#endif

#include "date.h"
#include "tz_private.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <istream>
#include <locale>
#if LAZY_INIT
#  include <memory>
#  include <mutex>
#endif
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _WIN32
#  ifdef DATE_BUILD_DLL
#    define DATE_API __declspec(dllexport)
#  elif defined(DATE_BUILD_LIB)
#    define DATE_API
#  else
#    define DATE_API __declspec(dllimport)
#  endif
#else
#  define DATE_API
#endif

namespace date
{

enum class choose {earliest, latest};

namespace detail
{
    struct undocumented;
}

class nonexistent_local_time
    : public std::runtime_error
{
public:
    template <class Duration>
    nonexistent_local_time(local_time<Duration> tp, local_seconds first,
                           const std::string& first_abbrev, local_seconds last,
                           const std::string& last_abbrev, sys_seconds time_sys);

private:
    template <class Duration>
    static
    std::string
    make_msg(local_time<Duration> tp,
             local_seconds first, const std::string& first_abbrev,
             local_seconds last, const std::string& last_abbrev,
             sys_seconds time_sys);
};

template <class Duration>
inline
nonexistent_local_time::nonexistent_local_time(local_time<Duration> tp,
                                               local_seconds begin,
                                               const std::string& first_abbrev,
                                               local_seconds end,
                                               const std::string& last_abbrev,
                                               sys_seconds time_sys)
    : std::runtime_error(make_msg(tp, begin, first_abbrev, end, last_abbrev, time_sys))
    {}

template <class Duration>
std::string
nonexistent_local_time::make_msg(local_time<Duration> tp, local_seconds begin,
                                 const std::string& first_abbrev, local_seconds end,
                                 const std::string& last_abbrev, sys_seconds time_sys)
{
    using namespace date;
    std::ostringstream os;
    os << tp << " is in a gap between\n"
       << begin << ' ' << first_abbrev << " and\n"
       << end   << ' ' << last_abbrev
       << " which are both equivalent to\n"
       << time_sys << " UTC";
    return os.str();
}

class ambiguous_local_time
    : public std::runtime_error
{
public:
    template <class Duration>
    ambiguous_local_time(local_time<Duration> tp, std::chrono::seconds first_offset,
                         const std::string& first_abbrev,
                         std::chrono::seconds second_offset,
                         const std::string& second_abbrev);

private:
    template <class Duration>
    static
    std::string
    make_msg(local_time<Duration> tp,
             std::chrono::seconds first_offset, const std::string& first_abbrev,
             std::chrono::seconds second_offset, const std::string& second_abbrev);
};

template <class Duration>
inline
ambiguous_local_time::ambiguous_local_time(
    local_time<Duration> tp,
    std::chrono::seconds first_offset,
    const std::string& first_abbrev,
    std::chrono::seconds second_offset,
    const std::string& second_abbrev)
    : std::runtime_error(make_msg(tp, first_offset, first_abbrev, second_offset,
                                  second_abbrev))
    {}

template <class Duration>
std::string
ambiguous_local_time::make_msg(local_time<Duration> tp,
                               std::chrono::seconds first_offset,
                               const std::string& first_abbrev,
                               std::chrono::seconds second_offset,
                               const std::string& second_abbrev)
{
    using namespace date;
    std::ostringstream os;
    os << tp << " is ambiguous.  It could be\n"
       << tp << ' ' << first_abbrev << " == "
       << tp - first_offset << " UTC or\n"
       << tp << ' ' << second_abbrev  << " == "
       << tp - second_offset  << " UTC";
    return os.str();
}

namespace detail { class Rule; }

struct sys_info
{
    sys_seconds          begin;
    sys_seconds          end;
    std::chrono::seconds offset;
    std::chrono::minutes save;
    std::string          abbrev;
};

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const sys_info& r)
{
    os << r.begin << '\n';
    os << r.end << '\n';
    os << make_time(r.offset) << "\n";
    os << make_time(r.save) << "\n";
    os << r.abbrev << '\n';
    return os;
}

struct local_info
{
    enum {unique, nonexistent, ambiguous} result;
    sys_info first;
    sys_info second;
};

template<class CharT, class Traits>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const local_info& r)
{
    if (r.result == local_info::nonexistent)
        os << "nonexistent between\n";
    else if (r.result == local_info::ambiguous)
        os << "ambiguous between\n";
    os << r.first;
    if (r.result != local_info::unique)
    {
        os << "and\n";
        os << r.second;
    }
    return os;
}

namespace detail { struct time_zone_tag {}; }

template <class Duration, class TimeZone>
class basic_zoned_time
{
    const TimeZone*   zone_;
    sys_time<Duration> tp_;

public:
             basic_zoned_time(const sys_time<Duration>& st);
    explicit basic_zoned_time(const TimeZone* z);
    explicit basic_zoned_time(const std::string& name);

    template <class Duration2,
              class = typename std::enable_if
                      <
                          std::is_convertible<sys_time<Duration2>,
                                              sys_time<Duration>>::value
                      >::type>
    basic_zoned_time(const basic_zoned_time<Duration2,TimeZone>& zt) NOEXCEPT;

    basic_zoned_time(const TimeZone* z,      const local_time<Duration>& tp);
    basic_zoned_time(const std::string& name, const local_time<Duration>& tp);
    basic_zoned_time(const char* name,        const local_time<Duration>& tp);
    basic_zoned_time(const TimeZone* z,      const local_time<Duration>& tp, choose c);
    basic_zoned_time(const std::string& name, const local_time<Duration>& tp, choose c);
    basic_zoned_time(const char* name,        const local_time<Duration>& tp, choose c);

    basic_zoned_time(const TimeZone* z,      const basic_zoned_time<Duration,TimeZone>& zt);
    basic_zoned_time(const std::string& name, const basic_zoned_time<Duration,TimeZone>& zt);
    basic_zoned_time(const char* name,        const basic_zoned_time<Duration,TimeZone>& zt);
    basic_zoned_time(const TimeZone* z,      const basic_zoned_time<Duration,TimeZone>& zt, choose);
    basic_zoned_time(const std::string& name, const basic_zoned_time<Duration,TimeZone>& zt, choose);
    basic_zoned_time(const char* name,        const basic_zoned_time<Duration,TimeZone>& zt, choose);

    basic_zoned_time(const TimeZone* z,      const sys_time<Duration>& st);
    basic_zoned_time(const std::string& name, const sys_time<Duration>& st);
    basic_zoned_time(const char* name,        const sys_time<Duration>& st);

    basic_zoned_time& operator=(const sys_time<Duration>& st);
    basic_zoned_time& operator=(const local_time<Duration>& ut);

             operator sys_time<Duration>() const;
    explicit operator local_time<Duration>() const;

    const TimeZone*     get_time_zone() const;
    local_time<Duration> get_local_time() const;
    sys_time<Duration>   get_sys_time() const;
    sys_info             get_info() const;

    template <class Duration1, class Duration2>
    friend
    bool
    operator==(const basic_zoned_time<Duration1,TimeZone>& x, const basic_zoned_time<Duration2,TimeZone>& y);

private:
    template <class D, class T> friend class basic_zoned_time;

    static_assert(std::is_convertible<std::chrono::seconds, Duration>::value,
                  "zoned_time must have a precision of seconds or finer");
};

template <class CharT, class Traits, class Duration1, class TimeZone>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const basic_zoned_time<Duration1, TimeZone>& t);

template<class TimeZone>
using basic_zoned_seconds = basic_zoned_time<std::chrono::seconds, TimeZone>;

template <class Duration1, class Duration2, class TimeZone>
inline
bool
operator==(const basic_zoned_time<Duration1, TimeZone>& x, const basic_zoned_time<Duration2, TimeZone>& y)
{
    return x.zone_ == y.zone_ && x.tp_ == y.tp_;
}

template <class Duration1, class Duration2, class TimeZone>
inline
bool
operator!=(const basic_zoned_time<Duration1, TimeZone>& x, const basic_zoned_time<Duration2, TimeZone>& y)
{
    return !(x == y);
}

template <class CharT, class Traits, class Duration1, class TimeZone>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const basic_zoned_time<Duration1, TimeZone>& t)
{
    to_stream(os, "%F %T %Z", t);
    return os;
}

#if TIMEZONE_FILES

namespace detail
{

class zone_info
{
public:
    zone_info(const std::chrono::seconds& g, const bool& d, const std::string& a);

    std::chrono::seconds gmt_offset;
    bool                 is_dst;
    std::string          abbreviation;
};

class transition
{
public:
    sys_seconds      timepoint;
    const zone_info* info;

    transition(const sys_seconds& t=sys_seconds(), const zone_info* i = nullptr);
};

class tzfile_data
{
public:
    std::vector<transition> transitions_;
    std::vector<zone_info>  local_infos_;

       tzfile_data();
};

inline zone_info::zone_info(const std::chrono::seconds& g, const bool& d, const std::string& a)
    : gmt_offset(g)
    , is_dst(d)
    , abbreviation(a)
{}

inline transition::transition(const sys_seconds& t, const zone_info* i)
    : timepoint(t)
    , info(i)
{}

inline tzfile_data::tzfile_data()
    : transitions_{}
    , local_infos_{}
{}

}

class leap;
class tzfile_db;

class tzfile_zone : public detail::time_zone_tag
{
private:
    friend class tzfile_db;
#if LAZY_INIT
    using data_t = std::unique_ptr<detail::tzfile_data>;
    DATE_API static void load_data(std::istream& s, detail::tzfile_data& pimpl);
#else
    using data_t = detail::tzfile_data;
#endif
    std::string name_;
    data_t      p;

public:
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzfile_zone(tzfile_zone&&) = default;
    tzfile_zone& operator=(tzfile_zone&&) = default;
#else   // defined(_MSC_VER) && (_MSC_VER < 1900)
    tzfile_zone(tzfile_zone&& src);
    tzfile_zone& operator=(tzfile_zone&& src);
#endif  // defined(_MSC_VER) && (_MSC_VER < 1900)

    DATE_API explicit tzfile_zone(const std::string& name, std::istream& s);
    DATE_API static void load_leaps(std::istream& s, std::vector<leap>& leaps);

    const std::string& name() const NOEXCEPT;

    template <class Duration> sys_info   get_info(sys_time<Duration> st) const;
    template <class Duration> local_info get_info(local_time<Duration> tp) const;

    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys(local_time<Duration> tp) const;

    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys(local_time<Duration> tp, choose z) const;

    template <class Duration>
        local_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_local(sys_time<Duration> tp) const;

    friend bool operator==(const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT;
    friend bool operator< (const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT;
    friend DATE_API std::ostream& operator<<(std::ostream& os, const tzfile_zone& z);

    static const tzfile_db& get_tzdb(const std::string& tz_dir=TZDIR);
    static const tzfile_db& reload_tzdb(const std::string& tz_dir=TZDIR);
    static tzfile_db init_tzdb(const std::string& tz_dir=TZDIR);


   DATE_API static const tzfile_zone* locate_zone(const std::string& tz_name, const std::string& tz_dir=TZDIR);
   DATE_API static const tzfile_zone* current_zone(const std::string& tz_dir=TZDIR);

private:
    DATE_API sys_info   get_info_impl(sys_seconds tp) const;
    DATE_API local_info get_info_impl(local_seconds tp) const;
    DATE_API sys_info   get_info_impl(sys_seconds tp, int timezone) const;
    const detail::zone_info* initial_zone_info() const;
    
    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys_impl(local_time<Duration> tp, choose z, std::false_type) const;
    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys_impl(local_time<Duration> tp, choose, std::true_type) const;
};

class tzfile_db
{
public:
    std::vector<tzfile_zone> zones;
#if !DATE_TIMEZONE_FILES_NO_LEAP
    std::vector<leap>        leaps;
#endif
    tzfile_db() = default;
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzfile_db(tzfile_db&&) = default;
    tzfile_db& operator=(tzfile_db&&) = default;
#else  // defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzfile_db(tzfile_db&& src)
        : zones(std::move(src.zones))
#if !DATE_TIMEZONE_FILES_NO_LEAP
        , leaps(std::move(src.leaps))
#endif
    {}

    tzfile_db& operator=(tzfile_db&& src)
    {
        zones = std::move(src.zones);
#if !DATE_TIMEZONE_FILES_NO_LEAP
        leaps = std::move(src.leaps);
#endif
        return *this;
    }
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)
    DATE_API static const tzfile_zone* locate_zone(const std::string& tz_name, const std::string& tz_dir=TZDIR);
    DATE_API static const tzfile_zone* current_zone(const std::string& tz_dir=TZDIR);
    
    DATE_API static const tzfile_db& get_tzdb(const std::string& tz_dir=TZDIR);
    DATE_API static const tzfile_db& reload_tzdb(const std::string& tz_dir=TZDIR);
    DATE_API static tzfile_db init_tzdb(std::string tz_dir=TZDIR);
    
    static CONSTDATA char version[] = "tzfile";
};

DATE_API std::ostream&
operator<<(std::ostream& os, const tzfile_db& db);

inline const tzfile_zone* tzfile_zone::locate_zone(const std::string& tz_name, const std::string& tz_dir)
{ return tzfile_db::locate_zone(tz_name, tz_dir); }

inline const tzfile_zone* tzfile_zone::current_zone(const std::string& tz_dir)
{ return tzfile_db::current_zone(tz_dir); }

inline
const tzfile_db&
tzfile_zone::get_tzdb(const std::string& tz_dir)
{ return tzfile_db::get_tzdb(tz_dir); }

inline
const tzfile_db&
tzfile_zone::reload_tzdb(const std::string& tz_dir)
{ return tzfile_db::reload_tzdb(tz_dir); }

inline
tzfile_db tzfile_zone::init_tzdb(const std::string& tz_dir)
{ return tzfile_db::init_tzdb(tz_dir); }


inline
const std::string&
tzfile_zone::name() const NOEXCEPT
{ return name_; }

template <class Duration>
inline
sys_info
tzfile_zone::get_info(sys_time<Duration> st) const
{ return get_info_impl(floor<std::chrono::seconds>(st)); }

template <class Duration>
inline
local_info
tzfile_zone::get_info(local_time<Duration> tp) const
{ return get_info_impl(floor<std::chrono::seconds>(tp)); }

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzfile_zone::to_sys(local_time<Duration> tp) const
{ return to_sys_impl(tp, choose{}, std::true_type{}); }

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzfile_zone::to_sys(local_time<Duration> tp, choose z) const
{ return to_sys_impl(tp, z, std::false_type{}); }

template <class Duration>
inline
local_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzfile_zone::to_local(sys_time<Duration> tp) const
{
    using LT = local_time<typename std::common_type<Duration, std::chrono::seconds>::type>;
    auto i = get_info(tp);
    return LT{(tp + i.offset).time_since_epoch()};
}

inline bool operator==(const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return x.name_ == y.name_;}
inline bool operator< (const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return x.name_ < y.name_;}

inline bool operator!=(const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return !(x == y);}
inline bool operator> (const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return   y < x;}
inline bool operator<=(const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return !(y < x);}
inline bool operator>=(const tzfile_zone& x, const tzfile_zone& y) NOEXCEPT {return !(x < y);}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzfile_zone::to_sys_impl(local_time<Duration> tp, choose z, std::false_type) const
{
    using namespace date;
    using namespace std::chrono;
    auto i = get_info(tp);
    if (i.result == local_info::nonexistent)
    {
        return i.first.end;
    }
    else if (i.result == local_info::ambiguous)
    {
        if (z == choose::latest)
            return sys_time<Duration>{tp.time_since_epoch()} - i.second.offset;
    }
    return sys_time<Duration>{tp.time_since_epoch()} - i.first.offset;
}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzfile_zone::to_sys_impl(local_time<Duration> tp, choose, std::true_type) const
{
    using namespace date;
    using namespace std::chrono;
    auto i = get_info(tp);
    if (i.result == local_info::nonexistent)
    {
        auto prev_end = local_seconds{i.first.end.time_since_epoch()} +
                        i.first.offset;
        auto next_begin = local_seconds{i.second.begin.time_since_epoch()} +
                          i.second.offset;
        throw nonexistent_local_time(tp, prev_end, i.first.abbrev,
                                         next_begin, i.second.abbrev, i.first.end);
    }
    else if (i.result == local_info::ambiguous)
    {
        throw ambiguous_local_time(tp, i.first.offset, i.first.abbrev,
                                       i.second.offset, i.second.abbrev);
    }
    return sys_time<Duration>{tp.time_since_epoch()} - i.first.offset;
}

#if defined(_MSC_VER) && (_MSC_VER < 1900)
    tzfile_zone::tzfile_zone(tzfile_zone&& src)
        : name_(std::move(src.name_))
        , p(std::move(src.p))
    {}
    
    tzfile_zone& tzfile_zone::operator=(tzfile_zone&& src)
    {
        name_ = std::move(src.name_);
        p = std::move(src.p);
        return *this;
    }
#endif  // defined(_MSC_VER) && (_MSC_VER < 1900)

#endif // TIMEZONE_FILES

#if TIMEZONE_RULES

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
namespace detail { struct zonelet; }
#endif

class tzrule_db;

class tzrule_zone : public detail::time_zone_tag
{
private:

    std::string          name_;
    std::vector<detail::zonelet> zonelets_;
#if LAZY_INIT
    std::unique_ptr<std::once_flag> adjusted_;
#endif

public:
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzrule_zone(tzrule_zone&&) = default;
    tzrule_zone& operator=(tzrule_zone&&) = default;
#else   // defined(_MSC_VER) && (_MSC_VER < 1900)
    tzrule_zone(tzrule_zone&& src);
    tzrule_zone& operator=(tzrule_zone&& src);
#endif  // defined(_MSC_VER) && (_MSC_VER < 1900)

    DATE_API explicit tzrule_zone(const std::string& s, detail::undocumented);

    const std::string& name() const NOEXCEPT;

    template <class Duration> sys_info   get_info(sys_time<Duration> st) const;
    template <class Duration> local_info get_info(local_time<Duration> tp) const;

    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys(local_time<Duration> tp) const;

    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys(local_time<Duration> tp, choose z) const;

    template <class Duration>
        local_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_local(sys_time<Duration> tp) const;

    friend bool operator==(const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT;
    friend bool operator< (const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT;
    friend DATE_API std::ostream& operator<<(std::ostream& os, const tzrule_zone& z);

    DATE_API void add(const std::string& s);
    DATE_API void adjust_infos(const std::vector<detail::Rule>& rules);

   DATE_API static const tzrule_zone* locate_zone(const std::string& tz_name);
#ifdef TZ_TEST
#  if TIMEZONE_MAPPING
   DATE_API static const tzrule_zone* locate_native_zone(const std::string& native_tz_name);
#  endif // _WIN32
#endif // TZ_TEST
   DATE_API static const tzrule_zone* current_zone();
   
   static const tzrule_db& get_tzdb();
   static const tzrule_db& reload_tzdb();
   static tzrule_db init_tzdb();

private:
    DATE_API sys_info   get_info_impl(sys_seconds tp) const;
    DATE_API local_info get_info_impl(local_seconds tp) const;
    DATE_API sys_info   get_info_impl(sys_seconds tp, int timezone) const;

    void parse_info(std::istream& in);

    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys_impl(local_time<Duration> tp, choose z, std::false_type) const;
    template <class Duration>
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        to_sys_impl(local_time<Duration> tp, choose, std::true_type) const;
};

#if defined(_MSC_VER) && (_MSC_VER < 1900)

inline
tzrule_zone::tzrule_zone(tzrule_zone&& src)
    : name_(std::move(src.name_))
    , zonelets_(std::move(src.zonelets_))
#if LAZY_INIT
    , adjusted_(std::move(src.adjusted_))
#endif
    {}

inline
tzrule_zone&
tzrule_zone::operator=(tzrule_zone&& src)
{
    name_ = std::move(src.name_);
    zonelets_ = std::move(src.zonelets_);
#if LAZY_INIT
    adjusted_ = std::move(src.adjusted_);
#endif
    return *this;
}

#endif  // defined(_MSC_VER) && (_MSC_VER < 1900)

inline
const std::string&
tzrule_zone::name() const NOEXCEPT
{
    return name_;
}

template <class Duration>
inline
sys_info
tzrule_zone::get_info(sys_time<Duration> st) const
{
    using namespace std::chrono;
    return get_info_impl(floor<seconds>(st));
}

template <class Duration>
inline
local_info
tzrule_zone::get_info(local_time<Duration> tp) const
{
    using namespace std::chrono;
    return get_info_impl(floor<seconds>(tp));
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzrule_zone::to_sys(local_time<Duration> tp) const
{
    return to_sys_impl(tp, choose{}, std::true_type{});
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzrule_zone::to_sys(local_time<Duration> tp, choose z) const
{
    return to_sys_impl(tp, z, std::false_type{});
}

template <class Duration>
inline
local_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzrule_zone::to_local(sys_time<Duration> tp) const
{
    using LT = local_time<typename std::common_type<Duration, std::chrono::seconds>::type>;
    auto i = get_info(tp);
    return LT{(tp + i.offset).time_since_epoch()};
}

inline bool operator==(const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return x.name_ == y.name_;}
inline bool operator< (const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return x.name_ < y.name_;}

inline bool operator!=(const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return !(x == y);}
inline bool operator> (const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return   y < x;}
inline bool operator<=(const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return !(y < x);}
inline bool operator>=(const tzrule_zone& x, const tzrule_zone& y) NOEXCEPT {return !(x < y);}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzrule_zone::to_sys_impl(local_time<Duration> tp, choose z, std::false_type) const
{
    using namespace date;
    using namespace std::chrono;
    auto i = get_info(tp);
    if (i.result == local_info::nonexistent)
    {
        return i.first.end;
    }
    else if (i.result == local_info::ambiguous)
    {
        if (z == choose::latest)
            return sys_time<Duration>{tp.time_since_epoch()} - i.second.offset;
    }
    return sys_time<Duration>{tp.time_since_epoch()} - i.first.offset;
}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tzrule_zone::to_sys_impl(local_time<Duration> tp, choose, std::true_type) const
{
    using namespace date;
    using namespace std::chrono;
    auto i = get_info(tp);
    if (i.result == local_info::nonexistent)
    {
        auto prev_end = local_seconds{i.first.end.time_since_epoch()} +
                        i.first.offset;
        auto next_begin = local_seconds{i.second.begin.time_since_epoch()} +
                          i.second.offset;
        throw nonexistent_local_time(tp, prev_end, i.first.abbrev,
                                         next_begin, i.second.abbrev, i.first.end);
    }
    else if (i.result == local_info::ambiguous)
    {
        throw ambiguous_local_time(tp, i.first.offset, i.first.abbrev,
                                       i.second.offset, i.second.abbrev);
    }
    return sys_time<Duration>{tp.time_since_epoch()} - i.first.offset;
}

#endif // TIMEZONE_RULES

class link
{
private:
    std::string name_;
    std::string target_;
public:
    DATE_API explicit link(const std::string& s);

    const std::string& name() const {return name_;}
    const std::string& target() const {return target_;}

    friend bool operator==(const link& x, const link& y) {return x.name_ == y.name_;}
    friend bool operator< (const link& x, const link& y) {return x.name_ < y.name_;}

    friend DATE_API std::ostream& operator<<(std::ostream& os, const link& x);
};

inline bool operator!=(const link& x, const link& y) {return !(x == y);}
inline bool operator> (const link& x, const link& y) {return   y < x;}
inline bool operator<=(const link& x, const link& y) {return !(y < x);}
inline bool operator>=(const link& x, const link& y) {return !(x < y);}

class leap
{
private:
    sys_seconds date_;

public:
    DATE_API explicit leap(const std::string& s, detail::undocumented);
#if TIMEZONE_FILES
    DATE_API explicit leap(const sys_seconds& date);
    template <class Duration>
    leap& operator-=(const Duration& d);
#endif

    sys_seconds date() const {return date_;}

    friend bool operator==(const leap& x, const leap& y) {return x.date_ == y.date_;}
    friend bool operator< (const leap& x, const leap& y) {return x.date_ < y.date_;}

    template <class Duration>
    friend
    bool
    operator==(const leap& x, const sys_time<Duration>& y)
    {
        return x.date_ == y;
    }

    template <class Duration>
    friend
    bool
    operator< (const leap& x, const sys_time<Duration>& y)
    {
        return x.date_ < y;
    }

    template <class Duration>
    friend
    bool
    operator< (const sys_time<Duration>& x, const leap& y)
    {
        return x < y.date_;
    }

    friend DATE_API std::ostream& operator<<(std::ostream& os, const leap& x);
};

#if TIMEZONE_FILES

inline leap::leap(const sys_seconds& date)
    : date_{date}
{}

template <class Duration>
leap& leap::operator-=(const Duration& d)
{
    date_ -= d;
    return *this;
}

#endif // TIMEZONE_FILES

inline bool operator!=(const leap& x, const leap& y) {return !(x == y);}
inline bool operator> (const leap& x, const leap& y) {return   y < x;}
inline bool operator<=(const leap& x, const leap& y) {return !(y < x);}
inline bool operator>=(const leap& x, const leap& y) {return !(x < y);}

template <class Duration>
inline
bool
operator==(const sys_time<Duration>& x, const leap& y)
{
    return y == x;
}

template <class Duration>
inline
bool
operator!=(const leap& x, const sys_time<Duration>& y)
{
    return !(x == y);
}

template <class Duration>
inline
bool
operator!=(const sys_time<Duration>& x, const leap& y)
{
    return !(x == y);
}

template <class Duration>
inline
bool
operator> (const leap& x, const sys_time<Duration>& y)
{
    return y < x;
}

template <class Duration>
inline
bool
operator> (const sys_time<Duration>& x, const leap& y)
{
    return y < x;
}

template <class Duration>
inline
bool
operator<=(const leap& x, const sys_time<Duration>& y)
{
    return !(y < x);
}

template <class Duration>
inline
bool
operator<=(const sys_time<Duration>& x, const leap& y)
{
    return !(y < x);
}

template <class Duration>
inline
bool
operator>=(const leap& x, const sys_time<Duration>& y)
{
    return !(x < y);
}

template <class Duration>
inline
bool
operator>=(const sys_time<Duration>& x, const leap& y)
{
    return !(x < y);
}

#if TIMEZONE_MAPPING

namespace detail
{

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

}  // detail

#endif  // TIMEZONE_MAPPING

#if TIMEZONE_RULES

class tzrule_db
{
public:
    std::string               version;
    std::vector<tzrule_zone>  zones;
    std::vector<link>         links;
    std::vector<leap>         leaps;
    std::vector<detail::Rule> rules;
#if TIMEZONE_MAPPING
    // TODO! These need some protection.
    std::vector<detail::timezone_mapping> mappings;
#endif

    tzrule_db() = default;
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzrule_db(tzrule_db&&) = default;
    tzrule_db& operator=(tzrule_db&&) = default;
#else  // defined(_MSC_VER) || (_MSC_VER >= 1900)
    tzrule_db(tzrule_db&& src)
        : version(std::move(src.version))
        , zones(std::move(src.zones))
        , links(std::move(src.links))
        , leaps(std::move(src.leaps))
        , rules(std::move(src.rules))
#if TIMEZONE_MAPPING
        , mappings(std::move(src.mappings))
#endif
    {}

    tzrule_db& operator=(tzrule_db&& src)
    {
        version = std::move(src.version);
        zones = std::move(src.zones);
        links = std::move(src.links);
        leaps = std::move(src.leaps);
        rules = std::move(src.rules);
#if TIMEZONE_MAPPING
        mappings = std::move(src.mappings);
#endif
        return *this;
    }
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)

    DATE_API static const tzrule_zone* locate_zone(const std::string& tz_name);
#ifdef TZ_TEST
#  if _WIN32
    DATE_API static const tzrule_zone* locate_native_zone(const std::string& native_tz_name);
#  endif // _WIN32
#endif // TZ_TEST
    DATE_API static const tzrule_zone* current_zone();
    
    DATE_API static const tzrule_db& get_tzdb();
    DATE_API static const tzrule_db& reload_tzdb();
    DATE_API static tzrule_db init_tzdb();

    DATE_API static void        set_install(const std::string& install);

#if HAS_REMOTE_API
    DATE_API static std::string remote_version();
    DATE_API static bool        remote_download(const std::string& version);
    DATE_API static bool        remote_install(const std::string& version);
#endif

};

DATE_API std::ostream&
operator<<(std::ostream& os, const tzrule_db& db);

inline
void set_install(const std::string& install)
{ return tzrule_db::set_install(install); }

#if HAS_REMOTE_API
inline
std::string remote_version()
{ return tzrule_db::remote_version(); }

inline
bool remote_download(const std::string& version)
{ return tzrule_db::remote_download(version); }

inline
bool remote_install(const std::string& version)
{ return tzrule_db::remote_install(version); }
#endif

inline
const tzrule_db& tzrule_zone::get_tzdb()
{ return tzrule_db::get_tzdb(); }

inline
const tzrule_db& tzrule_zone::reload_tzdb()
{ return tzrule_db::reload_tzdb(); }

inline
tzrule_db tzrule_zone::init_tzdb()
{ return tzrule_db::init_tzdb(); }

inline
const tzrule_zone* tzrule_zone::locate_zone(const std::string& tz_name)
{ return tzrule_db::locate_zone(tz_name); }

inline
const tzrule_zone* tzrule_zone::current_zone()
{ return tzrule_db::current_zone(); }

#ifdef TZ_TEST
#  if _WIN32
inline
const tzrule_zone* locate_native_zone(const std::string& native_tz_name)
{ return tzrule_db::locate_native_zone(native_tz_name); }
#  endif // _WIN32
#endif // TZ_TEST

#endif // TIMEZONE_RULES

#if TIMEZONE_DEFAULT == 0
typedef tzfile_zone time_zone;
typedef tzfile_db TZ_DB;
#elif TIMEZONE_DEFAULT == 1
typedef tzrule_db TZ_DB;
typedef tzrule_zone time_zone;
#else
static_assert(false, "TIMEZONE_DEFAULT must be between 0 and 1");
#endif

template<class Duration>
using zoned_time = basic_zoned_time<Duration, time_zone>;

typedef basic_zoned_seconds<time_zone> zoned_seconds;

inline
const time_zone* locate_zone(const std::string& tz_name)
{ return TZ_DB::locate_zone(tz_name); }

inline
const time_zone* current_zone()
{ return TZ_DB::current_zone(); }

// zoned_time

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const sys_time<Duration>& st)
    : zone_(TimeZone::locate_zone("UTC"))
    , tp_(st)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const TimeZone* z)
    : zone_(z)
    {assert(zone_ != nullptr);}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name)
    : basic_zoned_time(TimeZone::locate_zone(name))
    {}

template <class Duration, class TimeZone>
template <class Duration2, class>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const basic_zoned_time<Duration2,TimeZone>& zt) NOEXCEPT
    : zone_(zt.zone_)
    , tp_(zt.tp_)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration, TimeZone>::basic_zoned_time(const TimeZone* z, const local_time<Duration>& t)
    : zone_(z)
    , tp_(z->to_sys(t))
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name, const local_time<Duration>& t)
    : basic_zoned_time(TimeZone::locate_zone(name), t)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const char* name, const local_time<Duration>& t)
    : basic_zoned_time(TimeZone::locate_zone(name), t)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const TimeZone* z, const local_time<Duration>& t,
                                 choose c)
    : zone_(z)
    , tp_(z->to_sys(t, c))
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name, const local_time<Duration>& t,
                                 choose c)
    : basic_zoned_time(TimeZone::locate_zone(name), t, c)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const char* name, const local_time<Duration>& t,
                                 choose c)
    : basic_zoned_time(TimeZone::locate_zone(name), t, c)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const TimeZone* z, const basic_zoned_time<Duration,TimeZone>& zt)
    : zone_(z)
    , tp_(zt.tp_)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name, const basic_zoned_time<Duration,TimeZone>& zt)
    : basic_zoned_time(TimeZone::locate_zone(name), zt)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const char* name, const basic_zoned_time<Duration,TimeZone>& zt)
    : basic_zoned_time(TimeZone::locate_zone(name), zt)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const TimeZone* z, const basic_zoned_time<Duration,TimeZone>& zt, choose)
    : basic_zoned_time(z, zt)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name,
                                 const basic_zoned_time<Duration,TimeZone>& zt, choose c)
    : basic_zoned_time(TimeZone::locate_zone(name), zt, c)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const char* name,
                                 const basic_zoned_time<Duration,TimeZone>& zt, choose c)
    : basic_zoned_time(TimeZone::locate_zone(name), zt, c)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const TimeZone* z, const sys_time<Duration>& st)
    : zone_(z)
    , tp_(st)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const std::string& name, const sys_time<Duration>& st)
    : basic_zoned_time(TimeZone::locate_zone(name), st)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::basic_zoned_time(const char* name, const sys_time<Duration>& st)
    : basic_zoned_time(TimeZone::locate_zone(name), st)
    {}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>&
basic_zoned_time<Duration,TimeZone>::operator=(const sys_time<Duration>& st)
{
    tp_ = st;
    return *this;
}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>&
basic_zoned_time<Duration,TimeZone>::operator=(const local_time<Duration>& ut)
{
    tp_ = zone_->to_sys(ut);
    return *this;
}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::operator local_time<Duration>() const
{
    return get_local_time();
}

template <class Duration, class TimeZone>
inline
basic_zoned_time<Duration,TimeZone>::operator sys_time<Duration>() const
{
    return get_sys_time();
}

template <class Duration, class TimeZone>
inline
const TimeZone*
basic_zoned_time<Duration,TimeZone>::get_time_zone() const
{
    return zone_;
}

template <class Duration, class TimeZone>
inline
local_time<Duration>
basic_zoned_time<Duration,TimeZone>::get_local_time() const
{
    return zone_->to_local(tp_);
}

template <class Duration, class TimeZone>
inline
sys_time<Duration>
basic_zoned_time<Duration,TimeZone>::get_sys_time() const
{
    return tp_;
}

template <class Duration, class TimeZone>
inline
sys_info
basic_zoned_time<Duration,TimeZone>::get_info() const
{
    return zone_->get_info(tp_);
}

// make_zoned_time

template <class Duration>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,time_zone>
make_zoned(const sys_time<Duration>& tp)
{
    return {tp};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const sys_time<Duration>& tp)
{
    return {tp};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const TimeZone* zone, const local_time<Duration>& tp)
{
    return {zone, tp};
}

template <class Duration>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,time_zone>
make_zoned(const std::string& name, const local_time<Duration>& tp)
{
    return {name, tp};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const std::string& name, const local_time<Duration>& tp)
{
    return {name, tp};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const TimeZone* zone, const local_time<Duration>& tp, choose c)
{
    return {zone, tp, c};
}

template <class Duration>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,time_zone>
make_zoned(const std::string& name, const local_time<Duration>& tp, choose c)
{
    return {name, tp, c};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const std::string& name, const local_time<Duration>& tp, choose c)
{
    return {name, tp, c};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const TimeZone* zone, const basic_zoned_time<Duration,TimeZone>& zt)
{
    return {zone, zt};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const std::string& name, const basic_zoned_time<Duration,TimeZone>& zt)
{
    return {name, zt};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const TimeZone* zone, const basic_zoned_time<Duration,TimeZone>& zt, choose c)
{
    return {zone, zt, c};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const std::string& name, const basic_zoned_time<Duration,TimeZone>& zt, choose c)
{
    return {name, zt, c};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const TimeZone* zone, const sys_time<Duration>& st)
{
    return {zone, st};
}

template <class Duration>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,time_zone>
make_zoned(const std::string& name, const sys_time<Duration>& st)
{
    return {name, st};
}

template <class TimeZone, class Duration, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
inline
basic_zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type,TimeZone>
make_zoned(const std::string& name, const sys_time<Duration>& st)
{
    return {name, st};
}

template <class CharT, class Traits, class Duration, class TimeZone, typename std::enable_if<std::is_base_of<detail::time_zone_tag,TimeZone>::value,int>::type = 0>
void
to_stream(std::basic_ostream<CharT, Traits>& os, const CharT* fmt,
          const basic_zoned_time<Duration,TimeZone>& tp)
{
    auto const info = tp.get_info();
    to_stream(os, fmt, tp.get_local_time(), &info.abbrev, &info.offset);
}

class utc_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<utc_clock>;
    static CONSTDATA bool is_steady = false;

    static time_point now();
};

template <class Duration>
    using utc_time = std::chrono::time_point<utc_clock, Duration>;

using utc_seconds = utc_time<std::chrono::seconds>;

template <class Duration, class Tzdb=
#if TIMEZONE_DEFAULT == 0 && DATE_TIMEZONE_FILES_NO_LEAP && TIMEZONE_RULES
tzrule_db
#else
TZ_DB
#endif
>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(const sys_time<Duration>& st)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto const& leaps = Tzdb::get_tzdb().leaps;
    auto const lt = std::upper_bound(leaps.begin(), leaps.end(), st);
    return utc_time<duration>{st.time_since_epoch() + seconds{lt-leaps.begin()}};
}

// Return pair<is_leap_second, seconds{number_of_leap_seconds_since_1970}>
// first is true if ut is during a leap second insertion, otherwise false.
// If ut is during a leap second insertion, that leap second is included in the count
template <class Duration, class Tzdb=
#if TIMEZONE_DEFAULT == 0 && DATE_TIMEZONE_FILES_NO_LEAP && TIMEZONE_RULES
tzrule_db
#else
TZ_DB
#endif
>
std::pair<bool, std::chrono::seconds>
is_leap_second(date::utc_time<Duration> const& ut)
{
    using namespace date;
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto const& leaps = Tzdb::get_tzdb().leaps;
    auto tp = sys_time<duration>{ut.time_since_epoch()};
    auto const lt = std::upper_bound(leaps.begin(), leaps.end(), tp);
    auto ds = seconds{lt-leaps.begin()};
    tp -= ds;
    auto ls = false;
    if (lt > leaps.begin())
    {
        if (tp < lt[-1])
        {
            if (tp >= lt[-1].date() - seconds{1})
                ls = true;
            else
                --ds;
        }
    }
    return {ls, ds};
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(const utc_time<Duration>& ut)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto ls = is_leap_second(ut);
    auto tp = sys_time<duration>{ut.time_since_epoch() - ls.second};
    if (ls.first)
        tp = floor<seconds>(tp) + seconds{1} - duration{1};
    return tp;
}

inline
utc_clock::time_point
utc_clock::now()
{
    using namespace std::chrono;
    return to_utc_time(system_clock::now());
}

template <class CharT, class Traits, class Duration>
void
to_stream(std::basic_ostream<CharT, Traits>& os, const CharT* fmt,
          const utc_time<Duration>& t)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    const string abbrev("UTC");
    CONSTDATA seconds offset{0};
    auto ls = is_leap_second(t);
    auto tp = sys_time<CT>{t.time_since_epoch() - ls.second};
    auto const sd = floor<days>(tp);
    year_month_day ymd = sd;
    auto time = make_time(tp - sd);
    time.seconds() += seconds{ls.first};
    fields<CT> fds{ymd, time};
    to_stream(os, fmt, fds, &abbrev, &offset);
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const utc_time<Duration>& t)
{
    to_stream(os, "%F %T", t);
    return os;
}

template <class Duration, class CharT, class Traits, class Alloc = std::allocator<CharT>>
void
from_stream(std::basic_istream<CharT, Traits>& is, const CharT* fmt,
            utc_time<Duration>& tp, std::basic_string<CharT, Traits, Alloc>* abbrev = nullptr,
            std::chrono::minutes* offset = nullptr)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    minutes offset_local{};
    auto offptr = offset ? offset : &offset_local;
    fields<CT> fds{};
    from_stream(is, fmt, fds, abbrev, offptr);
    if (!fds.ymd.ok())
        is.setstate(ios::failbit);
    if (!is.fail())
    {
        bool is_60_sec = fds.tod.seconds() == seconds{60};
        if (is_60_sec)
            fds.tod.seconds() -= seconds{1};
        auto tmp = to_utc_time(sys_days(fds.ymd) + (fds.tod.to_duration() - *offptr));
        if (is_60_sec)
            tmp += seconds{1};
        if (is_60_sec != is_leap_second(tmp).first || !fds.tod.in_conventional_range())
        {
            is.setstate(ios::failbit);
            return;
        }
        tp = time_point_cast<Duration>(tmp);
    }
}

// tai_clock

class tai_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<tai_clock>;
    static const bool is_steady     = false;

    static time_point now() NOEXCEPT;
};

template <class Duration>
    using tai_time = std::chrono::time_point<tai_clock, Duration>;

using tai_seconds = tai_time<std::chrono::seconds>;

template <class Duration>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(const tai_time<Duration>& t) NOEXCEPT
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return utc_time<duration>{t.time_since_epoch()} -
            (sys_days(year{1970}/jan/1) - sys_days(year{1958}/jan/1) + seconds{10});
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(const utc_time<Duration>& t) NOEXCEPT
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return tai_time<duration>{t.time_since_epoch()} +
            (sys_days(year{1970}/jan/1) - sys_days(year{1958}/jan/1) + seconds{10});
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(const sys_time<Duration>& t)
{
    return to_tai_time(to_utc_time(t));
}

inline
tai_clock::time_point
tai_clock::now() NOEXCEPT
{
    using namespace std::chrono;
    return to_tai_time(system_clock::now());
}

template <class CharT, class Traits, class Duration>
void
to_stream(std::basic_ostream<CharT, Traits>& os, const CharT* fmt,
          const tai_time<Duration>& t)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    const string abbrev("TAI");
    CONSTDATA seconds offset{0};
    auto tp = sys_time<CT>{t.time_since_epoch()} -
              (sys_days(year{1970}/jan/1) - sys_days(year{1958}/jan/1));
    auto const sd = floor<days>(tp);
    year_month_day ymd = sd;
    auto time = make_time(tp - sd);
    fields<CT> fds{ymd, time};
    to_stream(os, fmt, fds, &abbrev, &offset);
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const tai_time<Duration>& t)
{
    to_stream(os, "%F %T", t);
    return os;
}

template <class Duration, class CharT, class Traits, class Alloc = std::allocator<CharT>>
void
from_stream(std::basic_istream<CharT, Traits>& is, const CharT* fmt,
            tai_time<Duration>& tp,
            std::basic_string<CharT, Traits, Alloc>* abbrev = nullptr,
            std::chrono::minutes* offset = nullptr)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    minutes offset_local{};
    auto offptr = offset ? offset : &offset_local;
    fields<CT> fds{};
    from_stream(is, fmt, fds, abbrev, offptr);
    if (!fds.ymd.ok() || !fds.tod.in_conventional_range())
        is.setstate(ios::failbit);
    if (!is.fail())
        tp = tai_time<Duration>{duration_cast<Duration>(
                (sys_days(fds.ymd) + fds.tod.to_duration() + (sys_days(year{1970}/jan/1) -
                sys_days(year{1958}/jan/1)) - *offptr).time_since_epoch())};
}

// gps_clock

class gps_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<gps_clock>;
    static const bool is_steady     = false;

    static time_point now() NOEXCEPT;
};

template <class Duration>
    using gps_time = std::chrono::time_point<gps_clock, Duration>;

using gps_seconds = gps_time<std::chrono::seconds>;

template <class Duration>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(const gps_time<Duration>& t) NOEXCEPT
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return utc_time<duration>{t.time_since_epoch()} +
            (sys_days(year{1980}/jan/sun[1]) - sys_days(year{1970}/jan/1) + seconds{9});
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(const utc_time<Duration>& t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return gps_time<duration>{t.time_since_epoch()} -
            (sys_days(year{1980}/jan/sun[1]) - sys_days(year{1970}/jan/1) + seconds{9});
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(const sys_time<Duration>& t)
{
    return to_gps_time(to_utc_time(t));
}

inline
gps_clock::time_point
gps_clock::now() NOEXCEPT
{
    using namespace std::chrono;
    return to_gps_time(system_clock::now());
}

template <class CharT, class Traits, class Duration>
void
to_stream(std::basic_ostream<CharT, Traits>& os, const CharT* fmt,
          const gps_time<Duration>& t)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    const string abbrev("GPS");
    CONSTDATA seconds offset{0};
    auto tp = sys_time<CT>{t.time_since_epoch()} +
              (sys_days(year{1980}/jan/sun[1]) - sys_days(year{1970}/jan/1));
    auto const sd = floor<days>(tp);
    year_month_day ymd = sd;
    auto time = make_time(tp - sd);
    fields<CT> fds{ymd, time};
    to_stream(os, fmt, fds, &abbrev, &offset);
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const gps_time<Duration>& t)
{
    to_stream(os, "%F %T", t);
    return os;
}

template <class Duration, class CharT, class Traits, class Alloc = std::allocator<CharT>>
void
from_stream(std::basic_istream<CharT, Traits>& is, const CharT* fmt,
            gps_time<Duration>& tp,
            std::basic_string<CharT, Traits, Alloc>* abbrev = nullptr,
            std::chrono::minutes* offset = nullptr)
{
    using namespace std;
    using namespace std::chrono;
    using CT = typename common_type<Duration, seconds>::type;
    minutes offset_local{};
    auto offptr = offset ? offset : &offset_local;
    fields<CT> fds{};
    from_stream(is, fmt, fds, abbrev, offptr);
    if (!fds.ymd.ok() || !fds.tod.in_conventional_range())
        is.setstate(ios::failbit);
    if (!is.fail())
        tp = gps_time<Duration>{duration_cast<Duration>(
                (sys_days(fds.ymd) + fds.tod.to_duration() -
                (sys_days(year{1980}/jan/sun[1]) -
                sys_days(year{1970}/jan/1)) - *offptr).time_since_epoch())};
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(const tai_time<Duration>& t)
{
    return to_sys_time(to_utc_time(t));
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(const gps_time<Duration>& t)
{
    return to_sys_time(to_utc_time(t));
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(const gps_time<Duration>& t) NOEXCEPT
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return tai_time<duration>{t.time_since_epoch()} +
            (sys_days(year{1980}/jan/sun[1]) - sys_days(year{1958}/jan/1) + seconds{19});
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(const tai_time<Duration>& t) NOEXCEPT
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return gps_time<duration>{t.time_since_epoch()} -
            (sys_days(year{1980}/jan/sun[1]) - sys_days(year{1958}/jan/1) + seconds{19});
}

}  // namespace date

#endif  // TZ_H
