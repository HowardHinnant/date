#ifndef TZ_H
#define TZ_H

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

// Get more recent database at http://www.iana.org/time-zones

// The notion of "current timezone" is something the operating system is expected to "just
// know". How it knows this is system specific. It's often a value set by the user at OS
// intallation time and recorded by the OS somewhere. On Linux and Mac systems the current
// timezone name is obtained by looking at the name or contents of a particular file on
// disk. On Windows the current timzeone name comes from the registry. In either method,
// there is no guarantee that the "native" current timezone name obtained will match any
// of the "Standard" names in this library's "database". On Linux, the names usually do
// seem to match so mapping functions to map from native to "Standard" are typically not
// required. On Windows, the names are never "Standard" so mapping is always required.
// Technically any OS may use the mapping process but currently only Windows does use it.

#ifdef _WIN32
#  ifndef TIMEZONE_MAPPING
#    define TIMEZONE_MAPPING 1
#  endif
#else
#  ifdef TIMEZONE_MAPPING
#    error "Timezone mapping is not required or not implemented for this platform."
#  endif
#endif

#ifndef LAZY_INIT
#  define LAZY_INIT 1
#endif

#ifndef HAS_REMOTE_API
#  ifdef _WIN32
#    define HAS_REMOTE_API 0
#  else
#    define HAS_REMOTE_API 1
#  endif
#endif

#ifndef AUTO_DOWNLOAD
#  define AUTO_DOWNLOAD HAS_REMOTE_API
#endif

static_assert(HAS_REMOTE_API == 0 ? AUTO_DOWNLOAD == 0 : true,
              "AUTO_DOWNLOAD can not be turned on without HAS_REMOTE_API");

#ifndef USE_SHELL_API
#  define USE_SHELL_API 0
#endif

#include "date.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <istream>
#include <locale>
#include <ostream>
#include <ratio>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#if LAZY_INIT
#  include <memory>
#  include <mutex>
#endif
#include <time.h>

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
                                               local_seconds first,
                                               const std::string& first_abbrev,
                                               local_seconds last,
                                               const std::string& last_abbrev,
                                               sys_seconds time_sys)
    : std::runtime_error(make_msg(tp, first, first_abbrev, last, last_abbrev, time_sys))
    {}

template <class Duration>
std::string
nonexistent_local_time::make_msg(local_time<Duration> tp, local_seconds first,
                                 const std::string& first_abbrev, local_seconds last,
                                 const std::string& last_abbrev, sys_seconds time_sys)
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

class Rule;

struct sys_info
{
    sys_seconds          begin;
    sys_seconds          end;
    std::chrono::seconds offset;
    std::chrono::minutes save;
    std::string          abbrev;
};

std::ostream& operator<<(std::ostream& os, const sys_info& r);

struct local_info
{
    enum {unique, nonexistent, ambiguous} result;
    sys_info first;
    sys_info second;
};

std::ostream& operator<<(std::ostream& os, const local_info& r);

class time_zone;

template <class Duration>
class zoned_time
{
    const time_zone*   zone_;
    sys_time<Duration> tp_;

public:
             zoned_time(sys_time<Duration> st);
    explicit zoned_time(const time_zone* z);
    explicit zoned_time(const std::string& name);

    template <class Duration2,
              class = typename std::enable_if
                      <
                          std::is_convertible<sys_time<Duration2>,
                                              sys_time<Duration>>::value
                      >::type>
        zoned_time(const zoned_time<Duration2>& zt) NOEXCEPT;

    zoned_time(const time_zone* z,      local_time<Duration> tp);
    zoned_time(const std::string& name, local_time<Duration> tp);
    zoned_time(const time_zone* z,      local_time<Duration> tp, choose c);
    zoned_time(const std::string& name, local_time<Duration> tp, choose c);

    zoned_time(const time_zone* z,      const zoned_time<Duration>& zt);
    zoned_time(const std::string& name, const zoned_time<Duration>& zt);
    zoned_time(const time_zone* z,      const zoned_time<Duration>& zt, choose);
    zoned_time(const std::string& name, const zoned_time<Duration>& zt, choose);

    zoned_time(const time_zone* z,      const sys_time<Duration>& st);
    zoned_time(const std::string& name, const sys_time<Duration>& st);

    zoned_time& operator=(sys_time<Duration> st);
    zoned_time& operator=(local_time<Duration> ut);

             operator sys_time<Duration>() const;
    explicit operator local_time<Duration>() const;

    const time_zone*     get_time_zone() const;
    local_time<Duration> get_local_time() const;
    sys_time<Duration>   get_sys_time() const;
    sys_info             get_info() const;

    template <class Duration1, class Duration2>
    friend
    bool
    operator==(const zoned_time<Duration1>& x, const zoned_time<Duration2>& y);

    template <class CharT, class Traits, class Duration1>
    friend
    std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, const zoned_time<Duration1>& t);

private:
    template <class D> friend class zoned_time;

    static_assert(std::is_convertible<std::chrono::seconds, Duration>::value,
                  "zoned_time must have a precision of seconds or finer");
};

using zoned_seconds = zoned_time<std::chrono::seconds>;

template <class Duration1, class Duration2>
inline
bool
operator==(const zoned_time<Duration1>& x, const zoned_time<Duration2>& y)
{
    return x.zone_ == y.zone_ && x.tp_ == y.tp_;
}

template <class Duration1, class Duration2>
inline
bool
operator!=(const zoned_time<Duration1>& x, const zoned_time<Duration2>& y)
{
    return !(x == y);
}

class time_zone
{
private:
    struct zonelet;

    std::string          name_;
    std::vector<zonelet> zonelets_;
#if LAZY_INIT
    std::unique_ptr<std::once_flag> adjusted_;
#endif

public:
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    time_zone(time_zone&&) = default;
    time_zone& operator=(time_zone&&) = default;
#else   // defined(_MSC_VER) && (_MSC_VER < 1900)
    time_zone(time_zone&& src);
    time_zone& operator=(time_zone&& src);
#endif  // defined(_MSC_VER) && (_MSC_VER < 1900)

    explicit time_zone(const std::string& s, detail::undocumented);

    const std::string& name() const;

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

    friend bool operator==(const time_zone& x, const time_zone& y);
    friend bool operator< (const time_zone& x, const time_zone& y);
    friend std::ostream& operator<<(std::ostream& os, const time_zone& z);

    void add(const std::string& s);
    void adjust_infos(const std::vector<Rule>& rules);

private:
    sys_info   get_info_impl(sys_seconds tp) const;
    local_info get_info_impl(local_seconds tp) const;
    sys_info   get_info_impl(sys_seconds tp, int timezone) const;

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
time_zone::time_zone(time_zone&& src)
    : name_(std::move(src.name_))
    , zonelets_(std::move(src.zonelets_))
#if LAZY_INIT
    , adjusted_(std::move(src.adjusted_))
#endif
    {}

inline
time_zone&
time_zone::operator=(time_zone&& src)
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
time_zone::name() const
{
    return name_;
}

template <class Duration>
inline
sys_info
time_zone::get_info(sys_time<Duration> st) const
{
    using namespace std::chrono;
    return get_info_impl(floor<seconds>(st));
}

template <class Duration>
inline
local_info
time_zone::get_info(local_time<Duration> tp) const
{
    using namespace std::chrono;
    return get_info_impl(floor<seconds>(tp));
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
time_zone::to_sys(local_time<Duration> tp) const
{
    return to_sys_impl(tp, choose{}, std::true_type{});
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
time_zone::to_sys(local_time<Duration> tp, choose z) const
{
    return to_sys_impl(tp, z, std::false_type{});
}

template <class Duration>
inline
local_time<typename std::common_type<Duration, std::chrono::seconds>::type>
time_zone::to_local(sys_time<Duration> tp) const
{
    using LT = local_time<typename std::common_type<Duration, std::chrono::seconds>::type>;
    auto i = get_info(tp);
    return LT{(tp + i.offset).time_since_epoch()};
}

inline bool operator==(const time_zone& x, const time_zone& y) {return x.name_ == y.name_;}
inline bool operator< (const time_zone& x, const time_zone& y) {return x.name_ < y.name_;}

inline bool operator!=(const time_zone& x, const time_zone& y) {return !(x == y);}
inline bool operator> (const time_zone& x, const time_zone& y) {return   y < x;}
inline bool operator<=(const time_zone& x, const time_zone& y) {return !(y < x);}
inline bool operator>=(const time_zone& x, const time_zone& y) {return !(x < y);}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
time_zone::to_sys_impl(local_time<Duration> tp, choose z, std::false_type) const
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
time_zone::to_sys_impl(local_time<Duration> tp, choose, std::true_type) const
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

class link
{
private:
    std::string name_;
    std::string target_;
public:
    explicit link(const std::string& s);

    const std::string& name() const {return name_;}
    const std::string& target() const {return target_;}

    friend bool operator==(const link& x, const link& y) {return x.name_ == y.name_;}
    friend bool operator< (const link& x, const link& y) {return x.name_ < y.name_;}

    friend std::ostream& operator<<(std::ostream& os, const link& x);
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
    explicit leap(const std::string& s, detail::undocumented);

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

    friend std::ostream& operator<<(std::ostream& os, const leap& x);
};

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

#ifdef TIMEZONE_MAPPING

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

struct timezone_info
{
    timezone_info() = default;
    std::string timezone_id;
    std::string standard_name;
};

}  // detail

#endif  // TIMEZONE_MAPPING

struct TZ_DB
{
    std::string            version;
    std::vector<time_zone> zones;
    std::vector<link>      links;
    std::vector<leap>      leaps;
    std::vector<Rule>      rules;
#ifdef TIMEZONE_MAPPING
    // TODO! These need some protection.
    std::vector<detail::timezone_mapping> mappings;
    std::vector<detail::timezone_info> native_zones;
#endif

    TZ_DB() = default;
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    TZ_DB(TZ_DB&&) = default;
    TZ_DB& operator=(TZ_DB&&) = default;
#else  // defined(_MSC_VER) || (_MSC_VER >= 1900)
    TZ_DB(TZ_DB&& src)
    :
        version(std::move(src.version)),
        zones(std::move(src.zones)),
        links(std::move(src.links)),
        leaps(std::move(src.leaps)),
        rules(std::move(src.rules))
#ifdef TIMEZONE_MAPPING
        ,
        mappings(std::move(src.mappings)),
        native_zones(std::move(src.native_zones))
#endif
    {}

    TZ_DB& operator=(TZ_DB&& src)
    {
        version = std::move(src.version);
        zones = std::move(src.zones);
        links = std::move(src.links);
        leaps = std::move(src.leaps);
        rules = std::move(src.rules);
#ifdef TIMEZONE_MAPPING
        mappings = std::move(src.mappings);
        native_zones = std::move(src.native_zones);
#endif
        return *this;
    }
#endif  // !defined(_MSC_VER) || (_MSC_VER >= 1900)
};

std::ostream&
operator<<(std::ostream& os, const TZ_DB& db);

const TZ_DB& get_tzdb();
const TZ_DB& reload_tzdb();

#if HAS_REMOTE_API
std::string remote_version();
bool        remote_download(const std::string& version);
bool        remote_install(const std::string& version);
#endif

const time_zone* locate_zone(const std::string& tz_name);
#ifdef TZ_TEST
#  if _WIN32
const time_zone* locate_native_zone(const std::string& native_tz_name);
#  endif // _WIN32
#endif // TZ_TEST
const time_zone* current_zone();

// zoned_time

template <class Duration>
inline
zoned_time<Duration>::zoned_time(sys_time<Duration> st)
    : zone_(locate_zone("UTC"))
    , tp_(st)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z)
    : zone_(z)
    {assert(zone_ != nullptr);}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name)
    : zoned_time(locate_zone(name))
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z, local_time<Duration> t)
    : zone_(z)
    , tp_(z->to_sys(t))
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name, local_time<Duration> t)
    : zoned_time(locate_zone(name), t)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z, local_time<Duration> t, choose c)
    : zone_(z)
    , tp_(z->to_sys(t, c))
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name, local_time<Duration> t,
                                 choose c)
    : zoned_time(locate_zone(name), t, c)
    {}

template <class Duration>
template <class Duration2, class>
inline
zoned_time<Duration>::zoned_time(const zoned_time<Duration2>& zt) NOEXCEPT
    : zone_(zt.zone_)
    , tp_(zt.tp_)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z, const zoned_time<Duration>& zt)
    : zone_(z)
    , tp_(zt.tp_)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name, const zoned_time<Duration>& zt)
    : zoned_time(locate_zone(name), zt)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z, const zoned_time<Duration>& zt, choose)
    : zoned_time(z, zt)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name,
                                 const zoned_time<Duration>& zt, choose c)
    : zoned_time(locate_zone(name), zt, c)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const time_zone* z, const sys_time<Duration>& st)
    : zone_(z)
    , tp_(st)
    {}

template <class Duration>
inline
zoned_time<Duration>::zoned_time(const std::string& name, const sys_time<Duration>& st)
    : zoned_time(locate_zone(name), st)
    {}


template <class Duration>
inline
zoned_time<Duration>&
zoned_time<Duration>::operator=(sys_time<Duration> st)
{
    tp_ = st;
    return *this;
}

template <class Duration>
inline
zoned_time<Duration>&
zoned_time<Duration>::operator=(local_time<Duration> ut)
{
    tp_ = zone_->to_sys(ut);
    return *this;
}

template <class Duration>
inline
zoned_time<Duration>::operator local_time<Duration>() const
{
    return get_local_time();
}

template <class Duration>
inline
zoned_time<Duration>::operator sys_time<Duration>() const
{
    return get_sys_time();
}

template <class Duration>
inline
const time_zone*
zoned_time<Duration>::get_time_zone() const
{
    return zone_;
}

template <class Duration>
inline
local_time<Duration>
zoned_time<Duration>::get_local_time() const
{
    return zone_->to_local(tp_);
}

template <class Duration>
inline
sys_time<Duration>
zoned_time<Duration>::get_sys_time() const
{
    return tp_;
}

template <class Duration>
inline
sys_info
zoned_time<Duration>::get_info() const
{
    return zone_->get_info(tp_);
}

// make_zoned_time

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(sys_time<Duration> tp)
{
    return {tp};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const time_zone* zone, local_time<Duration> tp)
{
    return {zone, tp};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const std::string& name, local_time<Duration> tp)
{
    return {name, tp};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const time_zone* zone, local_time<Duration> tp, choose c)
{
    return {zone, tp, c};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const std::string& name, local_time<Duration> tp, choose c)
{
    return {name, tp, c};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const time_zone* zone, const zoned_time<Duration>& zt)
{
    return {zone, zt};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const std::string& name, const zoned_time<Duration>& zt)
{
    return {name, zt};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const time_zone* zone, const zoned_time<Duration>& zt, choose c)
{
    return {zone, zt, c};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const std::string& name, const zoned_time<Duration>& zt, choose c)
{
    return {name, zt, c};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const time_zone* zone, const sys_time<Duration>& st)
{
    return {zone, st};
}

template <class Duration>
inline
zoned_time<typename std::common_type<Duration, std::chrono::seconds>::type>
make_zoned(const std::string& name, const sys_time<Duration>& st)
{
    return {name, st};
}

template <class CharT, class Traits, class Duration>
inline
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const zoned_time<Duration>& t)
{
    auto i = t.zone_->get_info(t.tp_);
    auto lt = t.tp_ + i.offset;
    return os << lt << ' ' << i.abbrev;
}

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
        sys_to_utc(sys_time<Duration> t);

    template <class Duration>
        static
        sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        utc_to_sys(std::chrono::time_point<utc_clock, Duration> t);
};

template <class Duration>
    using utc_time = std::chrono::time_point<utc_clock, Duration>;

using utc_seconds = utc_time<std::chrono::seconds>;

inline
utc_clock::time_point
utc_clock::now() NOEXCEPT
{
    using namespace std::chrono;
    return sys_to_utc(system_clock::now());
}

template <class Duration>
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
utc_clock::sys_to_utc(sys_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto const& leaps = get_tzdb().leaps;
    auto const lt = std::upper_bound(leaps.begin(), leaps.end(), t);
    return utc_time<duration>{t.time_since_epoch() + seconds{lt-leaps.begin()}};
}

template <class Duration>
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
utc_clock::utc_to_sys(utc_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto const& leaps = get_tzdb().leaps;
    auto tp = sys_time<duration>{t.time_since_epoch()};
    if (tp >= leaps.front())
    {
        auto const lt = std::upper_bound(leaps.begin(), leaps.end(), tp);
        tp -= seconds{lt-leaps.begin()};
        if (tp < lt[-1])
        {
            if (tp >= lt[-1].date() - seconds{1})
                tp = lt[-1].date() - duration{1};
            else
                tp += seconds{1};
        }
    }
    return tp;
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(utc_time<Duration> ut)
{
    return utc_clock::utc_to_sys(ut);
}

template <class Duration>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(sys_time<Duration> st)
{
    return utc_clock::sys_to_utc(st);
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const utc_time<Duration>& t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto const& leaps = get_tzdb().leaps;
    auto tp = sys_time<duration>{t.time_since_epoch()};
    if (tp >= leaps.front())
    {
        auto const lt = std::upper_bound(leaps.begin(), leaps.end(), tp);
        tp -= seconds{lt-leaps.begin()};
        if (tp < lt[-1])
        {
            if (tp >= lt[-1].date() - seconds{1})
            {
                auto const dp = floor<days>(tp);
                auto time = make_time(tp-dp);
                time.seconds() += seconds{1};
                return os << year_month_day(dp) << ' ' << time;
            }
            else
                tp += seconds{1};
        }
    }
    return os << tp;
}

// tai_clock

class tai_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<tai_clock>;
    static const bool is_steady     = true;

    static time_point now() noexcept;

    template <class Duration>
        static
        std::chrono::time_point<tai_clock,
            typename std::common_type<Duration, std::chrono::seconds>::type>
        utc_to_tai(utc_time<Duration> t);

    template <class Duration>
        static
        utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        tai_to_utc(std::chrono::time_point<tai_clock, Duration> t);
};

template <class Duration>
    using tai_time = std::chrono::time_point<tai_clock, Duration>;

using tai_seconds = tai_time<std::chrono::seconds>;

template <class Duration>
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tai_clock::utc_to_tai(utc_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return tai_time<duration>{t.time_since_epoch()} + 
            (sys_days{1970_y/jan/1} - sys_days{1958_y/jan/1} + seconds{10});
}

template <class Duration>
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
tai_clock::tai_to_utc(tai_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return utc_time<duration>{t.time_since_epoch()} - 
            (sys_days{1970_y/jan/1} - sys_days{1958_y/jan/1} + seconds{10});
}

template <class Duration>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(tai_time<Duration> t)
{
    return tai_clock::tai_to_utc(t);
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(utc_time<Duration> t)
{
    return tai_clock::utc_to_tai(t);
}

inline
tai_clock::time_point
tai_clock::now() noexcept
{
    using namespace std::chrono;
    return to_tai_time(utc_clock::now());
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const tai_time<Duration>& t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto tp = sys_time<duration>{t.time_since_epoch()} -
                (sys_days{1970_y/jan/1} - sys_days{1958_y/jan/1});
    return os << tp;
}

// gps_clock

class gps_clock
{
public:
    using duration                  = std::chrono::system_clock::duration;
    using rep                       = duration::rep;
    using period                    = duration::period;
    using time_point                = std::chrono::time_point<gps_clock>;
    static const bool is_steady     = true;

    static time_point now() noexcept;

    template <class Duration>
        static
        std::chrono::time_point<gps_clock,
            typename std::common_type<Duration, std::chrono::seconds>::type>
        utc_to_gps(utc_time<Duration> t);

    template <class Duration>
        static
        utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
        gps_to_utc(std::chrono::time_point<gps_clock, Duration> t);
};

template <class Duration>
    using gps_time = std::chrono::time_point<gps_clock, Duration>;

using gps_seconds = gps_time<std::chrono::seconds>;

template <class Duration>
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
gps_clock::utc_to_gps(utc_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return gps_time<duration>{t.time_since_epoch()} -
            (sys_days{1980_y/jan/sun[1]} - sys_days{1970_y/jan/1} + seconds{9});
}

template <class Duration>
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
gps_clock::gps_to_utc(gps_time<Duration> t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    return utc_time<duration>{t.time_since_epoch()} +
            (sys_days{1980_y/jan/sun[1]} - sys_days{1970_y/jan/1} + seconds{9});
}

template <class Duration>
inline
utc_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_utc_time(gps_time<Duration> t)
{
    return gps_clock::gps_to_utc(t);
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(utc_time<Duration> t)
{
    return gps_clock::utc_to_gps(t);
}

inline
gps_clock::time_point
gps_clock::now() noexcept
{
    using namespace std::chrono;
    return to_gps_time(utc_clock::now());
}

template <class CharT, class Traits, class Duration>
std::basic_ostream<CharT, Traits>&
operator<<(std::basic_ostream<CharT, Traits>& os, const gps_time<Duration>& t)
{
    using namespace std::chrono;
    using duration = typename std::common_type<Duration, seconds>::type;
    auto tp = sys_time<duration>{t.time_since_epoch()} +
                (sys_days{1980_y/jan/sun[1]} - sys_days{1970_y/jan/1});
    return os << tp;
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(tai_time<Duration> t)
{
    return to_sys_time(to_utc_time(t));
}

template <class Duration>
inline
sys_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_sys_time(gps_time<Duration> t)
{
    return to_sys_time(to_utc_time(t));
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(sys_time<Duration> t)
{
    return to_tai_time(to_utc_time(t));
}

template <class Duration>
inline
tai_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_tai_time(gps_time<Duration> t)
{
    return to_tai_time(to_utc_time(t));
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(sys_time<Duration> t)
{
    return to_gps_time(to_utc_time(t));
}

template <class Duration>
inline
gps_time<typename std::common_type<Duration, std::chrono::seconds>::type>
to_gps_time(tai_time<Duration> t)
{
    return to_gps_time(to_utc_time(t));
}

// format

namespace detail
{

template <class CharT, class Traits, class Duration>
std::basic_string<CharT, Traits>
format(const std::locale& loc, std::basic_string<CharT, Traits> fmt,
       local_time<Duration> tp, const sys_info* info = nullptr)
{
    // Handle these specially
    // %S  append fractional seconds if tp has precision finer than seconds
    // %T  append fractional seconds if tp has precision finer than seconds
    // %z  replace with offset from zone on +/-hhmm format
    // %Ez, %Oz replace with offset from zone on +/-hh:mm format
    // %Z  replace with abbreviation from zone

    using namespace std;
    using namespace std::chrono;
    auto command = false;
    auto modified = false;
    for (std::size_t i = 0; i < fmt.size(); ++i)
    {
        switch (fmt[i])
        {
        case '%':
            command = true;
            modified = false;
            break;
        case 'O':
        case 'E':
            modified = true;
            break;
        case 'S':
        case 'T':
            if (command && !modified && ratio_less<typename Duration::period, ratio<1>>::value)
            {
                basic_ostringstream<CharT, Traits> os;
                os.imbue(loc);
                os << make_time(tp - floor<seconds>(tp));
                auto s = os.str();
                s.erase(0, 8);
                fmt.insert(i+1, s);
                i += s.size() - 1;
            }
            command = false;
            modified = false;
            break;
        case 'z':
            if (command)
            {
                if (info == nullptr)
                    throw std::runtime_error("Can not format local_time with %z");
                else
                {
                    auto offset = duration_cast<minutes>(info->offset);
                    basic_ostringstream<CharT, Traits> os;
                    if (offset >= minutes{0})
                        os << '+';
                    os << make_time(offset);
                    auto s = os.str();
                    if (!modified)
                        s.erase(s.find(':'), 1);
                    fmt.replace(i - 1 - modified, 2 + modified, s);
                    i += s.size() - 1;
                }
            }
            command = false;
            modified = false;
            break;
        case 'Z':
            if (command && !modified)
            {
                if (info == nullptr)
                    throw std::runtime_error("Can not format local_time with %z");
                else
                {
                    fmt.replace(i - 1, 2, std::basic_string<CharT, Traits>
                                            (info->abbrev.begin(), info->abbrev.end()));
                    i += info->abbrev.size() - 1;
                }
            }
            command = false;
            modified = false;
            break;
        default:
            command = false;
            modified = false;
            break;
        }
    }
    auto& f = use_facet<time_put<CharT>>(loc);
    basic_ostringstream<CharT, Traits> os;
    auto tt = system_clock::to_time_t(sys_time<Duration>{tp.time_since_epoch()});
    std::tm tm{};
#ifndef _MSC_VER
    gmtime_r(&tt, &tm);
#else
    gmtime_s(&tm, &tt);
#endif
    f.put(os, os, os.fill(), &tm, fmt.data(), fmt.data() + fmt.size());
    return os.str();
}

}  // namespace detail

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(const std::locale& loc, std::basic_string<CharT, Traits> fmt,
       local_time<Duration> tp)
{
    return detail::format(loc, std::move(fmt), tp);
}

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(std::basic_string<CharT, Traits> fmt, local_time<Duration> tp)
{
    return detail::format(std::locale{}, std::move(fmt), tp);
}

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(const std::locale& loc, std::basic_string<CharT, Traits> fmt,
       const zoned_time<Duration>& tp)
{
    auto const info = tp.get_info();
    return detail::format(loc, std::move(fmt), tp.get_local_time(), &info);
}

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(std::basic_string<CharT, Traits> fmt, const zoned_time<Duration>& tp)
{
    auto const info = tp.get_info();
    return detail::format(std::locale{}, std::move(fmt), tp.get_local_time(), &info);
}

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(const std::locale& loc, std::basic_string<CharT, Traits> fmt,
       sys_time<Duration> tp)
{
    return format(loc, std::move(fmt), make_zoned(locate_zone("UTC"), tp));
}

template <class CharT, class Traits, class Duration>
inline
std::basic_string<CharT, Traits>
format(std::basic_string<CharT, Traits> fmt, sys_time<Duration> tp)
{
    return format(std::move(fmt), make_zoned(locate_zone("UTC"), tp));
}

// const CharT* formats

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const std::locale& loc, const CharT* fmt, local_time<Duration> tp)
{
    return detail::format(loc,  std::basic_string<CharT>(fmt), tp);
}

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const CharT* fmt, local_time<Duration> tp)
{
    return detail::format(std::locale{}, std::basic_string<CharT>(fmt), tp);
}

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const std::locale& loc, const CharT* fmt, const zoned_time<Duration>& tp)
{
    auto const info = tp.get_info();
    return detail::format(loc, std::basic_string<CharT>(fmt), tp.get_local_time(),
                          &info);
}

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const CharT* fmt, const zoned_time<Duration>& tp)
{
    auto const info = tp.get_info();
    return detail::format(std::locale{}, std::basic_string<CharT>(fmt),
                          tp.get_local_time(), &info);
}

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const std::locale& loc, const CharT* fmt, sys_time<Duration> tp)
{
    return format(loc, fmt, make_zoned(locate_zone("UTC"), tp));
}

template <class CharT, class Duration>
inline
std::basic_string<CharT>
format(const CharT* fmt, sys_time<Duration> tp)
{
    return format(fmt, make_zoned(locate_zone("UTC"), tp));
}

// parse

namespace detail
{

template <class CharT, class Traits, class Duration>
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev, std::chrono::minutes& offset)
{
    using namespace std;
    using namespace std::chrono;
    typename basic_istream<CharT, Traits>::sentry ok{is};
    if (ok)
    {
        auto& f = use_facet<time_get<CharT>>(is.getloc());
        ios_base::iostate err = ios_base::goodbit;
        std::tm tm{};
        Duration subseconds{};
        std::basic_string<CharT, Traits> temp_abbrev;
        minutes temp_offset{};

        auto b = format.data();
        auto i = b;
        auto e = b + format.size();
        auto command = false;
        auto modified = false;
        for (; i < e; ++i)
        {
            switch (*i)
            {
            case '%':
                command = true;
                modified = false;
                break;
            case 'O':
            case 'E':
                modified = true;
                break;
            case 'T':
            case 'S':
                if (command && !modified)
                {
                    f.get(is, 0, is, err, &tm, b, i-1);
                    b = i+1;
                    if (*i == 'T')
                    {
                        const CharT hm[] = {'%', 'H', ':', '%', 'M', ':'};
                        f.get(is, 0, is, err, &tm, hm, hm+6);
                    }
                    if (ratio_less<typename Duration::period, ratio<1>>::value)
                    {
                        double s;
                        is >> s;
                        if (!is.fail())
                            subseconds = round<Duration>(duration<double>{s});
                        else
                            err |= ios_base::failbit;
                    }
                    else
                    {
                        const CharT hm[] = {'%', 'S'};
                        f.get(is, 0, is, err, &tm, hm, hm+2);
                    }
                }
                command = false;
                modified = false;
                break;
            case 'z':
                if (command)
                {
                    f.get(is, 0, is, err, &tm, b, i-1-modified);
                    b = i+1;
                    if ((err & ios_base::failbit) == 0)
                    {
                        CharT sign{};
                        is >> sign;
                        if (!is.fail() && (sign == '+' || sign == '-'))
                        {
                            char h1, h0, m1, m0;
                            char colon = '\0';
                            h1 = static_cast<char>(is.get());
                            h0 = static_cast<char>(is.get());
                            if (modified)
                                colon = static_cast<char>(is.get());
                            m1 = static_cast<char>(is.get());
                            m0 = static_cast<char>(is.get());
                            if (!is.fail() && std::isdigit(h1) && std::isdigit(h0)
                                           && std::isdigit(m1) && std::isdigit(m0)
                                           && (!modified || colon == ':'))
                            {
                                temp_offset = 10*hours{h1 - '0'} + hours{h0 - '0'} +
                                              10*minutes{m1 - '0'} + minutes{m0 - '0'};
                                if (sign == '-')
                                    temp_offset = -temp_offset;
                            }
                            else
                                err |= ios_base::failbit;
                        }
                        else
                            err |= ios_base::failbit;
                    }
                }
                command = false;
                modified = false;
                break;
            case 'Z':
                if (command && !modified)
                {
                    f.get(is, 0, is, err, &tm, b, i-1);
                    b = i+1;
                    if ((err & ios_base::failbit) == 0)
                    {
                        is >> temp_abbrev;
                        if (is.fail())
                            err |= ios_base::failbit;
                    }
                }
                command = false;
                modified = false;
                break;
            default:
                command = false;
                modified = false;
                break;
            }
        }
        if ((err & ios_base::failbit) == 0)
        {
            if (b < e)
                f.get(is, 0, is, err, &tm, b, e);
            if ((err & ios_base::failbit) == 0)
            {
#ifdef _WIN32
                auto tt = _mkgmtime(&tm);
#else
                auto tt = timegm(&tm);
#endif
                tp = floor<Duration>(system_clock::from_time_t(tt) + subseconds);
                abbrev = std::move(temp_abbrev);
                offset = temp_offset;
            }
        }
        is.setstate(err);
    }
}

}  // namespace detail

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp)
{
    std::basic_string<CharT, Traits> abbrev;
    std::chrono::minutes offset{};
    detail::parse(is, format, tp, abbrev, offset);
    if (!is.fail())
        tp = floor<Duration>(tp - offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev)
{
    std::chrono::minutes offset{};
    detail::parse(is, format, tp, abbrev, offset);
    if (!is.fail())
        tp = floor<Duration>(tp - offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp,
      std::chrono::minutes& offset)
{
    std::basic_string<CharT, Traits> abbrev;
    detail::parse(is, format, tp, abbrev, offset);
    if (!is.fail())
        tp = floor<Duration>(tp - offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev, std::chrono::minutes& offset)
{
    detail::parse(is, format, tp, abbrev, offset);
    if (!is.fail())
        tp = floor<Duration>(tp - offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, sys_time<Duration>& tp,
      std::chrono::minutes& offset, std::basic_string<CharT, Traits>& abbrev)
{
    detail::parse(is, format, tp, abbrev, offset);
    if (!is.fail())
        tp = floor<Duration>(tp - offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, local_time<Duration>& tp)
{
    sys_time<Duration> st;
    std::basic_string<CharT, Traits> abbrev;
    std::chrono::minutes offset{};
    detail::parse(is, format, st, abbrev, offset);
    if (!is.fail())
        tp = local_time<Duration>{st.time_since_epoch()};
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, local_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev)
{
    sys_time<Duration> st;
    std::chrono::minutes offset{};
    detail::parse(is, format, st, abbrev, offset);
    if (!is.fail())
        tp = local_time<Duration>{st.time_since_epoch()};
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, local_time<Duration>& tp,
      std::chrono::minutes& offset)
{
    sys_time<Duration> st;
    std::basic_string<CharT, Traits> abbrev;
    detail::parse(is, format, st, abbrev, offset);
    if (!is.fail())
        tp = local_time<Duration>{st.time_since_epoch()};
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, local_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev, std::chrono::minutes& offset)
{
    sys_time<Duration> st;
    detail::parse(is, format, st, abbrev, offset);
    if (!is.fail())
        tp = local_time<Duration>{st.time_since_epoch()};
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is,
      const std::basic_string<CharT, Traits>& format, local_time<Duration>& tp,
      std::chrono::minutes& offset, std::basic_string<CharT, Traits>& abbrev)
{
    sys_time<Duration> st;
    detail::parse(is, format, st, abbrev, offset);
    if (!is.fail())
        tp = local_time<Duration>{st.time_since_epoch()};
}

// const CharT* formats

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format, sys_time<Duration>& tp)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format, sys_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format, sys_time<Duration>& tp,
      std::chrono::minutes& offset)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format, sys_time<Duration>& tp,
      std::basic_string<CharT, Traits>& abbrev, std::chrono::minutes& offset)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev, offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format, sys_time<Duration>& tp,
      std::chrono::minutes& offset, std::basic_string<CharT, Traits>& abbrev)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev, offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format,
      local_time<Duration>& tp)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format,
      local_time<Duration>& tp, std::basic_string<CharT, Traits>& abbrev)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format,
      local_time<Duration>& tp, std::chrono::minutes& offset)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format,
      local_time<Duration>& tp, std::basic_string<CharT, Traits>& abbrev,
      std::chrono::minutes& offset)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev, offset);
}

template <class CharT, class Traits, class Duration>
inline
void
parse(std::basic_istream<CharT, Traits>& is, const CharT* format,
      local_time<Duration>& tp, std::chrono::minutes& offset,
      std::basic_string<CharT, Traits>& abbrev)
{
    parse(is, std::basic_string<CharT, Traits>(format), tp, abbrev, offset);
}

}  // namespace date

#endif  // TZ_H
