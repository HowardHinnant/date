// The MIT License (MIT)
// 
// Copyright (c) 2015, 2016 Howard Hinnant
// Copyright (c) 2015 Ville Voutilainen
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

#include "tz_private.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>
#include <sys/stat.h>
#if HAS_REMOTE_API
#include <curl/curl.h>
#endif
#ifdef _WIN32
#include <locale>
#include <codecvt>
#endif

#if TIMEZONE_MAPPING
// Timezone mapping maps native (e.g. Windows) timezone names to the "Standard" names
// used by this library.
// The mapping process parses a CSV file of mapping data and uses std::quoted to do that.
// Because std::quoted is a C++14 feature found in <iomanip> any platforms using
// the mapping process require C++14.
// Windows uses the mapping process so C++14 is required on Windows.
// VS2015 supports std::quoted but there is no -std=c++14 flag required to enable it.
// MinGW on Windows also requires the mapping process so -std=c++14 is required
// when using g++ or clang.
// On Linux/Mac, no mapping / CSV file is required so std::quoted and C++14 isn't needed
// and so on these platforms C++11 should work but C++14 is preferred even there too
// because the date library in general works better with C++14.
#include <iomanip>
#endif

// unistd.h is used on some platforms as part of the the means to get
// the current time zone. On Win32 Windows.h provides a means to do it.
// gcc/mingw supports unistd.h on Win32 but MSVC does not.

#ifdef _WIN32
// Prevent windows defining min/max macros that will interfere with C++ versions.
#ifndef NOMINMAX
#define NOMINMAX
#endif
// We don't need everything Windows.h has to offer.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <wordexp.h>
#endif

namespace date
{
// +---------------------+
// | Begin Configuration |
// +---------------------+

#if _WIN32 // TODO: sensible default for all platforms.
static const std::string install{ "c:\\tzdata" };
#else  // !_WIN32

static
std::string
expand_path(std::string path)
{
    ::wordexp_t w{};
    ::wordexp(path.c_str(), &w, 0);
    assert(w.we_wordc == 1);
    path = w.we_wordv[0];
    ::wordfree(&w);
    return path;
}

static const std::string install = expand_path("~/Downloads/tzdata");

#endif  // !_WIN32

static const std::vector<std::string> files =
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

#if _MSC_VER && ! defined(__clang__) && ! defined( __GNUG__)
// We can't use static_assert here for MSVC (yet) because
// the expression isn't constexpr in MSVC yet.
// FIXME! Remove this when MSVC's constexpr support improves.
#else
static_assert(min_year <= max_year, "Configuration error");
#endif
#if __cplusplus >= 201402
static_assert(boring_day.ok(), "Configuration error");
#endif

// Until filesystem arrives.
static CONSTDATA char folder_delimiter =
#ifdef _WIN32
'\\';
#else
'/';
#endif

static bool file_exists(const std::string& filename)
{
#ifdef _WIN32
    return ::_access(filename.c_str(), 0) == 0;
#else
    return ::access(filename.c_str(), F_OK) == 0;
#endif
}

#ifdef _WIN32
// Win32 support requires calling OS functions.
// This routine maps OS error codes to readable text strngs.
static std::string get_win32_message(DWORD error_code)
{
    struct free_message {
        void operator()(char buf[]) {
            if (buf != nullptr)
            {
                auto result = HeapFree(GetProcessHeap(), 0, buf);
                assert(result != 0);
            }
        }
    };
    char* msg = nullptr;
    auto result = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                                       | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&msg), 0, nullptr );
    std::unique_ptr<char[], free_message> message_buffer(msg);
    if (result == 0) // If there is no error message, still give the code.
    {
        std::string err = "Error getting message for error number ";
        err += std::to_string(error_code);
        return err;
    }
    assert(message_buffer.get() != nullptr);
    return std::string(message_buffer.get());
}
#endif  // _WIN32

#if TIMEZONE_MAPPING

namespace // Put types in an anonymous name space.
{
    // A simple type to manage RAII for key handles and to
    // implement the trivial registry interface we need.
    // Not intended to be general-purpose.
    class reg_key
    {
    private:
        // Note there is no value documented to be an invalid handle value.
        // Not NULL nor INVALID_HANDLE_VALUE. We must rely on is_open.
        HKEY m_key = nullptr;
        bool m_is_open = false;
    public:
        HKEY handle()
        {
            return m_key;
        }
        bool is_open() const
        {
            return m_is_open;
        }
        LONG open(const wchar_t* key_name)
        {
            LONG result;
            result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_name, 0, KEY_READ, &m_key);
            if (result == ERROR_SUCCESS)
                m_is_open = true;
            return result;
        }
        LONG close()
        {
            if (m_is_open)
            {
                auto result = RegCloseKey(m_key);
                assert(result == ERROR_SUCCESS);
                if (result == ERROR_SUCCESS)
                {
                    m_is_open = false;
                    m_key = nullptr;
                }
                return result;
            }
            return ERROR_SUCCESS;
        }

        // WARNING: this function has a hard-coded value size limit.
        // It is not a general-purpose function.
        // It should be sufficient for our use cases. 
        // The function could be made workable for any size string
        // but we don't need the complexity of implementing that
        // for our meagre purposes right now.
        bool get_string(const wchar_t* key_name, std::string& value)
        {
            value.clear();
            wchar_t value_buffer[256];
            // in/out parameter. Documentation say that size is a count of bytes not chars.
            DWORD size = sizeof(value_buffer) - sizeof(value_buffer[0]);
            DWORD tzi_type = REG_SZ;
            if (RegQueryValueExW(handle(), key_name, nullptr, &tzi_type,
                reinterpret_cast<LPBYTE>(value_buffer), &size) == ERROR_SUCCESS)
            {
                // Function does not guarantee to null terminate.
                value_buffer[size/sizeof(value_buffer[0])] = L'\0';
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                value = converter.to_bytes(value_buffer);
                return true;
            }
            return false;
        }

        bool get_binary(const wchar_t* key_name, void* value, int value_size)
        {
            DWORD size = value_size;
            DWORD type = REG_BINARY;
            if (RegQueryValueExW(handle(), key_name, nullptr, &type,
                reinterpret_cast<LPBYTE>(value), &size) == ERROR_SUCCESS
                && (int) size == value_size)
                return true;
            return false;
        }

        ~reg_key()
        {
            close();
        }
    };
} // anonymous namespace

template < typename T, size_t N >
static inline size_t countof(T(&arr)[N])
{
    return std::extent< T[N] >::value;
}

// This function returns an exhaustive list of time zone information
// from the Windows registry.
// The routine tries to load as many time zone entries as possible despite errors.
// We don't want to fail to load the whole database just because one record can't be read.

static void get_windows_timezone_info(std::vector<timezone_info>& tz_list)
{
    tz_list.clear();
    LONG result;

    // Open the parent time zone key that has the list of timezones in.
    reg_key zones_key;
    static const wchar_t zones_key_name[] = 
    { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones" };
    result = zones_key.open(zones_key_name);
    // TODO! Review if this should happen here or be signalled later.
    // We don't want the process to fail on startup because of this.
    if (result != ERROR_SUCCESS)
        throw std::runtime_error("Time Zone registry key could not be opened: " 
        + get_win32_message(result));

    DWORD size;
    wchar_t zone_key_name[256];
    std::wstring value;

    // Iterate through the list of keys of the parent time zones key to get
    // each key that identifies each individual timezone.
    std::wstring full_zone_key_name;
    for (DWORD zone_index = 0; ; ++zone_index)
    {
        timezone_info tz;

        size = (DWORD) sizeof(zone_key_name)/sizeof(zone_key_name[0]);
        auto status = RegEnumKeyExW(zones_key.handle(), zone_index, zone_key_name, &size,
            nullptr, nullptr, nullptr, nullptr);
        if (status != ERROR_SUCCESS && status != ERROR_NO_MORE_ITEMS)
            throw std::runtime_error("Can't enumerate time zone registry key" 
            + get_win32_message(status));
        if (status == ERROR_NO_MORE_ITEMS)
            break;
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        tz.timezone_id = converter.to_bytes(zone_key_name);

        full_zone_key_name = zones_key_name;
        full_zone_key_name += L'\\';
        full_zone_key_name += zone_key_name;

        // If any field fails to be found, consider the whole time zone
        // entry corrupt and move onto the next. See comments
        // at the top of function.

        reg_key zone_key;
        if (zone_key.open(full_zone_key_name.c_str()) != ERROR_SUCCESS)
            continue;

        if (!zone_key.get_string(L"Std", tz.standard_name))
            continue;

#if 0
        // TBD these fields are not required yet.
        // They might be useful for test cases though.
        if (!zone_key.get_string("Display", tz.display_name))
            continue;

        if (!zone_key.get_binary("TZI", &tz.tzi, sizeof(TZI)))
            continue;
#endif
        zone_key.close();

        tz_list.push_back(std::move(tz));
    }
    result = zones_key.close();
}

// standard_name is the StandardName field from the Windows
// TIME_ZONE_INFORMATION structure.
// See the Windows API function GetTimeZoneInformation.
// The standard_name is also the value from STD field of
// under the windows registry key Time Zones.
// To be clear, standard_name does NOT represent a windows timezone id
// or an IANA tzid
static const timezone_info* find_native_timezone_by_standard_name(
    const std::string& standard_name)
{
    // TODO! we can improve on linear search.
    const auto& native_zones = get_tzdb().native_zones;
    for (const auto& tz : native_zones)
    {
        if (tz.standard_name == standard_name)
            return &tz;
    }

    return nullptr;
}

// Read CSV file of "other","territory","type".
// See timezone_mapping structure for more info.
// This function should be kept in sync with the code that writes this file.
static std::vector<timezone_mapping>
load_timezone_mappings_from_csv_file(const std::string& input_path)
{
    size_t line = 1;
    std::vector<timezone_mapping> mappings;
    std::ifstream is(input_path, std::ios_base::in | std::ios_base::binary);
    if (!is.is_open())
    {
        // We don't emit file exceptions because that's an implementation detail.
        std::string msg = "Error opening time zone mapping file: ";
        msg += input_path;
        throw std::runtime_error(msg);
    }
    auto error = [&](const char* info)
    {
        std::string msg = "Error reading zone mapping file at line ";
        msg += std::to_string(line);
        msg += ": ";
        msg += info;
        throw std::runtime_error(msg);
    };

    auto read_field_delim = [&]()
    {
        char field_delim;
        is.read(&field_delim, 1);
        if (is.gcount() != 1 || field_delim != ',')
            error("delimiter ',' expected");
    };
    std::string copyright;
    for (int i = 0; i < 4; ++i)
        getline(is, copyright);
    
    for (;;)
    {
        timezone_mapping zm{};
        char ch;

        is.read(&ch, 1);
        if (is.eof())
            break;
        std::getline(is, zm.other, '\"');
        read_field_delim();

        is.read(&ch, 1);
        std::getline(is, zm.territory, '\"');
        read_field_delim();

        is.read(&ch, 1);
        std::getline(is, zm.type, '\"');

        is.read(&ch, 1);
        if (is.gcount() != 1 || ch != '\n')
            error("record delimiter LF expected");

        if (is.fail() || is.eof())
            error("unexpected end of file, file read error or formatting error.");

        ++line;
        mappings.push_back(std::move(zm));
    }
    is.close();
    return mappings;
}

static bool
native_to_standard_timezone_name(const std::string& native_tz_name, 
                                 std::string& standard_tz_name)
{
    // TOOD! Need be a case insensitive compare?
    if (native_tz_name == "UTC")
    {
        standard_tz_name = "Etc/UTC";
        return true;
    }
    standard_tz_name.clear();
    // TODO! we can improve on linear search.
    const auto& mappings = date::get_tzdb().mappings;
    for (const auto& tzm : mappings)
    {
        if (tzm.other == native_tz_name)
        {
            standard_tz_name = tzm.type;
            return true;
        }
    }
    return false;
}
#endif  // TIMEZONE_MAPPING

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
    const char*const dow_names[] =
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
    const char*const month_names[] =
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

MonthDayTime::MonthDayTime(second_point tp, tz timezone)
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
        break;
    }
    return u.month_day_weekday_.month_day_.day();
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
        break;
    }
    return u.month_day_weekday_.month_day_.month();
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

second_point
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
        break;
    }
    auto const x = y/u.month_day_weekday_.month_day_;
    auto const wd1 = u.month_day_weekday_.weekday_;
    auto const wd0 = weekday(x);
    return day_point(x) + (wd1-wd0);
}

second_point
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
                    x.u = MonthDayTime::pair{ date::month(m) / d, date::weekday(dow) };
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
    detail::save_stream _(os);
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
        auto first_rule = rules.begin() + static_cast<difference_type>(i);
        auto last_rule = rules.begin() + static_cast<difference_type>(e);
        auto t = std::lower_bound(first_rule, last_rule, min_year);
        if (t > first_rule+1)
        {
            if (t == last_rule || t->starting_year() >= min_year)
                --t;
            auto d = static_cast<std::size_t>(t - first_rule);
            rules.erase(first_rule, t);
            e -= d;
        }
        first_rule = rules.begin() + static_cast<difference_type>(i);
        last_rule = rules.begin() + static_cast<difference_type>(e);
        t = std::upper_bound(first_rule, last_rule, max_year);
        if (t != last_rule)
        {
            auto d = static_cast<std::size_t>(last_rule - t);
            rules.erase(t, last_rule);
            e -= d;
        }
        i = e;
    }
    rules.shrink_to_fit();
}

// Zone

Zone::zonelet::~zonelet()
{
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    using minutes = std::chrono::minutes;
    using string = std::string;
    if (tag_ == has_save)
        u.save_.~minutes();
    else
        u.rule_.~string();
#endif
}

Zone::zonelet::zonelet()
{
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    ::new(&u.rule_) std::string();
#endif
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
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
    if (tag_ == has_save)
        ::new(&u.save_) std::chrono::minutes(i.u.save_);
    else
        ::new(&u.rule_) std::string(i.u.rule_);
#else
    if (tag_ == has_save)
        u.save_ = i.u.save_;
    else
        u.rule_ = i.u.rule_;
#endif
}

Zone::Zone(const std::string& s)
#if LAZY_INIT
    : adjusted_(new std::once_flag{})
#endif
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
find_next_rule(const Rule* first_rule, const Rule* last_rule, const Rule* r, date::year y)
{
    using namespace date;
    if (y == r->ending_year())
    {
        if (r == last_rule-1)
            return {nullptr, year::max()};
        ++r;
        if (y == r->ending_year())
            return {r, y};
        return {r, r->starting_year()};
    }
    if (r == last_rule-1 || r->ending_year() < r[1].ending_year())
    {
        while (r > first_rule && r->starting_year() == r[-1].starting_year())
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
const Rule*
find_first_std_rule(const std::pair<const Rule*, const Rule*>& eqr)
{
    auto r = eqr.first;
    auto ry = r->starting_year();
    while (r->save() != std::chrono::minutes{0})
    {
        std::tie(r, ry) = find_next_rule(eqr.first, eqr.second, r, ry);
        if (r == nullptr)
            throw std::runtime_error("Could not find standard offset in rule "
                                     + eqr.first->name());
    }
    return r;
}

static
std::pair<const Rule*, date::year>
find_rule_for_zone(const std::pair<const Rule*, const Rule*>& eqr,
                   const date::year& y, const std::chrono::seconds& offset,
                   const MonthDayTime& mdt)
{
    assert(eqr.first != nullptr);
    assert(eqr.second != nullptr);

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
                   const second_point& tp_utc, const second_point& tp_std,
                   const second_point& tp_loc)
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
find_rule(const std::pair<const Rule*, date::year>& first_rule,
          const std::pair<const Rule*, date::year>& last_rule,
          const date::year& y, const std::chrono::seconds& offset,
          const MonthDayTime& mdt, const std::chrono::minutes& initial_save,
          const std::string& initial_abbrev)
{
    using namespace std::chrono;
    using namespace date;
    auto r = first_rule.first;
    auto ry = first_rule.second;
    Info x{day_point(year::min()/boring_day), day_point(year::max()/boring_day),
           seconds{0}, initial_save, initial_abbrev};
    while (r != nullptr)
    {
        auto tr = r->mdt().to_sys(ry, offset, x.save);
        auto tx = mdt.to_sys(y, offset, x.save);
        // Find last rule where tx >= tr
        if (tx <= tr || (r == last_rule.first && ry == last_rule.second))
        {
            if (tx < tr && r == first_rule.first && ry == first_rule.second)
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
            if (!(r == first_rule.first && ry == first_rule.second))
                prev_save = find_previous_rule(r, ry).first->save();
            x.begin = r->mdt().to_sys(ry, offset, prev_save);
            x.save = r->save();
            x.abbrev = r->abbrev();
            if (!(r == last_rule.first && ry == last_rule.second))
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
        std::pair<const Rule*, const Rule*> eqr{};
        std::istringstream in;
        in.exceptions(std::ios::failbit | std::ios::badbit);
        // Classify info as rule-based, has save, or neither
        if (!z.u.rule_.empty())
        {
            // Find out if this zonelet has a rule or a save
            eqr = std::equal_range(rules.data(), rules.data() + rules.size(), z.u.rule_);
            if (eqr.first == eqr.second)
            {
                // The rule doesn't exist.  Assume this is a save
                try
                {
                    using namespace std::chrono;
                    using string = std::string;
                    in.str(z.u.rule_);
                    auto tmp = duration_cast<minutes>(parse_signed_time(in));
#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
                    z.u.rule_.~string();
                    z.tag_ = zonelet::has_save;
                    ::new(&z.u.save_) minutes(tmp);
#else
                    z.u.rule_.clear();
                    z.tag_ = zonelet::has_save;
                    z.u.save_ = tmp;
#endif
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
            {
                z.first_rule_ = std::make_pair(eqr.first, eqr.first->starting_year());
                z.initial_abbrev_ = find_first_std_rule(eqr)->abbrev();
            }
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

static
std::string
format_abbrev(std::string format, const std::string& variable, std::chrono::seconds off,
                                                               std::chrono::minutes save)
{
    using namespace std::chrono;
    auto k = format.find("%s");
    if (k != std::string::npos)
    {
        format.replace(k, 2, variable);
    }
    else
    {
        k = format.find('/');
        if (k != std::string::npos)
        {
            if (save == minutes{0})
                format.erase(k);
            else
                format.erase(0, k+1);
        }
        else
        {
            k = format.find("%z");
            if (k != std::string::npos)
            {
                std::string temp;
                if (off < seconds{0})
                {
                    temp = '-';
                    off = -off;
                }
                else
                    temp = '+';
                auto h = floor<hours>(off);
                off -= h;
                if (h < hours{10})
                    temp += '0';
                temp += std::to_string(h.count());
                if (off > seconds{0})
                {
                    auto m = floor<minutes>(off);
                    off -= m;
                    if (m < minutes{10})
                        temp += '0';
                    temp += std::to_string(m.count());
                    if (off > seconds{0})
                    {
                        if (off < seconds{10})
                            temp += '0';
                        temp += std::to_string(off.count());
                    }
                }
                format.replace(k, 2, temp);
            }
        }
    }
    return format;
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
    auto tps = floor<seconds>(tp);
#if LAZY_INIT
    std::call_once(*adjusted_, [this]()
                               {
                                   const_cast<Zone*>(this)->adjust_infos(get_tzdb().rules);
                               });
#endif
    auto i = std::upper_bound(zonelets_.begin(), zonelets_.end(), tps,
        [timezone](second_point t, const zonelet& zl)
        {
            return timezone == tz::utc ? t < zl.until_utc_ : t < zl.until_loc_;
        });
    
    Info r{};
    if (i != zonelets_.end())
    {
        if (i->tag_ == zonelet::has_save)
        {
            if (i != zonelets_.begin())
                r.begin = i[-1].until_utc_;
            else
                r.begin = day_point(year::min()/boring_day);
            r.end = i->until_utc_;
            r.offset = i->gmtoff_ + i->u.save_;
            r.save = i->u.save_;
        }
        else if (i->u.rule_.empty())
        {
            if (i != zonelets_.begin())
                r.begin = i[-1].until_utc_;
            else
                r.begin = day_point(year::min()/boring_day);
            r.end = i->until_utc_;
            r.offset = i->gmtoff_;
        }
        else
        {
            r = find_rule(i->first_rule_, i->last_rule_, y, i->gmtoff_,
                          MonthDayTime(tps, timezone), i->initial_save_,
                          i->initial_abbrev_);
            r.offset = i->gmtoff_ + r.save;
            if (i != zonelets_.begin() && r.begin < i[-1].until_utc_)
                r.begin = i[-1].until_utc_;
            if (r.end > i->until_utc_)
                r.end = i->until_utc_;
        }
        r.abbrev = format_abbrev(i->format_, r.abbrev, r.offset, r.save);
        assert(r.begin < r.end);
    }
    return r;
}

std::ostream&
operator<<(std::ostream& os, const Zone& z)
{
    using namespace date;
    using namespace std::chrono;
    detail::save_stream _(os);
    os.fill(' ');
    os.flags(std::ios::dec | std::ios::left);
#if LAZY_INIT
    std::call_once(*z.adjusted_, [&z]()
                                 {
                                     const_cast<Zone&>(z).adjust_infos(get_tzdb().rules);
                                 });
#endif
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
    detail::save_stream _(os);
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

#if HAS_REMOTE_API

// CURL tools

static
int
curl_global()
{
    if (::curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
        throw std::runtime_error("CURL global initialization failed");
    return 0;
}

static const auto curl_delete = [](CURL* p) {::curl_easy_cleanup(p);};

static
std::unique_ptr<CURL, decltype(curl_delete)>
curl_init()
{
    static const auto curl_is_now_initiailized = curl_global();
    return std::unique_ptr<CURL, decltype(curl_delete)>{::curl_easy_init(), curl_delete};
}

std::string
remote_version()
{
    std::string version;
    auto curl = curl_init();
    if (curl != nullptr)
    {
        curl_easy_setopt(curl.get(), CURLOPT_URL, "http://www.iana.org/time-zones");
        using curl_callback = std::size_t(*)(void* contents, std::size_t size,
                                             std::size_t nmemb, void* userp);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION,
            static_cast<curl_callback>(
            [](void* contents, std::size_t size, std::size_t nmemb, void* userp)
                -> std::size_t
            {
                auto& str = *static_cast<std::string*>(userp);
                auto realsize = size * nmemb;
                auto data = static_cast<const char*>(contents);
                str.append(data, realsize);
                return realsize;
            }));
        std::string str;
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &str);
        auto res = curl_easy_perform(curl.get());
        if (res == CURLE_OK)
        {
            CONSTDATA char db[] = "/time-zones/repository/releases/tzdata";
            CONSTDATA auto db_size = sizeof(db) - 1;
            auto p = str.find(db, 0, db_size);
            if (p != std::string::npos && p + (db_size + 5) <= str.size())
                version = str.substr(p + db_size, 5);
        }
    }
    return version;
}

bool
remote_download(const std::string& version)
{
    assert(!version.empty());
    auto curl = curl_init();
    if (curl != nullptr)
    {
        auto url = "http://www.iana.org/time-zones/repository/releases/tzdata" +
                   version + ".tar.gz";
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        using curl_callback = std::size_t(*)(void* contents, std::size_t size,
                                             std::size_t nmemb, void* userp);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION,
            static_cast<curl_callback>(
            [](void* contents, std::size_t size, std::size_t nmemb, void* userp)
                -> std::size_t
            {
                auto& of = *static_cast<std::ofstream*>(userp);
                auto realsize = size * nmemb;
                auto data = static_cast<const char*>(contents);
                of.write(data, realsize);
                return realsize;
            }));
        auto tarfile = install + version + ".tar.gz";
        decltype(curl_easy_perform(curl.get())) res;
        {
            std::ofstream of(tarfile);
            curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &of);
            res = curl_easy_perform(curl.get());
        }
        return res == CURLE_OK;
    }
    return false;
}

bool
remote_install(const std::string& version)
{
    auto success = false;
    assert(!version.empty());
    auto tarfile = install + version + ".tar.gz";
    if (file_exists(tarfile))
    {
        if (file_exists(install))
            std::system(("rm -R " + install).c_str());
        if (std::system(("mkdir " + install + " && "
                 "tar -xzf " + tarfile + " -C " + install).c_str()) == 0)
            success = true;
        std::system(("rm " + tarfile).c_str());
    }
    return success;
}

#endif  // HAS_REMOTE_API

static
std::string
get_version(const std::string& path)
{
    std::ifstream infile(path + "Makefile");
    std::string version;
    while (infile)
    {
        infile >> version;
        if (version == "VERSION=")
        {
            infile >> version;
            return version;
        }
    }
    throw std::runtime_error("Unable to get Timezone database version from " + path);
}

static
TZ_DB
init_tzdb()
{
    using namespace date;
    const std::string path = install + folder_delimiter;
    std::string line;
    bool continue_zone = false;
    TZ_DB db;

#if AUTO_DOWNLOAD
    if (!file_exists(install))
    {
        auto rv = remote_version();
        if (!rv.empty() && remote_download(rv))
            remote_install(rv);
        if (!file_exists(install))
        {
            std::string msg = "Timezone database not found at \"";
            msg += install;
            msg += "\"";
            throw std::runtime_error(msg);
        }
        db.version = get_version(path);
    }
    else
    {
        db.version = get_version(path);
        auto rv = remote_version();
        if (!rv.empty() && db.version != rv)
        {
            if (remote_download(rv))
            {
                remote_install(rv);
                db.version = get_version(path);
            }
        }
    }
#else  // !AUTO_DOWNLOAD
    if (!file_exists(install))
    {
        std::string msg = "Timezone database not found at \"";
        msg += install;
        msg += "\"";
        throw std::runtime_error(msg);
    }
    db.version = get_version(path);
#endif  // !AUTO_DOWNLOAD

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
#if !LAZY_INIT
    for (auto& z : db.zones)
        z.adjust_infos(db.rules);
#endif
    db.zones.shrink_to_fit();
    std::sort(db.links.begin(), db.links.end());
    db.links.shrink_to_fit();
    std::sort(db.leaps.begin(), db.leaps.end());
    db.leaps.shrink_to_fit();

#if TIMEZONE_MAPPING
    std::string mapping_file = path + "TimeZoneMappings.csv";
    db.mappings = load_timezone_mappings_from_csv_file(mapping_file);
    get_windows_timezone_info(db.native_zones);
#endif

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
#if AUTO_DOWNLOAD
    auto const& v = access_tzdb().version;
    if (!v.empty() && v == remote_version())
        return access_tzdb();
#endif
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

#ifdef TZ_TEST
#ifdef _WIN32
const Zone*
locate_native_zone(const std::string& native_tz_name)
{
    std::string standard_tz_name;
    if (!native_to_standard_timezone_name(native_tz_name, standard_tz_name))
    {
        std::string msg;
        msg = "locate_native_zone() failed: A mapping from the Windows Time Zone id \"";
        msg += native_tz_name;
        msg += "\" was not found in the time zone mapping database.";
        throw std::runtime_error(msg);
    }
    return locate_zone(standard_tz_name);
}
#endif
#endif

std::ostream&
operator<<(std::ostream& os, const TZ_DB& db)
{
    os << "Version: " << db.version << '\n';
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

#ifdef _WIN32

const Zone*
current_zone()
{
#if TIMEZONE_MAPPING
    TIME_ZONE_INFORMATION tzi{};
    DWORD tz_result = ::GetTimeZoneInformation(&tzi);
    if (tz_result == TIME_ZONE_ID_INVALID)
    {
        auto error_code = ::GetLastError(); // Store this quick before it gets overwritten.
        throw std::runtime_error("GetTimeZoneInformation failed: " 
            + get_win32_message(error_code));
    }
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::string standard_name(converter.to_bytes(tzi.StandardName));
    auto tz = find_native_timezone_by_standard_name(standard_name);
    if (!tz)
    {
        std::string msg;
        msg = "current_zone() failed: ";
        msg += standard_name;
        msg += " was not found in the Windows Time Zone registry";
        throw std::runtime_error( msg );
    }
    std::string standard_tzid;
    if (!native_to_standard_timezone_name(tz->timezone_id, standard_tzid))
    {
        std::string msg;
        msg = "current_zone() failed: A mapping from the Windows Time Zone id \"";
        msg += tz->timezone_id;
        msg += "\" was not found in the time zone mapping database.";
        throw std::runtime_error(msg);
    }
    return date::locate_zone(standard_tzid);
#else
    // Currently Win32 requires mapping for this function to work.
    throw std::runtime_error("current_zone not implemented.");
#endif
}

#else // ! WIN32

const Zone*
current_zone()
{
    // On some versions of some linux distro's (e.g. Ubuntu),
    // the current timezone might be in the first line of
    // the /etc/timezone file. So we check that.
#if __linux
    std::ifstream timezone_file("/etc/timezone");
    if (timezone_file.is_open())
    {
        std::string line;
        std::getline(timezone_file, line);
        if (!line.empty())
            return locate_zone(line);
        // Fall through to try other means.
    }
#endif
    // On some OS's a file called /etc/localtime may
    // exist and it may be either a real file
    // containing time zone details or a symlink to such a file.
    // On MacOS and BSD Unix if this file is a symlink it
    // might resolve to a path like this:
    // "/usr/share/zoneinfo/America/Los_Angeles"
    // If it does, we try to determine the current
    // timezone from the remainder of the path by removing the prefix
    // and hoping the rest resolves to valid timezone.
    // It may not always work though. If it doesn't then an
    // exception will be thrown by local_timezone.
    // The path may also take a relative form:
    // "../usr/share/zoneinfo/America/Los_Angeles".
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
    const char zonepath[] = "/usr/share/zoneinfo/";
    const size_t zonepath_len = sizeof(zonepath)/sizeof(zonepath[0])-1;
    const size_t pos = result.find(zonepath);
    if (pos != result.npos)
        result.erase(0, zonepath_len+pos);
    return locate_zone(result);
}
#endif

}  // namespace date
