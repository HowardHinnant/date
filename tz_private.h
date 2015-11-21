#ifndef TZ_PRIVATE_H
#define TZ_PRIVATE_H

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

#include "tz.h"

namespace date
{

// Fix for std::quoted
namespace cxxstd14 {

#if __cplusplus >= 201402

using quoted = std::quoted;

#else

// Got it from boost
// http://www.boost.org/doc/libs/1_58_0/boost/io/detail/quoted_manip.hpp

    namespace detail { template <class String, class Char> struct quoted_proxy; }

    //  ------------  public interface  ------------------------------------------------//

    //  manipulator for const std::basic_string&
    template <class Char, class Traits, class Alloc>
      detail::quoted_proxy<std::basic_string<Char, Traits, Alloc> const &, Char>
        quoted(const std::basic_string<Char, Traits, Alloc>& s,
               Char escape='\\', Char delim='\"');

    //  manipulator for non-const std::basic_string&
    template <class Char, class Traits, class Alloc>
      detail::quoted_proxy<std::basic_string<Char, Traits, Alloc> &, Char>
        quoted(std::basic_string<Char, Traits, Alloc>& s,
               Char escape='\\', Char delim='\"');

    //  manipulator for const C-string*
    template <class Char>
      detail::quoted_proxy<const Char*, Char>
        quoted(const Char* s, Char escape='\\', Char delim='\"');

    //  -----------  implementation details  -------------------------------------------//

    namespace detail
    {
		class ios_flags_saver
		{
		public:
			typedef ::std::ios_base            state_type;
			typedef ::std::ios_base::fmtflags  aspect_type;

			explicit  ios_flags_saver( state_type &s )
				: s_save_( s ), a_save_( s.flags() )
				{}
			ios_flags_saver( state_type &s, aspect_type const &a )
				: s_save_( s ), a_save_( s.flags(a) )
				{}
			~ios_flags_saver()
				{ this->restore(); }

			void  restore()
				{ s_save_.flags( a_save_ ); }

		private:
			state_type &       s_save_;
			aspect_type const  a_save_;

			ios_flags_saver& operator=(const ios_flags_saver&);
		};

	//  proxy used as an argument pack 
      template <class String, class Char>
      struct quoted_proxy
      {
        String  string;
        Char    escape;
        Char    delim;

        quoted_proxy(String s_, Char escape_, Char delim_)
          : string(s_), escape(escape_), delim(delim_) {}
      private:
        // String may be a const type, so disable the assignment operator
        quoted_proxy& operator=(const quoted_proxy&);  // = deleted
      };

      //  abstract away difference between proxies with const or non-const basic_strings
      template <class Char, class Traits, class Alloc>
      std::basic_ostream<Char, Traits>&
      basic_string_inserter_imp(std::basic_ostream<Char, Traits>& os,
        std::basic_string<Char, Traits, Alloc> const & string, Char escape, Char delim)
      {
        os << delim;
        typename std::basic_string<Char, Traits, Alloc>::const_iterator
          end_it = string.end();
        for (typename std::basic_string<Char, Traits, Alloc>::const_iterator
          it = string.begin();
          it != end_it;
          ++it )
        {
          if (*it == delim || *it == escape)
            os << escape;
          os << *it;
        }
        os << delim;
        return os;
      }

      //  inserter for const std::basic_string& proxies
      template <class Char, class Traits, class Alloc>
      inline
      std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, 
        const quoted_proxy<std::basic_string<Char, Traits, Alloc> const &, Char>& proxy)
      {
        return basic_string_inserter_imp(os, proxy.string, proxy.escape, proxy.delim);
      }

      //  inserter for non-const std::basic_string& proxies
      template <class Char, class Traits, class Alloc>
      inline
      std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, 
        const quoted_proxy<std::basic_string<Char, Traits, Alloc>&, Char>& proxy)
      {
        return basic_string_inserter_imp(os, proxy.string, proxy.escape, proxy.delim);
      }
 
      //  inserter for const C-string* proxies
      template <class Char, class Traits>
      std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& os, 
        const quoted_proxy<const Char*, Char>& proxy)
      {
        os << proxy.delim;
        for (const Char* it = proxy.string;
          *it;
          ++it )
        {
          if (*it == proxy.delim || *it == proxy.escape)
            os << proxy.escape;
          os << *it;
        }
        os << proxy.delim;
        return os;
      }

      //  extractor for non-const std::basic_string& proxies
      template <class Char, class Traits, class Alloc>
      std::basic_istream<Char, Traits>& operator>>(std::basic_istream<Char, Traits>& is, 
        const quoted_proxy<std::basic_string<Char, Traits, Alloc>&, Char>& proxy)
      {
        proxy.string.clear();
        Char c;
        is >> c;
        if (c != proxy.delim)
        {
          is.unget();
          is >> proxy.string;
          return is;
        }
        {
          ios_flags_saver ifs(is);
          is >> std::noskipws;
          for (;;)  
          {
            is >> c;
            if (!is.good())  // cope with I/O errors or end-of-file
              break;
            if (c == proxy.escape)
            {
              is >> c;
              if (!is.good())  // cope with I/O errors or end-of-file
                break;
            }
            else if (c == proxy.delim)
              break;
            proxy.string += c;
          }
        }
        return is;
      }

    }  // namespace detail

    //  manipulator implementation for const std::basic_string&
    template <class Char, class Traits, class Alloc>
    inline detail::quoted_proxy<std::basic_string<Char, Traits, Alloc> const &, Char>
    quoted(const std::basic_string<Char, Traits, Alloc>& s, Char escape, Char delim)
    {
      return detail::quoted_proxy<std::basic_string<Char, Traits, Alloc> const &, Char>
        (s, escape, delim);
    }

    //  manipulator implementation for non-const std::basic_string&
    template <class Char, class Traits, class Alloc>
    inline detail::quoted_proxy<std::basic_string<Char, Traits, Alloc> &, Char>
    quoted(std::basic_string<Char, Traits, Alloc>& s, Char escape, Char delim)
    {
      return detail::quoted_proxy<std::basic_string<Char, Traits, Alloc>&, Char>
        (s, escape, delim);
    }

    //  manipulator implementation for const C-string*
    template <class Char>
    inline detail::quoted_proxy<const Char*, Char>
    quoted(const Char* s, Char escape, Char delim)
    {
      return detail::quoted_proxy<const Char*, Char> (s, escape, delim);
    }
#endif
}


class MonthDayTime
{
private:
    struct pair
    {
        date::month_day month_day_;
        date::weekday   weekday_;
    };

    enum Type {month_day, month_last_dow, lteq, gteq};

    Type                         type_{month_day};

#if defined(_MSC_VER) && (_MSC_VER < 1900)
    struct U
#else
	union U
#endif
	{
        date::month_day          month_day_;
        date::month_weekday_last month_weekday_last_;
        pair                     month_day_weekday_;

        U() : month_day_{date::jan/1} {}
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
    MonthDayTime(second_point tp, tz timezone);
    MonthDayTime(const date::month_day& md, tz timezone);

    date::day day() const;
    date::month month() const;
    tz zone() const {return zone_;}

    void canonicalize(date::year y);

    second_point
       to_sys(date::year y, std::chrono::seconds offset, std::chrono::seconds save) const;
    date::day_point to_day_point(date::year y) const;

    second_point to_time_point(date::year y) const;
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

struct Zone::zonelet
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

    std::string          format_;
    date::year           until_year_{0};
    MonthDayTime         until_date_;
    second_point         until_utc_;
    second_point         until_std_;
    second_point         until_loc_;
    std::chrono::minutes initial_save_{};
    std::string          initial_abbrev_;
    std::pair<const Rule*, date::year> first_rule_{nullptr, date::year::min()};
    std::pair<const Rule*, date::year> last_rule_{nullptr, date::year::max()};

    ~zonelet();
    zonelet();
    zonelet(const zonelet& i);
    zonelet& operator=(const zonelet&) = delete;
};

}  // namespace date

#endif  // TZ_PRIVATE_H
