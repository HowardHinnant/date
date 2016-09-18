/*
 * subsecs.h
 *
 *  Created on: 16 Sep 2016
 *      Author: acolomitchi
 *
 * The no-shouting MIT License (ns-MIT)
 *
 * Copyright (c) 2016 Adrian Colomitchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * Disclaimer (no longer in All-Caps but still exonerating the authors and/or
 * copyright holders):
 *
 * The software is provided "as is", without warranty of any kind, express or
 * implied, including but not limited to the warranties of merchantability,
 * fitness for a particular purpose and noninfringement. In no event shall the
 * authors or copyright holders be liable for any claim, damages or other
 * liability, whether in an action of contract, tort or otherwise, arising from,
 * out of or in connection with the software or the use or other dealings in the
 * software.
 */

#ifndef SUBSECS_H_
#define SUBSECS_H_

#include <chrono>
#include <ostream>
#include <limits>
#include <locale>
#include <string>
#include <type_traits>

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


namespace date {
// forward declaration: this should disappear anyway if/when the content
// of this header is cannibalized into the appropriate place in `date.h`
template <class To, class Rep, class Period>
CONSTCD14 To floor(const std::chrono::duration<Rep, Period>& d);

namespace detail {

template <std::uintmax_t val, std::uintmax_t base>
struct ceil_log_struct {
private:
  // need one level of indirection to arrest infinite recursion upon
  // checking '(value<b)' stop condition
  template <bool, std::uintmax_t v, std::uintmax_t b=10>
  struct nl_len_tag;

  // recursion will stop when the (val < b), the literal length will be 1
  template <std::uintmax_t v, std::uintmax_t b>
  struct nl_len_tag<false, v, b> {
    static CONSTDATA unsigned value=1;
  };

  // if val>=b, call numliteral_len with val/b and add one to the returned value
  template <std::uintmax_t v, std::uintmax_t b>
  struct nl_len_tag<true, v, b> {
    static CONSTDATA unsigned value=ceil_log_struct<v/b, b>::value + 1;
  };

  using sfinae_guard_type=typename std::enable_if<
      (base>1) // don't accept base of 0 or 1, they don't make sense
  >::type;
public:
  static CONSTDATA unsigned value=
      nl_len_tag<(val>base), val, base>::value;

};

// ------
// ***Warning: note the unusual order of (power, base) for the parameters
// *** due to the default val for the base

template <unsigned long exponent, std::uintmax_t base=10>
struct pow_struct
{
private:
  static CONSTDATA std::uintmax_t at_half_pow=pow_struct<exponent / 2, base>::value;
public:
  static CONSTDATA std::uintmax_t value=
      at_half_pow*at_half_pow*(exponent % 2 ? base : 1)
  ;
};

template <std::uintmax_t base>
struct pow_struct<1, base>
{
  static CONSTDATA long long value=base;
};


template <std::uintmax_t base>
struct pow_struct<0,base>
{
  static CONSTDATA long long value=1;
};

#define POW10(width) (pow_struct<(width), 10>::value)
#define CEIL_LOG10(val) (ceil_log_struct<(val),10>::value)


// Inserting a right-aligned, 0-filled literal representation in base10
// of an integral number of type T, strictly obeying the limits of a specified
// width (number of characters available). Discards the sign
// if the presented value is signed and is negative.
// If the provided number does not fit into the allocated width,
// ***it will throw away the overflow, representing only the
// less-significant-digits*** - if I'm not mistaken, this is
// a necessary price to pay for compile-time loop unrolling
template <unsigned width, typename T=std::uintmax_t>
struct decimals_fmt {
private:
  // allow floating point representation as well, they go OK after sign elimination
  using type=typename std::enable_if<std::is_arithmetic<T>::value, T>::type;

  // the maximum unsigned value representable on 'width' digits
  static CONSTDATA std::uintmax_t max_val=POW10(width);

  // what the first value we should use for the division to get the first digit
  static CONSTDATA std::uintmax_t div_val=max_val/10;

  static type condition_value(const type val) {
    // discard the sign.
    type value=(val>=0 ? val : -val);
    // if it's greater or equal than the max_val (thus 'width' is not large enough)...
    //  ... then won't be able to deal with the excess, so just keep only the remainder
    value %= max_val;
    return value;
  }
public:
  template <typename CharT=char>
  void put(
    std::basic_string<CharT>& dest,
    std::size_t& inspos, type val
  )
  {
    type value=condition_value(val);
    CharT toIns=static_cast<CharT>('0'+(value / div_val));
    dest[inspos]=toIns;
    // advance and unroll one step further
    ++inspos;
    decimals_fmt<width-1, T> unrolled; // the compiler MUST evaluate this
    unrolled.put(dest, inspos, value % div_val);
  }


  // let's do something similar for appending in an ostream
  template <typename CharT=char>
  std::basic_ostream<CharT>&
  put(std::basic_ostream<CharT>& os, type value)
  {
    value=condition_value(value);
    os << static_cast<CharT>('0'+(value / div_val));
    // unroll one step further
    decimals_fmt<width-1, T> unrolled; // the compiler MUST evaluate this
    return unrolled.put(os, value % div_val);
  }
};

template <typename U>
struct decimals_fmt<0, U> {
private:
  using type=typename std::enable_if<std::is_arithmetic<U>::value, U>::type;
public:
  template <typename CharT=char>
  void put(std::basic_string<CharT>& dest,std::size_t& inspos, type val)
  { // with a width of zero, nothing happens;
  }

  template <typename CharT=char>
  std::basic_ostream<CharT>&
  put(std::basic_ostream<CharT>& os, type value)
  { // with a width of zero, nothing happens;
    return os;
  }
};


template <class SrcPeriod>
struct time_subsec_put {

private:
  // one extra level of indirection to deal with has/has-not subsecs
  template <bool has_subsecs,class Period=SrcPeriod> struct delegate;

  // this specialization will be chosen when the Period has subseconds
  template <class Period> struct delegate<true, Period> {
    template <typename Rep> using dur_type=std::chrono::duration<Rep, Period>;
    template <class Clock, typename Rep> using tp_type=
        std::chrono::time_point<Clock, dur_type<Rep>>;

    // Heuristic: denominator also carry the required precision
    static CONSTDATA std::uintmax_t max_val=
        POW10(CEIL_LOG10(Period::den))
    ;

    // the 'width' occupied by the digits.
    static CONSTDATA unsigned precision=CEIL_LOG10(max_val);

    // This is the space needed to output the subseconds value in full precision,
    // including the decimal dot.
    static CONSTDATA unsigned space_req=precision+1;


    // precomputed scale factor to be applied to received counts
    static CONSTDATA long double scale_factor=
      1.0L*max_val*Period::num/Period::den
    ;

    // Because we are supposed to deal with **sub**-seconds, anything that goes
    // above max_val is discarded (we only keep the lesser-significant digits)
    template <class Clock, typename Rep>
    static Rep condition_value(tp_type<Clock, Rep> tp) {
      // obtain the subseconds here: must use auto to adjust for odd ratios (likw 355/113)
      auto subsecs=tp-floor<std::chrono::seconds>(tp);
      std::uintmax_t scaled=static_cast<std::uintmax_t>(scale_factor*subsecs.count());
      return static_cast<Rep>(scaled % max_val);
    }

    // for periods that do have subseconds
    template <typename Clock, typename Rep, typename CharT, typename CharTraits>
    static void insert(
      std::basic_string<CharT, CharTraits>& dest,
      std::size_t& inspos,
      tp_type<Clock, Rep> tp,
      const std::locale& loc
    )
    {
      // obtain the conditioned subseconds here
      Rep subsecs=condition_value(tp);
      // make room for the content in the destination
      dest.insert(inspos, space_req, ' ');
      // insert the decimal dot
      CharT dotChar=std::use_facet<std::numpunct<CharT>>(loc).decimal_point();
      dest[inspos]=dotChar;
      inspos++;
      // prepare the decimals formatter
      decimals_fmt<precision, Rep> formatter;
      // render the value
      formatter.put(dest, inspos, subsecs);
    }

    // In ostream
    // Periods with subseconds
    template <typename Clock, typename Rep, typename CharT, typename CharTraits>
    static std::basic_ostream<CharT>& put(
        std::basic_ostream<CharT, CharTraits>& os,
        tp_type<Clock, Rep> tp
    )
    {
      // obtain the conditioned subseconds here
      Rep subsecs=condition_value(tp);
      // insert the decimal dot
      os << std::use_facet<std::numpunct<CharT>>(os.getloc()).decimal_point();
      // prepare the formatter
      decimals_fmt<precision, Rep> formatter;
      // echo the value
      formatter.put(os, subsecs);
      return os;
    }
  };

  // this specialization will be chosen when the Period does not have subseconds
  template <class Period> struct delegate<false, Period> {
    template <typename Rep> using dur_type=std::chrono::duration<Rep, Period>;
    template <class Clock, typename Rep> using tp_type=
        std::chrono::time_point<Clock, dur_type<Rep>>;
    template <class Clock, typename Rep,typename CharT, typename CharTraits>
    static void insert(
        std::basic_string<CharT, CharTraits>& dest,
        std::size_t& inspos,
        tp_type<Clock, Rep> tp,
        const std::locale& loc
    ) { // do nothing, no subsecs
    }
    template <class Clock, typename Rep, typename CharT, typename CharTraits>
    static std::basic_ostream<CharT>& put(
        std::basic_ostream<CharT,CharTraits>& os,
        tp_type<Clock, Rep> tp
    ) {// do nothing, no subsecs
      return os;
    }
  };
public:
  // A more relaxed condition than the (num < den)
  // Any already reduced rational fraction with den>1 will
  // cause decimals (if it didn't, then it would be an integer)
  static CONSTDATA bool admits_subsecs= (SrcPeriod::den!=1);

  // delegating the methods based on the admits/doesn't admit subseconds
  template <class Clock, typename Rep,typename CharT, typename CharTraits>
  static void insert(
      std::basic_string<CharT, CharTraits>& dest,
      std::size_t& inspos,
      std::chrono::time_point<Clock, std::chrono::duration<Rep,SrcPeriod>> tp,
      const std::locale& loc
  ) {
    delegate<admits_subsecs, SrcPeriod>::insert(dest, inspos, tp, loc);
  }
  template <class Clock, typename Rep, typename CharT, typename CharTraits>
  static std::basic_ostream<CharT>& put(
      std::basic_ostream<CharT,CharTraits>& os,
      std::chrono::time_point<Clock, std::chrono::duration<Rep,SrcPeriod>> tp
  ) {
    return delegate<admits_subsecs, SrcPeriod>::put(os, tp);
  }
};
#undef POW10
#undef CEIL_LOG10

} // namespace detail
} // namespace date


#undef CONSTDATA
#undef CONSTCD11
#undef CONSTCD14
#undef NOEXCEPT

#endif /* SUBSECS_H_ */
