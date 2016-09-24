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


// The algorithm for ceil_log using div/mod:
// - repeatedly divide the value by base, until the result is
//    less than base and greater than zero. The number of divisions
//    is floor_ceil.
//  - if at any division step above there is a reminder, then
//    ceil_log is floor_log+1. If no reminder at any step, then
//    floor_log=ceil_log(=log)
// The internal floor_log_tag does the divisions recursively and stores
//  the floor_log as the value + the information on whether or not
//  a reminder has been detected.
template <std::uintmax_t val, std::uintmax_t base>
struct ceil_log_struct {
private:
  // first (bool) arg will be true if val >= base (another division step is possible)
  // false otherwise.
  template <bool, std::uintmax_t v, std::uintmax_t b=10>
  struct floor_log_tag;

  // recursion will also stop when val==1 (floor_ceil==0) with no reminder
  template <std::uintmax_t b>
  struct floor_log_tag<false, 1, b> {
    static CONSTDATA unsigned value=0;
    static CONSTDATA bool     has_reminder=0;
  };

  // Recursion will stop when (1 < val < b). For val==1, the more specific
  // specialization above is preferred.
  template <std::uintmax_t v, std::uintmax_t b>
  struct floor_log_tag<false, v, b> {
    static CONSTDATA unsigned value=1;
    static CONSTDATA bool     has_reminder=1;
  };


  // if val>=b (first arg to true),
  // recursively call yourself with the v/b.
  // Record your reminder existence or any reminder existence on the way down
  template <std::uintmax_t v, std::uintmax_t b>
  struct floor_log_tag<true, v, b> {
    using recurse_step = floor_log_tag< (v/b>=b), v/b, b>;
    static CONSTDATA unsigned value=recurse_step::value+1;
    static CONSTDATA bool     has_reminder=( v % b ) || recurse_step::has_reminder;
  };

  using sfinae_guard_type=typename std::enable_if<
        (base>1) // don't accept base of 0 or 1, they don't make sense
    &&  (val>0)  // don't accept a zero for the argument of log
  >::type;

  using floor_log= floor_log_tag<(val>=base), val, base>;
public:
  static CONSTDATA unsigned value=
      floor_log::value
    + static_cast<std::uintmax_t>(floor_log::has_reminder)
  ;

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
  static CONSTDATA std::uintmax_t value=base;
};


template <std::uintmax_t base>
struct pow_struct<0,base>
{
  static CONSTDATA std::uintmax_t value=1;
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
  // allow floating point representation as well, they are OK after sign elimination
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

template <class Period>
struct period_traits {
  static CONSTDATA std::uintmax_t NUM=Period::num;
  static CONSTDATA std::uintmax_t DEN=Period::den;

  // Heuristic: denominator also carry the required precision
  static CONSTDATA std::uintmax_t max_val=
      POW10(CEIL_LOG10(Period::den))
  ;

  // the 'width' occupied by the digits.
  static CONSTDATA unsigned precision=CEIL_LOG10(max_val);

  // This is the space needed to output the subseconds value in full precision,
  // including the decimal dot.
  static CONSTDATA unsigned space_req=precision+1;

  // Because we are supposed to deal with **sub**-seconds, anything that goes
  // above max_val is discarded (we only keep the lesser-significant digits)
  template <typename Rep, class SrcPeriod>
  static Rep condition_value(std::chrono::duration<Rep, SrcPeriod> duration) {
    long double realSecs;
    if(std::abs(SrcPeriod::num)>std::abs(SrcPeriod::den)) {
      realSecs=(static_cast<long double>(SrcPeriod::num)/SrcPeriod::den)*duration.count();
    }
    else {
      realSecs=static_cast<long double>(SrcPeriod::num*duration.count())/SrcPeriod::den;
    }
    realSecs=std::abs(realSecs-std::trunc(realSecs));
    // at this point realSecs contains the fractional part of the seconds as a floating point
    std::uintmax_t scaled=static_cast<std::uintmax_t>(std::round(realSecs*max_val));
    return static_cast<Rep>(scaled % max_val);
  }

  // A more relaxed condition than the (num < den)
  // Any already reduced rational fraction with den>1 will
  // cause decimals (if it didn't, then it would be an integer)
  static CONSTDATA bool admits_subsecs= (Period::den!=1);
};


// deals only with the insertion in strings from a std::chrono::timepoint
template <class Period>
struct time_subsec_insert
{
private:
  using traits=period_traits<Period>;

  template <typename R> using d_type=std::chrono::duration<R, Period>;

  template <class C, typename R>
    using tp_type=std::chrono::time_point<C, d_type<R>>;

  template <bool flag, typename>
  struct delegate;

  template <typename P> struct delegate<true, P>
  {
    template <
      class Clock, typename Rep,
      typename CharT, typename CharTraits
    >
    static void insert(
      std::basic_string<CharT, CharTraits>& dest,
      std::size_t& inspos,
      tp_type<Clock, Rep> value,
      const std::locale& loc
    )
    {
      auto subsecsDuration=value-floor<std::chrono::seconds>(value);
      // obtain the conditioned subseconds here
      Rep subsecs=traits::condition_value(subsecsDuration);
      // make room for the content in the destination
      dest.insert(inspos, traits::space_req, ' ');
      // insert the decimal dot
      CharT dotChar=std::use_facet<std::numpunct<CharT>>(loc).decimal_point();
      dest[inspos]=dotChar;
      inspos++;
      // prepare the decimals formatter
      decimals_fmt<traits::precision, Rep> formatter;
      // render the value
      formatter.put(dest, inspos, subsecs);
    }
  };

  template <typename P> struct delegate<false, P> {

    template <
      class Clock, typename Rep,
      typename CharT, typename CharTraits
    >
    static void insert(
      std::basic_string<CharT, CharTraits>& dest,
      std::size_t& inspos,
      tp_type<Clock, Rep> value,
      const std::locale& loc
    ) { // does nothing
    }
  };
public:
  static CONSTDATA bool admits_subsecs=traits::admits_subsecs;

  template <class Clock,typename Rep,typename CharT, typename CharTraits>
  static void insert(
      std::basic_string<CharT, CharTraits>& dest,
      std::size_t& inspos,
      std::chrono::time_point<Clock, std::chrono::duration<Rep,Period>> tp,
      const std::locale& loc
  ) {
    delegate<admits_subsecs, Period>::insert(dest, inspos, tp, loc);
  }
};

// deals only with the append in ostream from a std::chrono::duration
template <class Period>
struct time_subsec_put
{
private:
  using traits=period_traits<Period>;

  template <typename R> using d_type=std::chrono::duration<R, Period>;

  template <bool flag, typename>
  struct delegate;

  template <typename P> struct delegate<true, P>
  {
    template <typename Rep, typename CharT, typename CharTraits>
    static std::basic_ostream<CharT>& put(
      std::basic_ostream<CharT, CharTraits>& os,
      d_type<Rep> value
    )
    {
      // obtain the conditioned subseconds here
      Rep subsecs=traits::condition_value(value);
      // insert the decimal dot
      os << std::use_facet<std::numpunct<CharT>>(os.getloc()).decimal_point();
      // prepare the formatter
      decimals_fmt<traits::precision, Rep> formatter;
      // echo the value
      formatter.put(os, subsecs);
      return os;
    }
  };

  template <typename P> struct delegate<false, P> {
    template <typename Rep, typename CharT, typename CharTraits>
    static std::basic_ostream<CharT>& put(
      std::basic_ostream<CharT, CharTraits>& os,
      d_type<Rep> value
    )
    { // does nothing
      return os;
    }
  };
public:
  static CONSTDATA bool admits_subsecs=traits::admits_subsecs;

  // appending to ostreams
  template <typename Rep,typename CharT, typename CharTraits>
  static std::basic_ostream<CharT>& put(
      std::basic_ostream<CharT,CharTraits>& os,
      std::chrono::duration<Rep, Period> value
  ) {
    return delegate<admits_subsecs, Period>::put(os, value);
  }
};

//#undef POW10
//#undef CEIL_LOG10

} // namespace detail
} // namespace date


#undef CONSTDATA
#undef CONSTCD11
#undef CONSTCD14
#undef NOEXCEPT

#endif /* SUBSECS_H_ */
