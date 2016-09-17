/*
 * subsecs.h
 *
 *  Created on: 16 Sep 2016
 *      Author: acolomitchi
 */

#ifndef SUBSECS_H_
#define SUBSECS_H_

#include <iostream>
#include <limits>
#include <locale>
#include <string>

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
namespace detail {


// Like std::enable_if, but for values
template <bool, typename T, T v>
struct v_enable_if;

template <typename T, T v>
struct v_enable_if<false, T, v> {
};

template <typename T, T v>
struct v_enable_if<true,T,v> {
  static CONSTDATA T value=v;
};

template <std::uintmax_t val, std::uintmax_t base>
struct ceil_log_struct {

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

  static CONSTDATA unsigned value=
      v_enable_if<
          (base>1), // don't accept base of 0 or 1, they don't make sense
          unsigned,
          nl_len_tag<(val>base), val, base>::value
      >::value
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
  using type=typename std::enable_if<std::is_arithmetic<U>::value, U>::type;

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
  // A more relaxed condition than the (num < den)
  // Any already reduced rational fraction with den>1 will
  // cause decimals (if it didn't, then it would be an integer)
  static CONSTDATA bool admits_subsecs= (SrcPeriod::den!=1);

  // refuse to deal with values greater than seconds, thus require
  // SrcPeriod::num strictly less than SrcPeriod::den.
  // Heuristic: denominator also carry the required precision
  static CONSTDATA std::uintmax_t max_val=
      POW10(CEIL_LOG10(SrcPeriod::den))
  ;

  // the 'width' occupied by the digits.
  static CONSTDATA unsigned precision=CEIL_LOG10(max_val);

  // This is the space needed to output the subseconds value in full precision,
  // including the decimal dot.
  static CONSTDATA unsigned space_req=precision+1;


  // precomputed scale factor to be applied to received counts
  static CONSTDATA long double scale_factor=
    1.0L*max_val*SrcPeriod::num/SrcPeriod::den
  ;

  // Because we are supposed to deal with **sub**-seconds, anything that goes
  // above max_val is discarded (we only keep the lesser-significant digits)
  template <typename Rep> Rep condition_value(Rep count) {
    std::uintmax_t scaled=static_cast<std::uintmax_t>(scale_factor*count);
    return static_cast<Rep>(scaled % max_val);
  }

  // for periods that do have subseconds
  template <typename Rep,typename CharT>
  void insert(
    std::basic_string<CharT>& dest,
    std::size_t& inspos,
    std::chrono::duration<Rep, SrcPeriod> duration,
    const std::locale& loc
  )
  {
    if(admits_subsecs) {
      // scale the count
      Rep count=condition_value(duration.count());
      // make room for the content in the destination
      dest.insert(inspos, space_req, ' ');
      // insert the decimal dot
      CharT dotChar=std::use_facet<std::numpunct<CharT>>(loc).decimal_point();
      dest[inspos]=dotChar;
      inspos++;
      // prepare the filler
      decimals_fmt<precision, Rep> filler;
      // output the value
      filler.put(dest, inspos, count);
    }
  }

  // In ostream
  // Periods with subseconds
  template <typename Rep, typename CharT=char>
  std::basic_ostream<CharT>& put(
      std::basic_ostream<CharT>& os,
      std::chrono::duration<Rep,SrcPeriod> count
  )
  {
    if(admits_subsecs) {
      // scale the count
      count=condition_value(count);
      // insert the decimal dot
      os << std::use_facet<std::numpunct<CharT>>(os.getloc()).decimal_point();
      // prepare the filler
      decimals_fmt<precision, Rep> filler;
      // echo the value
      filler.put(os, count);
    }
    return os;
  }
};

} // namespace detail
} // namespace date


#undef CONSTDATA
#undef CONSTCD11
#undef CONSTCD14
#undef NOEXCEPT

#endif /* SUBSECS_H_ */
