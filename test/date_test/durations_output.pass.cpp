// The MIT License (MIT)
//
// Copyright (c) 2018 Tomasz Kamiński
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


#include "date.h"

#include <cassert>
#include <sstream>

void test_SI()
{
   using namespace std::chrono;
   using namespace date;

   std::ostringstream os;

   // atto
   {
     duration<int, std::atto> d(13);
     os << d;
     assert(os.str() == "13as");
     os.str("");
   }

   // femto
   {
     duration<int, std::femto> d(13);
     os << d;
     assert(os.str() == "13fs");
     os.str("");
   }

   // pico
   {
     duration<int, std::pico> d(13);
     os << d;
     assert(os.str() == "13ps");
     os.str("");
   }

   // nano
   {
     duration<int, std::nano> d(13);
     os << d;
     assert(os.str() == "13ns");
     os.str("");
   }

   // mikro
   {
     duration<int, std::micro> d(13);
     os << d;
     assert(os.str() == "13\xC2\xB5s");
     os.str("");
   }

   // milli
   {
     duration<int, std::milli> d(13);
     os << d;
     assert(os.str() == "13ms");
     os.str("");
   }

   // centi
   {
     duration<int, std::centi> d(13);
     os << d;
     assert(os.str() == "13cs");
     os.str("");
   }

   // deci
   {
     duration<int, std::deci> d(13);
     os << d;
     assert(os.str() == "13ds");
     os.str("");
   }

   // seconds
   {
     duration<int> d(13);
     os << d;
     assert(os.str() == "13s");
     os.str("");
   }

   // deca
   {
     duration<int, std::deca> d(13);
     os << d;
     assert(os.str() == "13das");
     os.str("");
   }

   // hecto
   {
     duration<int, std::hecto> d(13);
     os << d;
     assert(os.str() == "13hs");
     os.str("");
   }

   // kilo
   {
     duration<int, std::kilo> d(13);
     os << d;
     assert(os.str() == "13ks");
     os.str("");
   }

   // mega
   {
     duration<int, std::mega> d(13);
     os << d;
     assert(os.str() == "13Ms");
     os.str("");
   }

   // giga
   {
     duration<int, std::giga> d(13);
     os << d;
     assert(os.str() == "13Gs");
     os.str("");
   }

   // tera
   {
     duration<int, std::tera> d(13);
     os << d;
     assert(os.str() == "13Ts");
     os.str("");
   }

   // peta
   {
     duration<int, std::peta> d(13);
     os << d;
     assert(os.str() == "13Ps");
     os.str("");
   }

   // femto
   {
     duration<int, std::exa> d(13);
     os << d;
     assert(os.str() == "13Es");
     os.str("");
   }
}

void test_calendar()
{
   using namespace std::chrono;
   using namespace date;

   std::ostringstream os;

   // minutes
   {
      minutes d(13);
      os << d;
      assert(os.str() == "13min");
      os.str("");
   }

   // hours
   {
      hours d(13);
      os << d;
      assert(os.str() == "13h");
      os.str("");
   }

   // days
   {
      days d(13);
      os << d;
      assert(os.str() == "13d");
      os.str("");
   }
}

void test_integral_scale()
{
   using namespace std::chrono;
   using namespace date;

   std::ostringstream os;

   // ratio 123 / 1
   {
      duration<int, std::ratio<123, 1>> d(13);
      os << d;
      assert(os.str() == "13[123]s");
      os.str("");
   }

   // ratio 100 / 4 = ratio 25 / 1
   {
      duration<int, std::ratio<25, 1>> d(13);
      os << d;
      assert(os.str() == "13[25]s");
      os.str("");
   }

   // weeks = ratio 7 * 24 * 60 * 60 / 1 = ratio 604800 / 1
   {
      weeks d(13);
      os << d;
      assert(os.str() == "13[604800]s");
      os.str("");
   }

   // years = 146097/400 days = ratio 146097/400 * 24 * 60 * 60 = ratio 31556952 / 1
   {
      years d(13);
      os << d;
      assert(os.str() == "13[31556952]s");
      os.str("");
   }

   // months = 1/12 years = ratio 1/12 * 31556952  = ratio 2629746 / 1
   {
      months d(13);
      os << d;
      assert(os.str() == "13[2629746]s");
      os.str("");
   }
}

void test_ratio_scale()
{
   using namespace std::chrono;
   using namespace date;

   std::ostringstream os;

   // ratio 1 / 2
   {
      duration<int, std::ratio<1, 2>> d(13);
      os << d;
      assert(os.str() == "13[1/2]s");
      os.str("");
   }

   // ratio 100 / 3
   {
      duration<int, std::ratio<100, 3>> d(13);
      os << d;
      assert(os.str() == "13[100/3]s");
      os.str("");
   }

   // ratio 100 / 6 = ratio 50 / 3
   {
      duration<int, std::ratio<100, 6>> d(13);
      os << d;
      assert(os.str() == "13[50/3]s");
      os.str("");
   }
}

void test_constexpr()
{
  using date::detail::get_units;

  CONSTCD11 auto as = get_units<char>(std::atto{});
  CONSTCD11 auto fs = get_units<char>(std::femto{});
  CONSTCD11 auto ps = get_units<char>(std::pico{});
  CONSTCD11 auto ns = get_units<char>(std::nano{});
  CONSTCD11 auto us = get_units<char>(std::micro{});
  CONSTCD11 auto usw = get_units<wchar_t>(std::micro{});
  CONSTCD11 auto ms = get_units<char>(std::milli{});
  CONSTCD11 auto cs = get_units<char>(std::centi{});
  CONSTCD11 auto ds = get_units<char>(std::deci{});
  CONSTCD11 auto s = get_units<char>(std::ratio<1>{});
  CONSTCD11 auto das = get_units<char>(std::deca{});
  CONSTCD11 auto hs = get_units<char>(std::hecto{});
  CONSTCD11 auto ks = get_units<char>(std::kilo{});
  CONSTCD11 auto Ms = get_units<char>(std::mega{});
  CONSTCD11 auto Gs = get_units<char>(std::giga{});
  CONSTCD11 auto Ts = get_units<char>(std::tera{});
  CONSTCD11 auto Ps = get_units<char>(std::peta{});
  CONSTCD11 auto Es = get_units<char>(std::exa{});
  (void)as, (void)fs, (void)ps, (void)ns, (void)usw, (void)us,
  (void)ms, (void)cs, (void)ds, (void)s,  (void)das, (void)hs,
  (void)ks, (void)Ms, (void)Gs, (void)Ts, (void)Ps,  (void)Es;

  CONSTCD11 auto min = get_units<char>(std::ratio<60>{});
  CONSTCD11 auto h = get_units<char>(std::ratio<3600>{});
  CONSTCD11 auto d = get_units<char>(std::ratio<86400>{});
  (void)min, (void)h, (void)d;

  CONSTCD14 auto integer = get_units<char>(std::ratio<123>{});
  CONSTCD14 auto ratio = get_units<char>(std::ratio<123, 3>{});
  (void)integer, (void)ratio;
}

int
main()
{
  test_SI();
  test_calendar();
  test_integral_scale();
  test_ratio_scale();
}
