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

#include <chrono>
#include "date/tz.h"

int
main()
{
   using namespace date;
   using namespace std::chrono;

   // before leap second
   {
     auto lu = local_days{2015_y/July/1_d} - seconds(1);
     auto ut = clock_cast<utc_clock>(lu);
     auto is_leap = is_leap_second(ut);
     assert(!is_leap.first);
     assert(is_leap.second == seconds(25));

     assert(utc_clock::to_local(ut) == lu);
     assert(utc_clock::to_local(ut, choose::earliest) == lu);
     assert(utc_clock::to_local(ut, choose::latest) == lu);

     assert(clock_cast<local_t>(ut) == lu);
   }

   // during leap second, milliseconds precision
   {
     auto lu = local_days{2015_y/July/1_d};
     auto ut = clock_cast<utc_clock>(lu) - milliseconds(50); //into leap second
     auto is_leap = is_leap_second(ut);
     assert(is_leap.first);
     assert(is_leap.second == seconds(26));

     try
     {
        clock_cast<local_t>(ut);
        assert(false);
     }
     catch (leap_second_insertion)
     {}

     assert(utc_clock::to_local(ut, choose::earliest) == lu - milliseconds(1));
     assert(utc_clock::to_local(ut, choose::latest) == lu);

     try
     {
        clock_cast<local_t>(ut);
        assert(false);
     }
     catch (leap_second_insertion)
     {}
   }

   // during leap second, nonoseconds precision
   {
     auto lu = local_days{2015_y/July/1_d};
     auto ut = clock_cast<utc_clock>(lu) - nanoseconds(50); //into leap second
     auto is_leap = is_leap_second(ut);
     assert(is_leap.first);
     assert(is_leap.second == seconds(26));

     try
     {
        utc_clock::to_local(ut);
        assert(false);
     }
     catch (leap_second_insertion)
     {}

     assert(utc_clock::to_local(ut, choose::earliest) == lu - nanoseconds(1));
     assert(utc_clock::to_local(ut, choose::latest) == lu);

     try
     {
        clock_cast<local_t>(ut);
        assert(false);
     }
     catch (leap_second_insertion)
     {}
   }

   // after leap second
   {
     auto lu = local_days{2015_y/July/1_d};
     auto ut = clock_cast<utc_clock>(lu);
     auto is_leap = is_leap_second(ut);
     assert(!is_leap.first);
     assert(is_leap.second == seconds(26));

     assert(utc_clock::to_local(ut) == lu);
     assert(utc_clock::to_local(ut, choose::earliest) == lu);
     assert(utc_clock::to_local(ut, choose::latest) == lu);

     assert(clock_cast<local_t>(ut) == lu);
   }
}
