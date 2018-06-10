#include <chrono>
#include "date/tz.h"

int
main()
{
   using namespace date;
   using namespace std::chrono_literals;
   using namespace std::chrono;

   /// sys epoch 
   {
     auto ls = local_days{1970_y/01/01_d};
     auto st = clock_cast<system_clock>(ls);
     assert(clock_cast<local_t>(st) == ls);
     assert(st.time_since_epoch() == 0s);
   }

   /// sys 2000 case 
   {
     auto ls = local_days{2000_y/01/01_d};
     auto st = clock_cast<system_clock>(ls);
     assert(clock_cast<local_t>(st) == ls);
     assert(st.time_since_epoch() == 946'684'800s);
   }


   /// utc epoch 
   {
     auto lu = local_days{1970_y/01/01_d};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<local_t>(ut) == lu);
     assert(ut.time_since_epoch() == 0s);
   }

   /// utc paper example 
   {
     auto lu = local_days{2000_y/01/01_d};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<local_t>(ut) == lu);
     assert(ut.time_since_epoch() == 946'684'822s);
   }

   /// tai epoch
   {
     auto lt = local_days{1958_y/01/01_d};
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<local_t>(tt) == lt);
     assert(tt.time_since_epoch() == 0s);

     auto lu = local_days{1957_y/12/31_d} + 23h + 59min + 50s;
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<tai_clock>(ut) == tt);
   }

   // tai paper example
   {
      auto lt = local_days{2000_y/01/01_d} + 32s;
      auto tt = clock_cast<tai_clock>(lt);
      assert(clock_cast<local_t>(tt) == lt);

      auto lu = local_days{2000_y/01/01_d};
      auto ut = clock_cast<utc_clock>(lu);
      assert(clock_cast<tai_clock>(ut) == tt);
   }

   /// gps epoch
   {
     auto lg = local_days{1980_y/01/Sunday[1]};
     auto gt = clock_cast<gps_clock>(lg);
     assert(clock_cast<local_t>(gt) == lg);
     assert(gt.time_since_epoch() == 0s);

     auto lu = local_days{1980_y/01/Sunday[1]};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<gps_clock>(ut) == gt);

     auto lt = local_days{1980_y/01/Sunday[1]} + 19s;
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<gps_clock>(tt) == gt);
   }

   // gps 2000 example
   {
     auto lg = local_days{2000_y/01/01_d};
     auto gt = clock_cast<gps_clock>(lg);
     assert(clock_cast<local_t>(gt) == lg);

     auto lu = local_days{2000_y/01/01_d} - 13s;
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<gps_clock>(ut) == gt);

     auto lt = local_days{2000_y/01/01_d} + 19s;
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<gps_clock>(tt) == gt);
   }

}
