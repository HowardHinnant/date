#include <chrono>
#include "date/tz.h"

int
main()
{
   using namespace date;
   using namespace std::chrono;

   // self
   {
     auto ls = local_days{1970_y/January/1_d};
     assert(clock_cast<local_t>(ls) == ls);
   }

   /// sys epoch
   {
     auto ls = local_days{1970_y/January/1_d};
     auto st = clock_cast<system_clock>(ls);
     assert(clock_cast<local_t>(st) == ls);
     assert(st.time_since_epoch() == seconds(0));
   }

   /// sys 2000 case
   {
     auto ls = local_days{2000_y/January/1_d};
     auto st = clock_cast<system_clock>(ls);
     assert(clock_cast<local_t>(st) == ls);
     assert(st.time_since_epoch() == seconds(946684800));
   }

   /// utc epoch
   {
     auto lu = local_days{1970_y/January/1_d};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<local_t>(ut) == lu);
     assert(ut.time_since_epoch() == seconds(0));
   }

   // utc leap second
   {
     auto lu = local_days{2January5_y/07/1_d} - milliseconds(1);
     auto ut = clock_cast<utc_clock>(lu) + milliseconds(50); //into leap second

     assert(clock_cast<local_t>(ut) == lu);
   }

   /// utc paper example
   {
     auto lu = local_days{2000_y/January/1_d};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<local_t>(ut) == lu);
     assert(ut.time_since_epoch() == seconds(946684822));
   }

   /// tai epoch
   {
     auto lt = local_days{1958_y/January/1_d};
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<local_t>(tt) == lt);
     assert(tt.time_since_epoch() == seconds(0));

     auto lu = local_days{1958_y/January/1_d} - seconds(10);
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<tai_clock>(ut) == tt);
   }

   // tai paper example
   {
      auto lt = local_days{2000_y/January/1_d} + seconds(32);
      auto tt = clock_cast<tai_clock>(lt);
      assert(clock_cast<local_t>(tt) == lt);

      auto lu = local_days{2000_y/January/1_d};
      auto ut = clock_cast<utc_clock>(lu);
      assert(clock_cast<tai_clock>(ut) == tt);
   }

   /// gps epoch
   {
     auto lg = local_days{1980_y/January/Sunday[1]};
     auto gt = clock_cast<gps_clock>(lg);
     assert(clock_cast<local_t>(gt) == lg);
     assert(gt.time_since_epoch() == seconds(0));

     auto lu = local_days{1980_y/January/Sunday[1]};
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<gps_clock>(ut) == gt);

     auto lt = local_days{1980_y/January/Sunday[1]} + seconds(19);
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<gps_clock>(tt) == gt);
   }

   // gps 2000 example
   {
     auto lg = local_days{2000_y/January/1_d};
     auto gt = clock_cast<gps_clock>(lg);
     assert(clock_cast<local_t>(gt) == lg);

     auto lu = local_days{2000_y/January/1_d} - seconds(13);
     auto ut = clock_cast<utc_clock>(lu);
     assert(clock_cast<gps_clock>(ut) == gt);

     auto lt = local_days{2000_y/January/1_d} + seconds(19);
     auto tt = clock_cast<tai_clock>(lt);
     assert(clock_cast<gps_clock>(tt) == gt);
   }

}
