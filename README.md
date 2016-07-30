[![Join the chat at https://gitter.im/HowardHinnant/date](https://badges.gitter.im/HowardHinnant/date.svg)](https://gitter.im/HowardHinnant/date?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This is actually several separate C++11/C++14 libraries:

1.  `"date.h"` is a header-only library which builds upon `<chrono>`.  It adds some new `duration` types, and new `time_point` types.  It also adds "field" types such as `year_month_day` which is a struct `{year, month, day}`.  And it provides convenient means to convert between the "field" types and the `time_point` types.  See http://howardhinnant.github.io/date/date.html for more details.

    Here is the Cppcon 2015 presentation on date.h: https://www.youtube.com/watch?v=tzyGjOm8AKo

    Here are the Cppcon 2015 slides on date.h: http://schd.ws/hosted_files/cppcon2015/43/hinnant_dates.pdf

2. `"tz.h"` / `"tz.cpp"`  are a timezone library built on top of the `"date.h"` library.  This timezone library is a complete parser of the IANA timezone database.  It provides for an easy way to access all of the data in this database, using the types from `"date.h"` and `<chrono>`.  The IANA database also includes data on leap seconds, and this library provides utilities to compute with that information as well.  See http://howardhinnant.github.io/date/tz.html for more details.

3.  `"chrono_io.h"` is a header-only library for streaming out chrono durations.  See http://howardhinnant.github.io/date/chrono_io.html for more details.

4. `"iso_week.h"` is a header-only library built on top of the `"date.h"` library which implements the ISO week date calendar.  See http://howardhinnant.github.io/date/iso_week.html for more details.

5. `"julian.h"` is a header-only library built on top of the `"date.h"` library which implements a proleptic Julian calendar which is fully interoperable with everything above.  See http://howardhinnant.github.io/date/julian.html for more details.

6. `"islamic.h"` is a header-only library built on top of the `"date.h"` library which implements a proleptic Islamic calendar which is fully interoperable with everything above.  See http://howardhinnant.github.io/date/islamic.html for more details.

There has been a recent change in the library design.  If you are trying to migrate from the previous design, rename `day_point` to `sys_days` everywhere, and that ought to bring the number of errors down to a small roar.

`"date.h"` and `"tz.h"` are now proposed for standardization here:  http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0355r0.html
