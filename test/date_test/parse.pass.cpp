// The MIT License (MIT)
//
// Copyright (c) 2016 Howard Hinnant
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

// This test is meant to maintain a record of the sizeof each type.

#include "date.h"
#include <cassert>
#include <sstream>

void
test_a()
{
    using namespace date;
    {
        // correct abbreviation
        std::istringstream in{"Sun 2016-12-11"};
        sys_days tp;
        parse(in, "%a %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct abbreviation
        std::istringstream in{"Sun 2016-12-11"};
        sys_days tp;
        parse(in, "%A %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct full name
        std::istringstream in{"Sunday 2016-12-11"};
        sys_days tp;
        parse(in, "%a %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct full name
        std::istringstream in{"Sunday 2016-12-11"};
        sys_days tp;
        parse(in, "%A %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // not a valid name
        std::istringstream in{"Dec 2016-12-11"};
        sys_days tp;
        parse(in, "%a %F", tp);
        assert( in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 1970_y/1/1);
    }
    {
        // wrong name
        std::istringstream in{"Sat 2016-12-11"};
        sys_days tp;
        parse(in, "%a %F", tp);
        assert( in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 1970_y/1/1);
    }
    {
        // extra ws in input
        std::istringstream in{"Sun  2016-12-11"};
        sys_days tp;
        parse(in, "%a %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // extra ws in format
        std::istringstream in{"Sun 2016-12-11"};
        sys_days tp;
        parse(in, "%a  %F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
}

void
test_b()
{
    using namespace date;
    {
        // correct abbreviation
        std::istringstream in{"Dec 11 2016"};
        sys_days tp;
        parse(in, "%b %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct abbreviation
        std::istringstream in{"Dec 11 2016"};
        sys_days tp;
        parse(in, "%B %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct abbreviation
        std::istringstream in{"Dec 11 2016"};
        sys_days tp;
        parse(in, "%h %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct full name
        std::istringstream in{"December 11 2016"};
        sys_days tp;
        parse(in, "%b %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct full name
        std::istringstream in{"December 11 2016"};
        sys_days tp;
        parse(in, "%B %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // correct full name
        std::istringstream in{"December 11 2016"};
        sys_days tp;
        parse(in, "%h %d %Y", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 2016_y/12/11);
    }
    {
        // incorrect abbreviation
        std::istringstream in{"Dece 11 2016"};
        sys_days tp;
        parse(in, "%b %d %Y", tp);
        assert( in.fail());
        assert(!in.bad());
        assert(!in.eof());
        assert(tp == 1970_y/1/1);
    }
}

void
test_c()
{
    using namespace date;
    using namespace std::chrono;
    {
        // correct abbreviation
        std::istringstream in{"Sun Dec 11 14:02:43 2016"};
        sys_seconds tp;
        parse(in, "%c", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{14} + minutes{2} + seconds{43});
    }
}

void
test_x()
{
    using namespace date;
    using namespace std::chrono;
    {
        // correct abbreviation
        std::istringstream in{"12/11/16"};
        sys_seconds tp;
        parse(in, "%x", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11});
    }
}

void
test_X()
{
    using namespace date;
    using namespace std::chrono;
    {
        // correct abbreviation
        std::istringstream in{"2016-12-11 14:02:43"};
        sys_seconds tp;
        parse(in, "%F %X", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{14} + minutes{2} + seconds{43});
    }
}

void
test_C()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"20 16 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/11);
    }
    {
        std::istringstream in{"-2 1 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == -101_y/12/11);
    }
    {
        std::istringstream in{"-1 0 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == -100_y/12/11);
    }
    {
        std::istringstream in{"-1 99 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == -99_y/12/11);
    }
    {
        std::istringstream in{"-1 1 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == -1_y/12/11);
    }
    {
        std::istringstream in{"0 0 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 0_y/12/11);
    }
    {
        std::istringstream in{"0 1 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 1_y/12/11);
    }
    {
        std::istringstream in{"0 99 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 99_y/12/11);
    }
    {
        std::istringstream in{"1 0 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 100_y/12/11);
    }
    {
        std::istringstream in{"1 1 12 11"};
        sys_days tp;
        parse(in, "%C %y %m %d", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 101_y/12/11);
    }
}

void
test_d()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016 09 12"};
        sys_days tp;
        parse(in, "%Y %d %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/9);
    }
    {
        std::istringstream in{"2016 09 12"};
        sys_days tp;
        parse(in, "%Y %e %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/9);
    }
    {
        std::istringstream in{"2016 9 12"};
        sys_days tp;
        parse(in, "%Y %d %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/9);
    }
    {
        std::istringstream in{"2016 9 12"};
        sys_days tp;
        parse(in, "%Y %e %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/9);
    }
}

void
test_D()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"12/11/16"};
        sys_days tp;
        parse(in, "%D", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/11);
    }
}

void
test_F()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-13"};
        sys_days tp;
        parse(in, "%F", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/12/13);
    }
}

void
test_H()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 15"};
        sys_time<hours> tp;
        parse(in, "%F %H", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{15});
    }
}

void
test_Ip()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 1 pm"};
        sys_time<hours> tp;
        parse(in, "%F %I %p", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{13});
    }
    {
        std::istringstream in{"2016-12-11 1 am"};
        sys_time<hours> tp;
        parse(in, "%F %I %p", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{1});
    }
}

void
test_j()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016 361"};
        sys_days tp;
        parse(in, "%Y %j", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
}

void
test_m()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016 12 09"};
        sys_days tp;
        parse(in, "%Y %d %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/9/12);
    }
    {
        std::istringstream in{"2016 12 9"};
        sys_days tp;
        parse(in, "%Y %d %m", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == 2016_y/9/12);
    }
}

void
test_M()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 15"};
        sys_time<minutes> tp;
        parse(in, "%F %M", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + minutes{15});
    }
}

void
test_S()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 15"};
        sys_seconds tp;
        parse(in, "%F %S", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + seconds{15});
    }
    {
        std::istringstream in{"2016-12-11 15.001"};
        sys_time<milliseconds> tp;
        parse(in, "%F %S", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + seconds{15} + milliseconds{1});
    }
}

void
test_T()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 15:43:22"};
        sys_seconds tp;
        parse(in, "%F %T", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{15} + minutes{43} + seconds{22});
    }
    {
        std::istringstream in{"2016-12-11 15:43:22.001"};
        sys_time<milliseconds> tp;
        parse(in, "%F %T", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{15} + minutes{43} + seconds{22} +
                                              milliseconds{1});
    }
    {
        std::istringstream in{"2016-12-11 15:43:22"};
        sys_time<milliseconds> tp;
        parse(in, "%F %T", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{15} + minutes{43} + seconds{22});
    }
}

void
test_p()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-11 11pm"};
        sys_time<hours> tp;
        parse(in, "%F %I%p", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/11} + hours{23});
    }
}

void
test_r()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-26 1:36:57 pm"};
        sys_seconds tp;
        parse(in, "%F %r", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26} + hours{13} + minutes{36} + seconds{57});
    }
}

void
test_R()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-26 13:36"};
        sys_seconds tp;
        parse(in, "%F %R", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26} + hours{13} + minutes{36});
    }
}

void
test_U()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-52-1"};
        sys_days tp;
        parse(in, "%Y-%U-%w", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
}

void
test_W()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-52-1"};
        sys_days tp;
        parse(in, "%Y-%W-%w", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
}

void
test_GV()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-52-1"};
        sys_days tp;
        parse(in, "%G-%V-%w", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
    {
        std::istringstream in{"2016-52-1"};
        sys_days tp;
        parse(in, "%G-%V-%w", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
    {
        std::istringstream in{"20 16-52-1"};
        sys_days tp;
        parse(in, "%C %g-%V-%w", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
    {
        std::istringstream in{"20 16-52-1"};
        sys_days tp;
        parse(in, "%C %g-%V-%u", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26});
    }
}

void
test_z()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::istringstream in{"2016-12-26 15:53:22 -0500"};
        sys_seconds tp;
        parse(in, "%F %T %z", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26} + hours{20} + minutes{53} + seconds{22});
    }
    {
        std::istringstream in{"2016-12-26 15:53:22 -0500"};
        local_seconds tp;
        parse(in, "%F %T %z", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == local_days{2016_y/12/26} + hours{15} + minutes{53} + seconds{22});
    }
    {
        std::istringstream in{"2016-12-26 15:53:22 -05:00"};
        sys_seconds tp;
        parse(in, "%F %T %Ez", tp);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == sys_days{2016_y/12/26} + hours{20} + minutes{53} + seconds{22});
    }
}

void
test_Z()
{
    using namespace date;
    using namespace std::chrono;
    {
        std::string a;
        std::istringstream in{"2016-12-26 15:53:22 word"};
        local_seconds tp;
        parse(in, "%F %T %Z", tp, a);
        assert(!in.fail());
        assert(!in.bad());
        assert(tp == local_days{2016_y/12/26} + hours{15} + minutes{53} + seconds{22});
        assert(a == "word");
    }
}

int
main()
{
    test_a();
    test_b();
    test_c();
    test_C();
    test_d();
    test_D();
    test_F();
    test_H();
    test_Ip();
    test_j();
    test_m();
    test_M();
    test_p();
    test_r();
    test_R();
    test_S();
    test_T();
    test_U();
    test_W();
    test_GV();
    test_x();
    test_X();
    test_z();
    test_Z();
}
