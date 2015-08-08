// Howard Hinnant
// This work is licensed under a Creative Commons Attribution 4.0 International License.
// http://creativecommons.org/licenses/by/4.0/

// days - day not allowed

#include "date.h"

int
main()
{
    using namespace date;
    auto x = days{3} - 7_d;
}
