#include "tz.h"
#include <type_traits>

template<typename TimeZone>
struct test_zone {
    static void test() {
        using namespace std;
        static_assert( is_nothrow_destructible<TimeZone>{}, "");
        static_assert(!is_default_constructible<TimeZone>{}, "");
        static_assert(!is_copy_constructible<TimeZone>{}, "");
        static_assert(!is_copy_assignable<TimeZone>{}, "");
        static_assert( is_nothrow_move_constructible<TimeZone>{}, "");
        static_assert( is_nothrow_move_assignable<TimeZone>{}, "");
    }
};

int
main()
{
    using namespace date;
#if TIMEZONE_RULES
    test_zone<tzrule_zone>::test();
#endif
#if TIMEZONE_FILES
    test_zone<tzfile_zone>::test();
#endif
}
