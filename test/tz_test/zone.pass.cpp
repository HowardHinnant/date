#include "tz.h"
#include <type_traits>

int
main()
{
    using namespace std;
    using namespace date;
    static_assert( is_nothrow_destructible<Zone>{}, "");
    static_assert(!is_default_constructible<Zone>{}, "");
    static_assert(!is_copy_constructible<Zone>{}, "");
    static_assert(!is_copy_assignable<Zone>{}, "");
    static_assert( is_nothrow_move_constructible<Zone>{}, "");
    static_assert( is_nothrow_move_assignable<Zone>{}, "");
}
