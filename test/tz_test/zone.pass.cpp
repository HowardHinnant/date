#include "tz.h"
#include <type_traits>

int
main()
{
    using namespace std;
    using namespace date;
    static_assert( is_nothrow_destructible<time_zone>{}, "");
    static_assert(!is_default_constructible<time_zone>{}, "");
    static_assert(!is_copy_constructible<time_zone>{}, "");
    static_assert(!is_copy_assignable<time_zone>{}, "");
    static_assert( is_nothrow_move_constructible<time_zone>{}, "");

    // The libstdc++ ABI depends on the OS version. On older Linux
    // distributions, the pre-C++11 ABI is used, which means the old
    // std::string definitions are used, not declaring certain functions
    // and operators noexcept. So even when using gcc 6, the move
    // assignment operator for std::string is not noexcept.

#if !defined(__GLIBCXX__) || (_GLIBCXX_USE_CXX11_ABI > 0)
    static_assert( is_nothrow_move_assignable<time_zone>{}, "");
#else
    static_assert( is_move_assignable<time_zone>{}, "");
#endif
}
