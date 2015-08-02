// Howard Hinnant
// This work is licensed under a Creative Commons Attribution 4.0 International License.
// http://creativecommons.org/licenses/by/4.0/

// constexpr struct last_spec {} last{};

#include "date.h"

#include <type_traits>

static_assert(std::is_same<decltype(date::last), const date::last_spec>{}, "");

int
main()
{
}
