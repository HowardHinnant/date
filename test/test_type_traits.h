#ifndef DATE_TEST_TYPE_TRAITS_H
#define DATE_TEST_TYPE_TRAITS_H

#include <type_traits>

namespace date
{
namespace detail
{

struct can_add_impl {
    template<class A, class B>
    static std::true_type test(const A& a, const B& b, decltype(a+b)*){ return {}; }

    template<class A, class B>
    static std::false_type test(const A&, const B&, ...) { return {}; }
};
struct can_subtract_impl {
    template<class A, class B>
    static std::true_type test(const A& a, const B& b, decltype(a-b)*){ return {}; }

    template<class A, class B>
    static std::false_type test(const A&, const B&, ...) { return {}; }
};
struct can_divide_impl {
    template<class A, class B>
    static std::true_type test(const A& a, const B& b, decltype(a/b)*){ return {}; }

    template<class A, class B>
    static std::false_type test(const A&, const B&, ...) { return {}; }
};
struct can_less_than_impl {
    template<class A, class B>
    static std::true_type test(const A& a, const B& b, decltype(a<b)*){ return {}; }

    template<class A, class B>
    static std::false_type test(const A&, const B&, ...) { return {}; }
};

}

template<class A, class B>
auto test_can_add(const A& a, const B& b) -> decltype(detail::can_add_impl::test(a, b, nullptr))
{ return {}; }

template<class A, class B>
auto test_can_subtract(const A& a, const B& b) -> decltype(detail::can_subtract_impl::test(a, b, nullptr))
{ return {}; }

template<class A, class B>
auto test_can_divide(const A& a, const B& b) -> decltype(detail::can_divide_impl::test(a, b, nullptr))
{ return {}; }

template<class A, class B>
auto test_can_less_than(const A& a, const B& b) -> decltype(detail::can_less_than_impl::test(a, b, nullptr))
{ return {}; }

}
#endif
