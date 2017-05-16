// The MIT License (MIT)
//
// Copyright (c) 2017 Aaron Bishop
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

#ifndef DATE_TEST_TYPE_TRAITS_H
#define DATE_TEST_TYPE_TRAITS_H

#include <type_traits>

namespace test
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

struct TestA {
	constexpr TestA(){}
};
struct TestB {
	constexpr TestB(){}
};

	
int operator+(const TestB&, const TestA&);
int operator-(const TestB&, const TestA&);
int operator/(const TestB&, const TestA&);
bool operator<(const TestB&, const TestA&);


template<class A, class B>
constexpr bool test_can_add(const A& a, const B& b)
{ return decltype(test::can_add_impl::test(a, b, nullptr))::value; }

template<class A, class B>
constexpr bool test_can_subtract(const A& a, const B& b)
{ return decltype(test::can_subtract_impl::test(a, b, nullptr))::value; }

template<class A, class B>
constexpr bool test_can_divide(const A& a, const B& b)
{ return decltype(test::can_divide_impl::test(a, b, nullptr))::value; }

template<class A, class B>
constexpr bool test_can_less_than(const A& a, const B& b)
{ return decltype(test::can_less_than_impl::test(a, b, nullptr))::value; }

static_assert(test_can_add(TestB{}, TestA{}), "test_can_add true failed");
static_assert(!test_can_add(TestB{}, TestB{}), "test_can_add false failed");
static_assert(test_can_subtract(TestB{}, TestA{}), "test_can_subtract true failed");
static_assert(!test_can_subtract(TestB{}, TestB{}), "test_can_subtract false failed");
static_assert(test_can_divide(TestB{}, TestA{}), "test_can_divide true failed");
static_assert(!test_can_divide(TestB{}, TestB{}), "test_can_divide false failed");
static_assert(test_can_less_than(TestB{}, TestA{}), "test_can_less_than true failed");
static_assert(!test_can_less_than(TestB{}, TestB{}), "test_can_less_than false failed");

}
#endif
