// The MIT License (MIT)
//
// Copyright (c) 2015, 2016 Howard Hinnant
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

#include "tz.h"
#include <iostream>

int
main()
{
    using namespace std::chrono;
    using namespace date;
	int ret = 0;
	const auto&& now = system_clock::now();
	try{
		std::cout << make_zoned(current_zone(), now) << '\n';
		std::cout << make_zoned("America/New_York", now) << '\n';
	}catch(const std::exception& e){
		std::cerr << "error while running make_zoned(current_zone(), now()): " << e.what() << '\n';
		ret = 1;
	}
	return ret;
}

