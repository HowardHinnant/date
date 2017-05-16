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
	try
	{
		auto gps_epoch  = gps_seconds{seconds{0}};  // 1980-01-06 00:00:00 UTC
		auto unix_epoch = sys_seconds{seconds{0}};  // 1970-01-01 00:00:00 UTC
		if(gps_epoch - to_gps_time(unix_epoch) != seconds{315964809})
			throw std::runtime_error{"Invalid epoch difference(gps)"};
		if(to_sys_time(gps_epoch) - unix_epoch != seconds{315964800})
			throw std::runtime_error{"Invalid epoch difference(sys)"};
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << '\n';
		return 1;
	}
	return 0;
}
