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

#include "date.h"

#include <cassert>
#include <iostream>
#include <type_traits>
#include <locale>

int
main()
{
  using namespace date;
  using namespace std::chrono;

  std::locale loc("en-US");

	std::istringstream iss("3/10/18");
	iss.imbue(loc);

	date::local_seconds tLocal;
	iss >> date::parse("%x", tLocal);

  // Seconds since Epoch for the 10th of march
	assert(tLocal.time_since_epoch().count() == 1520640000);

  iss.imbue(std::locale("de-DE"));
  iss >> date::parse("%x", tLocal);

  // Seconds since Epoch for the 3rd of october
  assert(tLocal.time_since_epoch().count() == 1538524800);

}
