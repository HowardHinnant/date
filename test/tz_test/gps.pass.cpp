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
