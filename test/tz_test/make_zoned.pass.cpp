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
#if TIMEZONE_FILES
	try{
		std::cout << make_zoned(tzfile_zone::current_zone(), now) << '\n';
		std::cout << make_zoned<tzfile_zone>("America/New_York", now) << '\n';
	}catch(const std::exception& e){
		std::cerr << "error while running make_zoned(tzfile_zone::current_zone(), now()): " << e.what() << '\n';
		ret = 1;
	}
#endif
#if TIMEZONE_RULES
	try{
		std::cout << make_zoned(tzrule_zone::current_zone(), now) << '\n';
		std::cout << make_zoned<tzrule_zone>("America/New_York", now) << '\n';
	}catch(const std::exception& e){
		std::cerr << "error while running make_zoned(tzrule_zone::current_zone(), now()): " << e.what() << '\n';
		ret = 1;
	}
#endif
	return ret;
}
