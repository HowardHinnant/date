#include "tz.h"
#include <cassert>

#define assert_zoned(t, z, msg) static_assert(std::is_same<t::time_zone, z>::value, msg)

int
main()
{
    using namespace std::chrono;
    using namespace date;
	const auto&& now = system_clock::now();
	const local_seconds local_now{floor<local_seconds::duration>(now.time_since_epoch())};
	
	assert_zoned(decltype(make_zoned(now)), time_zone, "make_zoned(const sys_time&) failed");
	assert_zoned(decltype(make_zoned(current_zone(), local_now)), time_zone, "make_zoned(const time_zone*, const local_time&) failed");
	assert_zoned(decltype(make_zoned(std::string{}, local_now)), time_zone, "make_zoned(const std::string&, const local_time&) failed");
	assert_zoned(decltype(make_zoned("", local_now)), time_zone, "make_zoned(const char*, const local_time&) failed");
	assert_zoned(decltype(make_zoned(current_zone(), local_now, choose::earliest)), time_zone, "make_zoned(const time_zone*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned(std::string{}, local_now, choose::earliest)), time_zone, "make_zoned(const std::string&, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned("", local_now, choose::earliest)), time_zone, "make_zoned(const char*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned(current_zone(), make_zoned(now))), time_zone, "make_zoned(const time_zone*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned(std::string{}, make_zoned(now))), time_zone, "make_zoned(const std::string&, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned("", make_zoned(now))), time_zone, "make_zoned(const char*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned(current_zone(), make_zoned(now), choose::earliest)), time_zone, "make_zoned(const time_zone*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned(std::string{}, make_zoned(now), choose::earliest)), time_zone, "make_zoned(const std::string&, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned("", make_zoned(now), choose::earliest)), time_zone, "make_zoned(const char*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned(current_zone(), now)), time_zone, "make_zoned(const time_zone*, const sys_time&) failed");
	assert_zoned(decltype(make_zoned(std::string{}, now)), time_zone, "make_zoned(const std::string&, const sys_time&) failed");
	assert_zoned(decltype(make_zoned("", now)), time_zone, "make_zoned(const char*, const sys_time&) failed");
	
#if TIMEZONE_FILES
	assert_zoned(decltype(make_zoned<tzfile_zone>(now)), tzfile_zone, "make_zoned<tzfile_zone>(const sys_time&) failed");
	assert_zoned(decltype(make_zoned(tzfile_zone::current_zone(), local_now)), tzfile_zone, "make_zoned(const tzfile_zone*, const local_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>(std::string{}, local_now)), tzfile_zone, "make_zoned<tzfile_zone>(const std::string&, const local_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>("", local_now)), tzfile_zone, "make_zoned<tzfile_zone>(const char*, const local_time&) failed");
	assert_zoned(decltype(make_zoned(tzfile_zone::current_zone(), local_now, choose::earliest)), tzfile_zone, "make_zoned(const tzfile_zone*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>(std::string{}, local_now, choose::earliest)), tzfile_zone, "make_zoned<tzfile_zone>(const std::string&, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>("", local_now, choose::earliest)), tzfile_zone, "make_zoned<tzfile_zone>(const char*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned(tzfile_zone::current_zone(), make_zoned<tzfile_zone>(now))), tzfile_zone, "make_zoned(const tzfile_zone*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>(std::string{}, make_zoned<tzfile_zone>(now))), tzfile_zone, "make_zoned<tzfile_zone>(const std::string&, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>("", make_zoned<tzfile_zone>(now))), tzfile_zone, "make_zoned<tzfile_zone>(const char*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned(tzfile_zone::current_zone(), make_zoned<tzfile_zone>(now), choose::earliest)), tzfile_zone, "make_zoned(const tzfile_zone*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>(std::string{}, make_zoned<tzfile_zone>(now), choose::earliest)), tzfile_zone, "make_zoned<tzfile_zone>(const std::string&, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>("", make_zoned<tzfile_zone>(now), choose::earliest)), tzfile_zone, "make_zoned<tzfile_zone>(const char*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned(tzfile_zone::current_zone(), now)), tzfile_zone, "make_zoned(const tzfile_zone*, const sys_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>(std::string{}, now)), tzfile_zone, "make_zoned<tzfile_zone>(const std::string&, const sys_time&) failed");
	assert_zoned(decltype(make_zoned<tzfile_zone>("", now)), tzfile_zone, "make_zoned<tzfile_zone>(const char*, const sys_time&) failed");
#endif
	
#if TIMEZONE_RULES
	assert_zoned(decltype(make_zoned<tzrule_zone>(now)), tzrule_zone, "make_zoned<tzrule_zone>(const sys_time&) failed");
	assert_zoned(decltype(make_zoned(tzrule_zone::current_zone(), local_now)), tzrule_zone, "make_zoned(const tzrule_zone*, const local_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>(std::string{}, local_now)), tzrule_zone, "make_zoned<tzrule_zone>(const std::string&, const local_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>("", local_now)), tzrule_zone, "make_zoned<tzrule_zone>(const char*, const local_time&) failed");
	assert_zoned(decltype(make_zoned(tzrule_zone::current_zone(), local_now, choose::earliest)), tzrule_zone, "make_zoned(const tzrule_zone*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>(std::string{}, local_now, choose::earliest)), tzrule_zone, "make_zoned<tzrule_zone>(const std::string&, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>("", local_now, choose::earliest)), tzrule_zone, "make_zoned<tzrule_zone>(const char*, const local_time&, choose) failed");
	assert_zoned(decltype(make_zoned(tzrule_zone::current_zone(), make_zoned<tzrule_zone>(now))), tzrule_zone, "make_zoned(const tzrule_zone*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>(std::string{}, make_zoned<tzrule_zone>(now))), tzrule_zone, "make_zoned<tzrule_zone>(const std::string&, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>("", make_zoned<tzrule_zone>(now))), tzrule_zone, "make_zoned<tzrule_zone>(const char*, const basic_zoned_time&) failed");
	assert_zoned(decltype(make_zoned(tzrule_zone::current_zone(), make_zoned<tzrule_zone>(now), choose::earliest)), tzrule_zone, "make_zoned(const tzrule_zone*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>(std::string{}, make_zoned<tzrule_zone>(now), choose::earliest)), tzrule_zone, "make_zoned<tzrule_zone>(const std::string&, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>("", make_zoned<tzrule_zone>(now), choose::earliest)), tzrule_zone, "make_zoned<tzrule_zone>(const char*, const basic_zoned_time&, choose) failed");
	assert_zoned(decltype(make_zoned(tzrule_zone::current_zone(), now)), tzrule_zone, "make_zoned(const tzrule_zone*, const sys_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>(std::string{}, now)), tzrule_zone, "make_zoned<tzrule_zone>(const std::string&, const sys_time&) failed");
	assert_zoned(decltype(make_zoned<tzrule_zone>("", now)), tzrule_zone, "make_zoned<tzrule_zone>(const char*, const sys_time&) failed");
#endif

	return 0;
}

