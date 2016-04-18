#include "tz.h"
#include <iostream>

void
test_info(const date::Zone* zone, const date::Info& info)
{
    using namespace date;
    using namespace std::chrono;
    auto begin = info.begin;
    auto end = info.end - microseconds{1};
    auto mid = begin + (end - begin) /2 ;

    if (begin > day_point{jan/1/1700})
    {
        auto local = zone->to_local(begin).first;
        auto prev_local = zone->to_local(begin - seconds{1}).first;
        if (prev_local < local - seconds{1})
        {
            assert(zone->to_sys(local) == begin);
            auto imaginary = prev_local + (local - seconds{1} - prev_local) / 2;
            try
            {
                zone->to_sys(imaginary);
                assert(false);
            }
            catch (const nonexistent_local_time&)
            {
            }
        }
        else if (prev_local > local - seconds{1})
        {
            auto ambiguous = local - seconds{1} +
                             (prev_local - (local - seconds{1})) / 2;
            try
            {
                zone->to_sys(ambiguous);
                assert(false);
            }
            catch (const ambiguous_local_time&)
            {
            }
        }
    }

    auto local = zone->to_local(mid).first;
    assert(zone->to_sys(local) == mid);

    if (end < day_point{jan/1/3000})
    {
        auto local = zone->to_local(end).first;
        auto next_local = zone->to_local(info.end).first;
        if (next_local < local + microseconds{1})
        {
            auto ambiguous = next_local + (local + microseconds{1} - next_local) / 2;
            try
            {
                zone->to_sys(ambiguous);
                assert(false);
            }
            catch (const ambiguous_local_time&)
            {
            }
        }
        else if (next_local > local + microseconds{1})
        {
            assert(zone->to_sys(local) == end);
            auto imaginary = local + microseconds{1} +
                             (next_local - (local + microseconds{1})) / 2;
            try
            {
                zone->to_sys(imaginary);
                assert(false);
            }
            catch (const nonexistent_local_time&)
            {
            }
        }
    }
}

int
main()
{
    using namespace date;
    using namespace std::chrono;
    auto& db = get_tzdb();
    std::vector<std::string> names;
    names.reserve(db.zones.size() + db.links.size());
    for (auto& zone : db.zones)
        names.push_back(zone.name());
    for (auto& link : db.links)
        names.push_back(link.name());
    std::sort(names.begin(), names.end());
    std::cout << db.version << "\n\n";
    for (auto const& name : names)
    {
        std::cout << name << '\n';
        auto z = locate_zone(name);
        auto begin = day_point(jan/1/year::min()) + 0s;
        auto end   = day_point(jan/1/2035) + 0s;
        auto info = z->get_info(begin, tz::utc);
        std::cout << "Initially:           ";
        if (info.offset >= 0s)
            std::cout << '+';
        std::cout << make_time(info.offset);
        if (info.save == 0min)
            std::cout << " standard ";
        else
            std::cout << " daylight ";
        std::cout << info.abbrev << '\n';
        test_info(z, info);
        auto prev_offset = info.offset;
        auto prev_abbrev = info.abbrev;
        auto prev_save = info.save;
        for (begin = info.end; begin < end; begin = info.end)
        {
            info = z->get_info(begin, tz::utc);
            test_info(z, info);
            if (info.offset == prev_offset && info.abbrev == prev_abbrev &&
                    info.save == prev_save)
                continue;
            auto dp = floor<days>(begin);
            auto ymd = year_month_day(dp);
            auto time = make_time(begin - dp);
            std::cout << ymd << 'T' << time << "Z ";
            if (info.offset >= 0s)
                std::cout << '+';
            std::cout << make_time(info.offset);
            if (info.save == 0min)
                std::cout << " standard ";
            else
                std::cout << " daylight ";
            std::cout << info.abbrev << '\n';
            prev_offset = info.offset;
            prev_abbrev = info.abbrev;
            prev_save = info.save;
        }
        std::cout << '\n';
    }
}