#include "tz.h"
#include <iostream>

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
        auto prev_offset = info.offset;
        auto prev_abbrev = info.abbrev;
        auto prev_save = info.save;
        for (begin = info.end; begin < end; begin = info.end)
        {
            info = z->get_info(begin, tz::utc);
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