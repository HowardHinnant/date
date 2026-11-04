#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};

    const auto dur_val = fdp.ConsumeIntegral<int64_t>();

    switch (fdp.ConsumeEnum<duration_type>())
    {
        case duration_type::NANOSECONDS:
            make_time(nanoseconds{dur_val});
            break;
        case duration_type::MICROSECONDS:
            make_time(microseconds{dur_val});
            break;
        case duration_type::MILLISECONDS:
            make_time(milliseconds {dur_val});
            break;
        case duration_type::SECONDS:
            make_time(seconds {dur_val});
            break;
        case duration_type::MINUTES:
            make_time(minutes {dur_val});
            break;
        case duration_type::HOURS:
            make_time(hours {dur_val});
            break;
        case duration_type::DAYS:
            make_time(days {dur_val});
            break;
        case duration_type::WEEKS:
            make_time(weeks {dur_val});
            break;
        case duration_type::MONTHS:
            make_time(months {dur_val});
            break;
        case duration_type::YEARS:
            make_time(years {dur_val});
            break;
        default:
            return -1;
    }

    return 0;
}