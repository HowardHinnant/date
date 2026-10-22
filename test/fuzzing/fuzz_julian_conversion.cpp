#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"
#include "date/julian.h"
#include "date/iso_week.h"

using namespace date;
using namespace std::chrono;

enum class ConvType
{
    ToYMD,
    ToJYMD,
    ToISOWeek,
    kMaxValue=ToISOWeek  // NOLINT: FuzzedDataProvider requires this field as is
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    std::ostringstream os;
    switch (fdp.ConsumeEnum<ConvType>())
    {
        case ConvType::ToYMD:
            os << year_month_day{consume_julian_year_month_day(fdp)};
            break;
        case ConvType::ToJYMD:
            os << julian::year_month_day{consume_year_month_day(fdp)};
            break;
        case ConvType::ToISOWeek:
            os << iso_week::year_weeknum_weekday{consume_julian_year_month_day(fdp)};
            break;
        default:
            return -1;
    }
    return 0;
}