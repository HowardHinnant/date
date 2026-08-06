#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"
#include "date/iso_week.h"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    std::ostringstream os;
    auto a = iso_week::year_weeknum_weekday{sys_days{days{fdp.ConsumeIntegral<int64_t>()}}};
    os << a;
    return 0;
}