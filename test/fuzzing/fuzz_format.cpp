#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    const auto format_str = fdp.ConsumeRandomLengthString();
    std::ostringstream os;

    try {
        os << format(format_str.c_str(), consume_year_month_day(fdp));
    }
    catch (std::ios_base::failure&)
    {
        return -1;
    }

    return 0;
}
