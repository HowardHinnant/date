#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    const auto format = fdp.ConsumeRandomLengthString();

    std::istringstream is{fdp.ConsumeRandomLengthString()};
    year_month_day ymd;
    from_stream(is, format.c_str(), ymd);

    return 0;
}