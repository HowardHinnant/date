#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    const auto format = fdp.ConsumeRandomLengthString();

    std::ostringstream os;
    to_stream(os, format.c_str(), consume_year_month_day(fdp));

    return 0;
}