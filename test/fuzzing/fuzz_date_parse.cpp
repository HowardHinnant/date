#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    const auto format = fdp.ConsumeRandomLengthString();
    auto date = consume_year_month_day(fdp);
    std::istringstream in{fdp.ConsumeRandomLengthString()};

    in >> parse(format.c_str(), date);

    return 0;
}