#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzutil.hpp"

using namespace date;
using namespace std::chrono;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp{data, size};
    const auto format_str = fdp.ConsumeRandomLengthString();
    std::istringstream in{fdp.ConsumeRandomLengthString()};

    if (fdp.ConsumeBool())
    {
        sys_days tp;
        in >> parse(format_str, tp);
    }
    else
    {
        sys_seconds tp;
        in >> parse(format_str, tp);
    }
    return 0;
}