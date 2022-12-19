#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "secure_string.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    char* buf = (char*) malloc(sizeof(char) * 1000);
    const char* format = str.c_str();

    sprintf_s(buf, sizeof(char) * 1000, format);

    free(buf);
    return 0;
}
