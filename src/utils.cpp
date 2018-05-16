#include "utils.h"

std::string DumpToHexString(const uint8_t* dump, uint32_t dumpsize)
{
    std::string res;
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < dumpsize; ++i)
    {
        unsigned char c = static_cast<unsigned char>(dump[i]);
        res += hex[c >> 4];
        res += hex[c & 0xf];
    }
    return res;
}

std::string DumpToHexString(const std::string& dump)
{
    return DumpToHexString((const uint8_t*)dump.data(), (uint32_t)dump.size());
}

void HexStringToDump(const std::string& hexstr, std::vector<uint8_t>& dump)
{
    uint8_t c;
    const char* pos = hexstr.c_str();
    for(size_t i = 0; i < hexstr.size() / 2; ++i)
    {
        sscanf(pos, "%2hhx", &c);
        pos += 2;
        dump.push_back(c);
    }
}
