#include <string>
#include <vector>

#ifndef UTILS
#define UTILS

std::string DumpToHexString(const std::string& dump);
std::string DumpToHexString(const uint8_t* dump, uint32_t dumpsize);
void HexStringToDump(const std::string& hexstr, std::vector<uint8_t>& dump);

#endif
