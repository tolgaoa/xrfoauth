#ifndef FILE_STRING_HPP_FILE_SEEN
#define FILE_STRING_HPP_FILE_SEEN

#include <string>

namespace util {

std::string string_format(const char* format, ...);

std::string& ltrim(std::string& s);
// trim from end
std::string& rtrim(std::string& s);
// trim from both ends
std::string& trim(std::string& s);
// extract query param from given querystring
std::string get_query_param(std::string querystring, std::string param);
}  // namespace util
#endif
