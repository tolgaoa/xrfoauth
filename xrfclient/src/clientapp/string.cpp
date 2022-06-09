#include "string.hpp"
#include <iostream>

#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <stdarg.h>
#include <regex>

template<class T>
class Buffer {
 public:
  explicit Buffer(size_t size) {
    msize = size;
    mbuf  = new T[msize];
  }
  ~Buffer() {
    if (mbuf) delete[] mbuf;
  }
  T* get() { return mbuf; }

 private:
  Buffer();
  size_t msize;
  T* mbuf;
};

std::string util::string_format(const char* format, ...) {
  va_list args;

  va_start(args, format);
  size_t size = vsnprintf(NULL, 0, format, args) + 1;  // Extra space for '\0'
  va_end(args);

  Buffer<char> buf(size);

  va_start(args, format);
  vsnprintf(buf.get(), size, format, args);
  va_end(args);

  return std::string(buf.get(), size - 1);  // We don't want the '\0' inside
}

// Licence : https://creativecommons.org/licenses/by-sa/4.0/legalcode
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring#217605

// trim from start
std::string& util::ltrim(std::string& s) {
  s.erase(
      s.begin(),
      std::find_if(
          s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

// trim from end
std::string& util::rtrim(std::string& s) {
  s.erase(
      std::find_if(
          s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace)))
          .base(),
      s.end());
  return s;
}

// trim from both ends
std::string& util::trim(std::string& s) {
  return util::ltrim(util::rtrim(s));
}

// extract query param from given querystring
std::string query_param_tmp;
//
std::string util::get_query_param(std::string querystring, std::string param) {
  std::regex reList("([^=]*)=([^&]*)&?");
  query_param_tmp.clear();
  std::for_each(
      std::sregex_iterator(querystring.begin(), querystring.end(), reList),
      std::sregex_iterator(), [param](std::smatch match) {
        if (match[1] == param) {
          query_param_tmp = match[2].str().c_str();
          return;
        }
      });
  return query_param_tmp;
}
