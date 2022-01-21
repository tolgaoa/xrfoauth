cmake_minimum_required(VERSION 3.4)
project(xappoauth)

set(CMAKE_CXX_STANDARDS 14)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
set(SOURCES main.cpp ${PROJECT_SOURCE_DIR}/xrf_jwt.hpp)
add_executable(test ${SOURCES}) 
target_link_libraries(test OpenSSL::SSL)
target_link_libraries(test OpenSSL::Crypto)
