cmake_minimum_required(VERSION 3.4)
project(xappoauth)
enable_testing()

set(CMAKE_CXX_STANDARDS 14)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/xrfapp)

add_subdirectory(xrfapp)

add_executable(${PROJECT_NAME} main.cpp) 

target_include_directories(${PROJECT_NAME} PUBLIC ./)
#target_link_directories(${PROJECT_NAME} PUBLIC xrfapp/)
target_link_libraries(${PROJECT_NAME} XRF XRF_API)

target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

