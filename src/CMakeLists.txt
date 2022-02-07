cmake_minimum_required(VERSION 3.4)
project(xappoauth)
enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/xrfapp)
include_directories(${PROJECT_SOURCE_DIR}/api-server)

add_subdirectory(xrfapp)
add_subdirectory(api-server)

add_executable(${PROJECT_NAME} main.cpp) 

target_include_directories(${PROJECT_NAME} PUBLIC ./)
#target_link_directories(${PROJECT_NAME} PUBLIC xrfapp/)
target_link_libraries(${PROJECT_NAME} XRF_API XRF)

target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

