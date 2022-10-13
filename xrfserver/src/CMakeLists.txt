cmake_minimum_required(VERSION 3.4)
project(xappoauth)
enable_testing()

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

find_library(PISTACHE_LIBRARY pistache)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/xrfapp)
include_directories(${PROJECT_SOURCE_DIR}/api-server)
include_directories(${PROJECT_SOURCE_DIR}/api-server/api)
include_directories(${PROJECT_SOURCE_DIR}/api-server/impl)
include_directories(${PROJECT_SOURCE_DIR}/api-server/model)

add_subdirectory(xrfapp)
add_subdirectory(api-server)

add_executable(${PROJECT_NAME} main.cpp) 

target_include_directories(${PROJECT_NAME} PUBLIC ./)

target_link_directories(${PROJECT_NAME} PUBLIC xrfapp/)
target_link_directories(${PROJECT_NAME} PUBLIC api-server/)

target_link_libraries(${PROJECT_NAME} XRF_API XRF)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} curl)
target_link_libraries(${PROJECT_NAME} ${PISTACHE_LIBRARY})

