cmake_minimum_required(VERSION 2.4)

project(xappoauth)

#find_package(cpp-jwt REQUIRED)
#add_subdirectory(third_party/cpp-jwt)

include_directories(${PROJECT_SOURCE_DIR})
set(SOURCES main.cpp ${PROJECT_SOURCE_DIR}/xapp_jwt.cpp)
add_executable(test ${SOURCES}) 
