cmake_minimum_required(VERSION 2.4)

project(tcpclient)

include_directories(${PROJECT_SOURCE_DIR})
set(SOURCES main.cpp ${PROJECT_SOURCE_DIR}/xapp_jwt.cpp)
add_executable(test ${SOURCES}) 
