include_directories(${CMAKE_CURRENT_SOURCE_DIR}/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/impl)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/model)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../clientapp)


file(GLOB XAPP_CLIENT_API_src_files
    xrfc-api-server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/model/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/api/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/impl/*.cpp

)

add_library(XAPP_CLIENT_API STATIC
	    ${XAPP_CLIENT_API_src_files})
