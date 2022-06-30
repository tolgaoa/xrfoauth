#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/api)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/impl)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/model)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/)

add_library (XAPP_CLIENT STATIC 
	xapp_profile.cpp
	xrf_client.cpp
	xapp_main.cpp
	xapp_msg.cpp
	xapp_jwt.cpp
	)
