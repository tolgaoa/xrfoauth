include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/impl)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/model)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../api-server/)

add_library (XRF STATIC 
	xrf_jwt.cpp
	xrf_msg.cpp
	xrf_main.cpp
	xapp_meta.cpp)
