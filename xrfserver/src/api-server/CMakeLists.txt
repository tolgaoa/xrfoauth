include_directories(${CMAKE_CURRENT_SOURCE_DIR}/api)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/impl)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/model)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../xrfapp)


file(GLOB XRF_API_SERVER_src_files
    xrf-api-server.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/model/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/api/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/impl/*.cpp

)

add_library(XRF_API STATIC
            ${XRF_API_SERVER_src_files})
