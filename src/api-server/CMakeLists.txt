set(XRF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")


include_directories(${XRF_API_SERVER_DIR}/api)
include_directories(${XRF_API_SERVER_DIR}/impl)
include_directories(${XRF_API_SERVER_DIR}/model)
include_directories(${XRF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/xrfapp)


file(GLOB XRF_API_SERVER_src_files
    ${XRF_API_SERVER_DIR}/xrf-api-server.cpp
    ${XRF_API_SERVER_DIR}/model/*.cpp
    ${XRF_API_SERVER_DIR}/api/*.cpp
    ${XRF_API_SERVER_DIR}/impl/*.cpp

)

add_library(XRF_API STATIC
           ${NRF_API_SERVER_src_files})
