set(XRF_API_SERVER_DIR "${SRC_TOP_DIR}/api-server")

ExternalProject_Add(PISTACHE
    GIT_REPOSITORY https://github.com/oktal/pistache.git
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
)

ExternalProject_Add(NLOHMANN
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}

)
include_directories(${EXTERNAL_INSTALL_LOCATION}/include)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

include_directories(${XRF_API_SERVER_DIR}/api)
include_directories(${XRF_API_SERVER_DIR}/impl)
include_directories(${XRF_API_SERVER_DIR}/model)
include_directories(${XRF_API_SERVER_DIR}/)
include_directories(${SRC_TOP_DIR}/xrf_app)
include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)


file(GLOB XRF_API_SERVER_src_files
    ${XRF_API_SERVER_DIR}/xrf-api-server.cpp
    ${XRF_API_SERVER_DIR}/model/*.cpp
    ${XRF_API_SERVER_DIR}/api/*.cpp
    ${XRF_API_SERVER_DIR}/impl/*.cpp

)

add_library(XRF_API STATIC
           ${NRF_API_SERVER_src_files})
