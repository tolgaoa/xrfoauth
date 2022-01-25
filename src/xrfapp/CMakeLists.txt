#include_directories(${SRC_TOP_DIR}/api-server/api)
#include_directories(${SRC_TOP_DIR}/api-server/impl)
#include_directories(${SRC_TOP_DIR}/api-server/model)
#include_directories(${SRC_TOP_DIR}/api-server/)

#set(OPENSSL_USE_STATIC_LIBS TRUE)
#find_package(OpenSSL REQUIRED)

add_library (XRF xrf_jwt.cpp)
#target_link_libraries(OpenSSL::SSL)
#target_link_libraries(OpenSSL::Crypto)
