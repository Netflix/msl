message(STATUS "crypto")

include_directories(${OPENSSL_INCLUDE_DIR})

set(OPENSSL_IMPL_DIR opensslImpl)

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(crypto OBJECT
    ${OPENSSL_IMPL_DIR}/aesCbc.cpp
    ${OPENSSL_IMPL_DIR}/aesCmac.cpp
    ${OPENSSL_IMPL_DIR}/aesKw.cpp
    ${OPENSSL_IMPL_DIR}/diffieHellman.cpp
    ${OPENSSL_IMPL_DIR}/digest.cpp
    ${OPENSSL_IMPL_DIR}/hmacSha.cpp
    ${OPENSSL_IMPL_DIR}/rsa.cpp
    ${OPENSSL_IMPL_DIR}/util.cpp
    ${OPENSSL_IMPL_DIR}/util.h
    ${THISDIR_SRC}
)

