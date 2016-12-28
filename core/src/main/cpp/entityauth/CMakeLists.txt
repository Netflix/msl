message(STATUS "entityauth")

include_directories(${OPENSSL_INCLUDE_DIR})

add_library( entityauth OBJECT
    EntityAuthenticationData.cpp
    EntityAuthenticationData.h
    EntityAuthenticationFactory.h
    EntityAuthenticationScheme.cpp
    EntityAuthenticationScheme.h
    PresharedAuthenticationData.cpp
    PresharedAuthenticationData.h
    PresharedAuthenticationFactory.cpp
    PresharedAuthenticationFactory.h
    PresharedKeyStore.h
    PresharedProfileAuthenticationData.cpp
    PresharedProfileAuthenticationData.h
    RsaAuthenticationData.cpp
    RsaAuthenticationData.h
    RsaAuthenticationFactory.cpp
    RsaAuthenticationFactory.h
    RsaStore.h
    UnauthenticatedAuthenticationData.cpp
    UnauthenticatedAuthenticationData.h
    UnauthenticatedAuthenticationFactory.cpp
    UnauthenticatedAuthenticationFactory.h
)

