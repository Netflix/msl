message(STATUS "keyx")

include_directories(${OPENSSL_INCLUDE_DIR})

add_library( keyx OBJECT
    AsymmetricWrappedExchange.cpp
    AsymmetricWrappedExchange.h
    DiffieHellmanExchange.cpp
    DiffieHellmanExchange.h
    DiffieHellmanParameters.h
    KeyExchangeFactory.h
    KeyExchangeScheme.cpp
    KeyExchangeScheme.h
    KeyRequestData.cpp
    KeyRequestData.h
    KeyResponseData.cpp
    KeyResponseData.h
    SymmetricWrappedExchange.cpp
    SymmetricWrappedExchange.h
)
