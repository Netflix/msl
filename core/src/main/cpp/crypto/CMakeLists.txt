message(STATUS "crypto")

include_directories(${OPENSSL_INCLUDE_DIR})

set(OPENSSL_IMPL_DIR opensslImpl)

add_library( crypto OBJECT
    ${OPENSSL_IMPL_DIR}/aesCbc.cpp
    ${OPENSSL_IMPL_DIR}/aesCmac.cpp
    ${OPENSSL_IMPL_DIR}/aesKw.cpp
    ${OPENSSL_IMPL_DIR}/diffieHellman.cpp
    ${OPENSSL_IMPL_DIR}/digest.cpp
    ${OPENSSL_IMPL_DIR}/hmacSha.cpp
    ${OPENSSL_IMPL_DIR}/rsa.cpp
    ${OPENSSL_IMPL_DIR}/util.cpp
    ${OPENSSL_IMPL_DIR}/util.h
    ClientMslCryptoContext.h
    ICryptoContext.h
    IRandom.h
    JcaAlgorithm.h
    JsonWebKey.cpp
    JsonWebKey.h
    Key.cpp
    Key.h
    MslCiphertextEnvelope.cpp
    MslCiphertextEnvelope.h
    MslSignatureEnvelope.cpp
    MslSignatureEnvelope.h
    NullCryptoContext.h
    OpenSslLib.cpp
    OpenSslLib.h
    Random.cpp
    Random.h
    RsaCryptoContext.cpp
    RsaCryptoContext.h
    SessionCryptoContext.cpp
    SessionCryptoContext.h
    SymmetricCryptoContext.cpp
    SymmetricCryptoContext.h
)

