project(mslCore)
cmake_minimum_required(VERSION 2.8.8)
message(STATUS "Core top level")

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -std=c++11 \
    -ftrapv \
    -fwrapv \
    -pedantic \
    -pedantic-errors \
    -Wall \
    -Wextra \
    -Werror \
    -Wconversion \
    -Wno-sign-conversion \
    -fmessage-length=0 \
    -Wpointer-arith \
    -Wformat \
    -Werror=format-security \
    -Werror=array-bounds \
    -fstack-protector \
    "   
)
# TODO
# -fno-omit-frame-pointer \
# -fsanitize=address \
# TODO
# - remove -Wno-sign-conversion

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -g3")

set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl/1.0.2j)
find_package(OpenSSL REQUIRED)

find_package(ZLIB REQUIRED)

add_subdirectory(crypto)
add_subdirectory(entityauth)
add_subdirectory(io)
add_subdirectory(keyx)
add_subdirectory(msg)
add_subdirectory(tokens)
add_subdirectory(userauth)
add_subdirectory(util)

#set (CMAKE_SHARED_LINKER_FLAGS "-stdlib=libc++")

add_library(${PROJECT_NAME} SHARED
    $<TARGET_OBJECTS:crypto>
    $<TARGET_OBJECTS:entityauth>
    $<TARGET_OBJECTS:io>
    $<TARGET_OBJECTS:keyx>
    $<TARGET_OBJECTS:msg>
    $<TARGET_OBJECTS:tokens>
    $<TARGET_OBJECTS:userauth>
    $<TARGET_OBJECTS:util>
    Date.cpp
    Date.h
    Enum.h
    Exception.cpp
    Exception.h
    IOException.h
    IllegalArgumentException.h
    IllegalStateException.h
    Macros.h
    MslConstants.cpp
    MslConstants.h
    MslCryptoException.h
    MslEncodingException.h
    MslEntityAuthException.h
    MslError.cpp
    MslError.h
    MslErrorResponseException.h
    MslException.cpp
    MslException.h
    MslInternalException.h
    MslKeyExchangeException.h
    MslMasterTokenException.h
    MslMessageException.h
    MslUserAuthException.h
    MslUserIdTokenException.h
    RangeException.h
    StaticAssert.h
    TimeoutException.h
)

target_link_libraries( ${PROJECT_NAME}
    ${OPENSSL_CRYPTO_LIBRARY}
    ${ZLIB_LIBRARIES}
)
