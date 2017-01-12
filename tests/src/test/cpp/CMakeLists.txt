project(mslCoreTest)
cmake_minimum_required(VERSION 2.8.8)
message(STATUS "=== Core Test top level ===")

set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl/1.0.2j)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ../../main/cpp
    ../../main/cpp/lib
    ../../../../core/src/main/cpp
    ../../../../core/src/main/cpp/lib
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -DGTEST_DONT_DEFINE_FAIL=1 \
    -DRAPIDJSON_HAS_STDSTRING=1 \
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

# mslCore shared library
add_subdirectory(../../../../core/src/main/cpp mslCoreBin)

# mock implementations
add_subdirectory(../../main/cpp mslMockBin)

# actual tests
add_subdirectory(crypto)
add_subdirectory(entityauth)
add_subdirectory(io)
add_subdirectory(keyx)
add_subdirectory(msg)
add_subdirectory(tokens)
add_subdirectory(userauth)
add_subdirectory(util)

# Source in this directory
file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

# GTest source
set(GTEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../main/cpp/lib)

add_executable(${PROJECT_NAME}
    $<TARGET_OBJECTS:cryptoTest>
    $<TARGET_OBJECTS:entityauthTest>
    $<TARGET_OBJECTS:ioTest>
    $<TARGET_OBJECTS:keyxTest>
    $<TARGET_OBJECTS:msgTest>
    $<TARGET_OBJECTS:tokensTest>
    $<TARGET_OBJECTS:userauthTest>
    $<TARGET_OBJECTS:utilTest>
    ${THISDIR_SRC}
    ${GTEST_ROOT}/gtest/gtest-all.cc
    ${GTEST_ROOT}/gmock/gmock-all.cc
)

target_link_libraries( ${PROJECT_NAME}
    ${OPENSSL_CRYPTO_LIBRARY}
    mslCore
    mslMock
)

# Copy resource files used by tests
file(COPY ../resources DESTINATION src/test/)
