project(mslMock)
cmake_minimum_required(VERSION 2.8.8)
message(STATUS "=== MockImpl top level ===")

set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl/1.0.2j)
find_package(OpenSSL REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
    ${OPENSSL_INCLUDE_DIR}
    ../../../../core/src/main/cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -std=c++11 \
    -DRAPIDJSON_HAS_STDSTRING=1 \
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

add_subdirectory(entityauth)
add_subdirectory(keyx)
add_subdirectory(msg)
add_subdirectory(tokens)
add_subdirectory(userauth)
add_subdirectory(util)

add_library(${PROJECT_NAME} STATIC
    $<TARGET_OBJECTS:entityauthMock>
    $<TARGET_OBJECTS:keyxMock>
    $<TARGET_OBJECTS:msgMock>
    $<TARGET_OBJECTS:tokensMock>
    $<TARGET_OBJECTS:userauthMock>
    $<TARGET_OBJECTS:utilMock>
)
