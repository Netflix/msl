message(STATUS "keyx")

include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(keyx OBJECT ${THISDIR_SRC})
