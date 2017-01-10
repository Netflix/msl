message(STATUS "entityauth")

include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(entityauth OBJECT ${THISDIR_SRC})
