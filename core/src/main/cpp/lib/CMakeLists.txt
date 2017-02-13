message(STATUS "lib")

include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB_RECURSE THISDIR_SRC
    "*.h"
    "*.c"
    "*.cpp"
)

add_library(lib OBJECT ${THISDIR_SRC}
)
