message(STATUS "cryptoTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(cryptoTest OBJECT ${THISDIR_SRC})
