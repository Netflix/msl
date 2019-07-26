message(STATUS "tokensTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(tokensTest OBJECT ${THISDIR_SRC})
