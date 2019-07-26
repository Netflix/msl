message(STATUS "ioTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(ioTest OBJECT ${THISDIR_SRC})
