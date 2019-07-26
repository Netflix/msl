message(STATUS "utilTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(utilTest OBJECT ${THISDIR_SRC})
