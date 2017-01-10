message(STATUS "util")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(util OBJECT ${THISDIR_SRC})
