message(STATUS "tokens")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(tokens OBJECT ${THISDIR_SRC})
