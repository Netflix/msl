message(STATUS "tokensMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(tokensMock OBJECT ${THISDIR_SRC})
