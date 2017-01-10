message(STATUS "msg")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(msg OBJECT ${THISDIR_SRC})
