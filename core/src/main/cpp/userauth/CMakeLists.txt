message(STATUS "userauth")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(userauth OBJECT ${THISDIR_SRC})
