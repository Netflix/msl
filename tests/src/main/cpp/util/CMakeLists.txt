message(STATUS "utilMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(utilMock OBJECT ${THISDIR_SRC})
