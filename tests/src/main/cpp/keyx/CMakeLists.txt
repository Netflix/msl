message(STATUS "keyxMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(keyxMock OBJECT ${THISDIR_SRC})
