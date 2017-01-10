message(STATUS "msgMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(msgMock OBJECT ${THISDIR_SRC})
