message(STATUS "userauthMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(userauthMock OBJECT ${THISDIR_SRC})
