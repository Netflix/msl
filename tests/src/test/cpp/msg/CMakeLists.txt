message(STATUS "msgTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(msgTest OBJECT ${THISDIR_SRC})
