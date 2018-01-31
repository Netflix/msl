message(STATUS "keyxTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(keyxTest OBJECT ${THISDIR_SRC})
