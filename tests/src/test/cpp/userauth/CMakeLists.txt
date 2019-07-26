message(STATUS "userauthTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(userauthTest OBJECT ${THISDIR_SRC})
