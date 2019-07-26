message(STATUS "io")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRAPIDJSON_HAS_STDSTRING=1")



file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(io OBJECT ${THISDIR_SRC})
