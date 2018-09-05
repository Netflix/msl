message(STATUS "io")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRAPIDJSON_HAS_STDSTRING=1")

# Ignore new warning for conversion from 64 to 32 bits, we should
# not have a MSL payload larger than 2^32 bytes.
set_source_files_properties(BufferedInputStream.cpp PROPERTIES COMPILE_FLAGS "-Wno-shorten-64-to-32")
set_source_files_properties(ByteArrayInputStream.cpp PROPERTIES COMPILE_FLAGS "-Wno-shorten-64-to-32")


file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(io OBJECT ${THISDIR_SRC})
