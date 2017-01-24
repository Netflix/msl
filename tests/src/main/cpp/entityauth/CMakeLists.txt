message(STATUS "entityauthMock")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(entityauthMock OBJECT ${THISDIR_SRC})
