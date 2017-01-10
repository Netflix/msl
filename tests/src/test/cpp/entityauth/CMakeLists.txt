message(STATUS "entityauthTest")

file(GLOB THISDIR_SRC
    "*.h"
    "*.cpp"
)

add_library(entityauthTest OBJECT ${THISDIR_SRC})
