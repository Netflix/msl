message(STATUS "tokens")

add_library( tokens OBJECT
    ClientTokenFactory.cpp
    ClientTokenFactory.h
    MasterToken.cpp
    MasterToken.h
    MslUser.cpp
    MslUser.h
    ServiceToken.cpp
    ServiceToken.h
    TokenFactory.h
    UserIdToken.cpp
    UserIdToken.h
)

