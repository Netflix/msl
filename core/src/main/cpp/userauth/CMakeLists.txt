message(STATUS "userauth")

add_library( userauth OBJECT
    EmailPasswordAuthenticationData.cpp
    EmailPasswordAuthenticationData.h
    EmailPasswordAuthenticationFactory.cpp
    EmailPasswordAuthenticationFactory.h
    EmailPasswordStore.h
    UserAuthenticationData.cpp
    UserAuthenticationData.h
    UserAuthenticationFactory.h
    UserAuthenticationScheme.cpp
    UserAuthenticationScheme.h
    UserIdTokenAuthenticationData.cpp
    UserIdTokenAuthenticationData.h
    UserIdTokenAuthenticationFactory.cpp
    UserIdTokenAuthenticationFactory.h
)

