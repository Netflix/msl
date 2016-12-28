message(STATUS "util")

add_library( util OBJECT
    AuthenticationUtils.h
    Base64.cpp
    Base64.h
    Base64Secure.cpp
    Base64Secure.h
    BlockingQueue.h
    CMakeLists.txt
    ConcurrentHashMap.h
    Debug.h
    Executor.h
    Hex.cpp
    Hex.h
    MslContext.cpp
    MslContext.h
    MslStore.h
    MslUtils.cpp
    MslUtils.h
    Mutex.cpp
    Mutex.h
    NullAuthenticationUtils.h
    NullMslStore.cpp
    NullMslStore.h
    ReadWriteLock.cpp
    ReadWriteLock.h
    ScopedDisposer.h
    SimpleMslStore.cpp
    SimpleMslStore.h
    StaticMslMutex.cpp
    StaticMslMutex.h
    ThreadPool.cpp
    ThreadPool.h
)

