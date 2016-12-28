message(STATUS "msg")

add_library( msg OBJECT
    ConsoleFilterStreamFactory.cpp
    ConsoleFilterStreamFactory.h
    ErrorHeader.cpp
    ErrorHeader.h
    ErrorMessageRegistry.h
    FilterStreamFactory.h
    Header.cpp
    Header.h
    HeaderKeys.h
    MessageBuilder.cpp
    MessageBuilder.h
    MessageCapabilities.cpp
    MessageCapabilities.h
    MessageContext.cpp
    MessageContext.h
    MessageDebugContext.h
    MessageHeader.cpp
    MessageHeader.h
    MessageInputStream.cpp
    MessageInputStream.h
    MessageOutputStream.cpp
    MessageOutputStream.h
    MessageServiceTokenBuilder.cpp
    MessageServiceTokenBuilder.h
    MessageStreamFactory.cpp
    MessageStreamFactory.h
    MslControl.cpp
    MslControl.h
    NonReplayableMessageContext.h
    PayloadChunk.cpp
    PayloadChunk.h
    PublicMessageContext.h
    SecretMessageContext.h
)
