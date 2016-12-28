message(STATUS "io")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DRAPIDJSON_HAS_STDSTRING=1")

add_library( io OBJECT
    ByteArrayInputStream.cpp
    ByteArrayInputStream.h
    ByteArrayOutputStream.cpp
    ByteArrayOutputStream.h
    CMakeLists.txt
    InputStream.h
    JsonHandler.cpp
    JsonHandler.h
    JsonMslArray.cpp
    JsonMslArray.h
    JsonMslObject.cpp
    JsonMslObject.h
    JsonMslTokenizer.cpp
    JsonMslTokenizer.h
    JsonVisitor.cpp
    JsonVisitor.h
    MslArray.cpp
    MslArray.h
    MslEncodable.h
    MslEncoderException.h
    MslEncoderFactory.cpp
    MslEncoderFactory.h
    MslEncoderFormat.cpp
    MslEncoderFormat.h
    MslEncoderUtils.cpp
    MslEncoderUtils.h
    MslObject.cpp
    MslObject.h
    MslTokenizer.cpp
    MslTokenizer.h
    MslVariant.cpp
    MslVariant.h
    OutputStream.h
    StringVisitor.cpp
    StringVisitor.h
    Url.h
)

