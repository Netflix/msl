//
//  MslUrl.h
//  mslcpp
//
//  Created by John Doornbos on 9/16/16.
//  Copyright © 2016 John Doornbos. All rights reserved.
//

#ifndef MslUrl_h
#define MslUrl_h

#include "InputStream.h"
#include "OutputStream.h"

namespace netflix {
namespace msl {
namespace io {

class MslConnection;

class MslUrl
{
public:
    virtual ~MslUrl() {};
    
    virtual std::shared_ptr<MslConnection> openConnection() = 0;

    virtual void setTimeout(int64_t timeout) = 0;
};

class MslConnection
{
public:
    virtual ~MslConnection() {};
    
    virtual std::shared_ptr<InputStream> getInputStream() = 0;
    virtual std::shared_ptr<OutputStream> getOutputStream() = 0;
};
    
}
}
}

#endif /* MslUrl_h */
