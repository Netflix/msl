/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SRC_IO_URL_H_
#define SRC_IO_URL_H_

#include "InputStream.h"
#include "OutputStream.h"

namespace netflix {
namespace msl {
namespace io {

class Connection;

class Url
{
public:
    virtual ~Url() {};
    
    virtual std::shared_ptr<Connection> openConnection() = 0;

    virtual void setTimeout(int64_t timeout) = 0;
};

class Connection
{
public:
    virtual ~Connection() {};
    
    virtual std::shared_ptr<InputStream> getInputStream() = 0;
    virtual std::shared_ptr<OutputStream> getOutputStream() = 0;
};
    
}}} // namespace netflix::msl::io

#endif /* SRC_IO_URL_H_ */
