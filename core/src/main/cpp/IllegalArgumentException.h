/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_ILLEGALARGUMENTEXCEPTION_H_
#define SRC_ILLEGALARGUMENTEXCEPTION_H_

#include <Exception.h>

namespace netflix
{
namespace msl
{

/**
 * Emulates java's IllegalArgumentException.
 */
class IllegalArgumentException: public Exception
{
public:
    /**
     * Construct a new MSL internal exception with the specified detail message.
     *
     * @param message the detail message.
     */
    inline IllegalArgumentException(const std::string& details) : Exception(details) {}

    /**
     * Construct a new MSL internal exception with the specified detail message
     * and cause.
     *
     * @param message the detail message.
     * @param cause the cause.
     */
    inline IllegalArgumentException(const std::string& details, const IException& cause)
        : Exception(details, cause) {}

    virtual inline ~IllegalArgumentException() throw() {}

    DECLARE_EXCEPTION_CLONE(IllegalArgumentException);

private:
    IllegalArgumentException();  // not implemented
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_ILLEGALARGUMENTEXCEPTION_H_ */
