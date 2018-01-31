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

#ifndef SRC_MSLERRORRESPONSEEXCEPTION_H_
#define SRC_MSLERRORRESPONSEEXCEPTION_H_

#include <Exception.h>
#include <string>

namespace netflix
{
namespace msl
{

/**
 * <p>Thrown when an exception occurs while attempting to create and send an
 * automatically generated error response.</p>
 */
class MslErrorResponseException: public Exception
{
public:
    /**
     * <p>Construct a new MSL error response exception with the specified detail
     * message, cause, and the original exception thrown by the request that
     * prompted an automatic error response.</p>
     *
     * <p>The detail message should describe the error that triggered the
     * automatically generated error response.</p>
     *
     * @param message the detail message.
     * @param cause the cause.
     * @param requestCause the original request exception.
     */
    inline MslErrorResponseException(const std::string& message,
            const IException& cause, const IException& requestCause)
        : Exception(message, cause)
    {
        std::shared_ptr<IException> temp = requestCause.clone();
        requestCause_.swap(temp);
    }

    /**
     * <p>Construct a new MSL error response exception with the specified detail
     * message, cause, and the original exception thrown by the request that
     * prompted an automatic error response.</p>
     *
     * <p>The detail message should describe the error that triggered the
     * automatically generated error response.</p>
     *
     * @param message the detail message.
     * @param cause the cause.
     * @param requestCause the original request exception.
     */
    inline MslErrorResponseException(const std::string& message,
            const IException& cause)
        : Exception(message, cause)
    {
    }

    virtual inline ~MslErrorResponseException() throw() {}

    /**
     * @return the exception thrown by the request that prompted the error
     *         response.
     */
    inline std::shared_ptr<IException> getRequestCause() {return requestCause_;}

    DECLARE_EXCEPTION_CLONE(MslErrorResponseException);

private:
    MslErrorResponseException();  // not implemented
    /** The original exception thrown by the request. */
    std::shared_ptr<IException> requestCause_;
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_MSLERRORRESPONSEEXCEPTION_H_ */
