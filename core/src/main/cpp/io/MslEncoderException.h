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

#ifndef SRC_IO_MSLENCODEREXCEPTION_H_
#define SRC_IO_MSLENCODEREXCEPTION_H_

#include <Exception.h>
#include <string>

namespace netflix {
namespace msl {
namespace io {

/**
 * <p>A MSL encoder exception is thrown by the MSL encoding abstraction classes
 * when there is a problem.</p>
 */
class MslEncoderException : public Exception
{
public:
    /**
     * <p>Construct a new MSL encoder exception with the provided message.</p>
     *
     * @param message the detail message.
     */
    MslEncoderException(const std::string& message) : Exception(message) {}

    /**
     * <p>Construct a new MSL encoder exception with the provided cause.</p>
     *
     * @param cause the cause of the exception.
     */
    MslEncoderException(const std::exception& cause) : Exception(cause) {}

    /**
     * <p>Construct a new MSL encoder exception with the provided message and
     * cause.</p>
     *
     * @param message the detail message.
     * @param cause the cause of the exception.
     */
    MslEncoderException(const std::string& message, const IException& cause)
            : Exception(message, cause) {}

    virtual inline ~MslEncoderException() throw() {}

    DECLARE_EXCEPTION_CLONE(MslEncoderException);

private:
    MslEncoderException();  // not implemented

};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_MSLENCODEREXCEPTION_H_ */
