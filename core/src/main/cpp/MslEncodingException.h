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

#ifndef SRC_MSLENCODINGEXCEPTION_H_
#define SRC_MSLENCODINGEXCEPTION_H_

#include <MslException.h>
#include <iosfwd>

namespace netflix
{
namespace msl
{

/**
 * Thrown when an encoding exception occurs within the Message Security Layer.
 */
class MslEncodingException: public MslException
{
public:
    /**
     * Construct a new MSL encoding exception with the specified error.
     *
     * @param error the error.
     */
    MslEncodingException(const MslError& error) : MslException(error) {}

    /**
     * Construct a new MSL encoding exception with the specified error and
     * details.
     *
     * @param error the error.
     * @param details the details text.
     */
    MslEncodingException(const MslError& error, const std::string& details)
        : MslException(error, details) {}

    /**
     * Construct a new MSL encoding exception with the specified error,
     * details, and cause.
     *
     * @param error the error.
     * @param details the details text.
     * @param cause the cause.
     */
    MslEncodingException(const MslError& error, const std::string& details,
            const IException& cause)
        : MslException(error, details, cause) {}

    /**
     * Construct a new MSL encoding exception with the specified error and
     * cause.
     *
     * @param error the error.
     * @param cause the cause.
     */
    MslEncodingException(const MslError& error, const IException& cause)
        : MslException(error, cause) {}

    virtual MslEncodingException& setMessageId(int64_t messageId) {
        MslException::setMessageId(messageId);
        return *this;
    }

    virtual MslEncodingException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken) {
        MslException::setMasterToken(masterToken);
        return *this;
    }

    virtual MslEncodingException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
        MslException::setEntityAuthenticationData(entityAuthData);
        return *this;
    }

    virtual MslEncodingException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) {
        MslException::setUserIdToken(userIdToken);
        return *this;
    }

    virtual MslEncodingException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) {
        MslException::setUserAuthenticationData(userAuthData);
        return *this;
    }

    DECLARE_EXCEPTION_CLONE(MslEncodingException);

private:
    MslEncodingException();  // not implemented
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_MSLENCODINGEXCEPTION_H_ */
