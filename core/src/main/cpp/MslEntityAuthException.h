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

#ifndef SRC_MSLENTITYAUTHEXCEPTION_H_
#define SRC_MSLENTITYAUTHEXCEPTION_H_

#include <MslException.h>

namespace netflix {
namespace msl {

/**
 * Thrown when an entity authentication exception occurs within the Message
 * Security Layer.
 */
class MslEntityAuthException: public MslException
{
public:
    virtual ~MslEntityAuthException() throw() {}

    /**
     * Construct a new MSL entity authentication exception with the specified
     * error.
     *
     * @param error the error.
     */
    MslEntityAuthException(const MslError& error) : MslException(error) {}

    /**
     * Construct a new MSL entity authentication exception with the specified
     * error and details.
     *
     * @param error the error.
     * @param details the details text.
     */
    MslEntityAuthException(const MslError& error, const std::string& details)
        : MslException(error, details) {}

    /**
     * Construct a new MSL entity authentication exception with the specified
     * error, details, and cause.
     *
     * @param error the error.
     * @param details the details text.
     * @param cause the cause.
     */
    MslEntityAuthException(const MslError& error, const std::string& details, const IException& cause)
        : MslException(error, details, cause) {}

    /**
     * Construct a new MSL entity authentication exception with the specified
     * error and cause.
     *
     * @param error the error.
     * @param cause the cause.
     */
    MslEntityAuthException(const MslError& error, const IException& cause)
        : MslException(error, cause) {}

    virtual MslEntityAuthException& setMessageId(int64_t messageId) {
        MslException::setMessageId(messageId);
        return *this;
    }

    virtual MslEntityAuthException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken) {
        MslException::setMasterToken(masterToken);
        return *this;
    }

    virtual MslEntityAuthException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
        MslException::setEntityAuthenticationData(entityAuthData);
        return *this;
    }

    virtual MslEntityAuthException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) {
        MslException::setUserIdToken(userIdToken);
        return *this;
    }

    virtual MslEntityAuthException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) {
        MslException::setUserAuthenticationData(userAuthData);
        return *this;
    }

    DECLARE_EXCEPTION_CLONE(MslEntityAuthException);

private:
    MslEntityAuthException(); // not implemented
};

}} // namespace netflix::msl

#endif /* SRC_MSLENTITYAUTHEXCEPTION_H_ */
