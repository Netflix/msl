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

#ifndef SRC_MSLUSERIDTOKENEXCEPTION_H_
#define SRC_MSLUSERIDTOKENEXCEPTION_H_

#include <MslException.h>
#include <stdint.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace tokens { class MasterToken; class UserIdToken; }
namespace entityauth { class EntityAuthenticationData; }

class MslError;

/**
 * Thrown when there is a problem with a user ID token, but the token was
 * successfully parsed.
 */
class MslUserIdTokenException : public MslException
{
public:
    virtual ~MslUserIdTokenException() {}

    /**
     * Construct a new MSL user ID token exception with the specified error and
     * user ID token.
     *
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     */
    MslUserIdTokenException(const MslError& error, std::shared_ptr<tokens::UserIdToken> userIdToken) : MslException(error)
    {
        MslException::setUserIdToken(userIdToken);
    }

    /**
     * Construct a new MSL user ID token exception with the specified error,
     * user ID token, and details.
     *
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     * @param details the details text.
     */
    MslUserIdTokenException(const MslError& error, std::shared_ptr<tokens::UserIdToken> userIdToken,
            const std::string& details) : MslException(error, details)
    {
        MslException::setUserIdToken(userIdToken);
    }

    /**
     * Construct a new MSL user ID token exception with the specified error,
     * user ID token, details, and cause.
     *
     * @param error the error.
     * @param userIdToken the user ID token. May not be null.
     * @param details the details text.
     * @param cause the cause.
     */
    MslUserIdTokenException(const MslError& error, std::shared_ptr<tokens::UserIdToken> userIdToken,
            const std::string& details, const IException& cause) : MslException(error, details, cause)
    {
        MslException::setUserIdToken(userIdToken);
    }

    virtual MslUserIdTokenException& setMessageId(int64_t messageId) {
        MslException::setMessageId(messageId);
        return *this;
    }

    virtual MslUserIdTokenException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken) {
        MslException::setMasterToken(masterToken);
        return *this;
    }

    virtual MslUserIdTokenException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
        MslException::setEntityAuthenticationData(entityAuthData);
        return *this;
    }

    virtual MslUserIdTokenException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) {
        MslException::setUserIdToken(userIdToken);
        return *this;
    }

    virtual MslUserIdTokenException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) {
        MslException::setUserAuthenticationData(userAuthData);
        return *this;
    }

    DECLARE_EXCEPTION_CLONE(MslUserIdTokenException);

private:
    MslUserIdTokenException(); // not implemented
};

}} // namespace netflix::msl

#endif /* SRC_MSLUSERIDTOKENEXCEPTION_H_ */
