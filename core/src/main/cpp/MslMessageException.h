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

#ifndef SRC_MSLMESSAGEEXCEPTION_H_
#define SRC_MSLMESSAGEEXCEPTION_H_

#include <MslException.h>
#include <stdint.h>
#include <string>
#include <memory>

namespace netflix {
namespace msl {
namespace tokens { class MasterToken; class UserIdToken; }
namespace entityauth { class EntityAuthenticationData; }

class MslError;

/**
 * Thrown when a message exception occurs within the Message Security Layer.
 */
class MslMessageException : public MslException
{
public:
    virtual ~MslMessageException() {}

    /**
     * Construct a new MSL message exception with the specified error.
     *
     * @param error the error.
     */
    MslMessageException(const MslError& error) : MslException(error) {}

    /**
     * Construct a new MSL message exception with the specified error and
     * details.
     *
     * @param error the error.
     * @param details the details text.
     */
    MslMessageException(const MslError& error, const std::string& details) : MslException(error, details) {}

    /**
     * Construct a new MSL message exception with the specified error, details,
     * and cause.
     *
     * @param error the error.
     * @param details the details text.
     * @param cause the cause.
     */
    MslMessageException(const MslError& error, const std::string& details, const IException& cause)
    : MslException(error, details, cause) {}

    virtual MslMessageException& setMessageId(int64_t messageId) {
        MslException::setMessageId(messageId);
        return *this;
    }

    virtual MslMessageException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken) {
        MslException::setMasterToken(masterToken);
        return *this;
    }

    virtual MslMessageException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
        MslException::setEntityAuthenticationData(entityAuthData);
        return *this;
    }

    virtual MslMessageException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) {
        MslException::setUserIdToken(userIdToken);
        return *this;
    }

    virtual MslMessageException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) {
        MslException::setUserAuthenticationData(userAuthData);
        return *this;
    }

    DECLARE_EXCEPTION_CLONE(MslMessageException);

private:
    MslMessageException(); // not implemented
};

}} // namespace netflix::msl

#endif /* SRC_MSLMESSAGEEXCEPTION_H_ */
