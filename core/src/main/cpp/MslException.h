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

#ifndef SRC_MSLEXCEPTION_H_
#define SRC_MSLEXCEPTION_H_

#include <Exception.h>
#include <MslError.h>
#include <memory>

namespace netflix {
namespace msl {
namespace entityauth { class EntityAuthenticationData; }
namespace userauth { class UserAuthenticationData; }
namespace tokens { class MasterToken; class UserIdToken; }

/**
 * Thrown when an exception occurs within the Message Security Layer.
 */
class MslException : public Exception
{
public:
    virtual ~MslException() {}

    /**
     * Construct a new MSL exception with the specified error.
     *
     * @param error the error.
     */
    explicit MslException(const MslError& error);

    /**
     * Construct a new MSL exception with the specified error and details.
     *
     * @param error the error.
     * @param details the details text.
     */
    MslException(const MslError& error, const std::string& details);

    /**
     * Construct a new MSL exception with the specified error, details, and
     * cause.
     *
     * @param error the error.
     * @param details the details text.
     * @param cause the cause.
     */
    MslException(const MslError& error, const std::string& details,
            const IException& cause);

    /**
     * Construct a new MSL exception with the specified error and cause.
     *
     * @param error the error.
     * @param cause the cause.
     */
    MslException(const MslError& error, const IException& cause);

    /**
     * @return the error.
     */
    inline MslError getError() const { return error_; }

    /**
     * Returns the message ID of the message associated with the exception. May
     * be 0 if there is no message associated or the exception was thrown
     * before extracting the message ID. Note: message ID's are 53 bits.
     *
     * @return the message ID or 0.
     */
    int64_t getMessageId() const;

    /**
     * Returns the master token of the entity associated with the exception.
     * May be empty if the entity is identified by entity authentication data or
     * not applicable to the exception.
     *
     * @return the master token or empty.
     * @see #getEntityAuthenticationData()
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() const;

    /**
     * Returns the entity authentication data of the entity associated with the
     * exception. May be empty if the entity is identified by a master token or
     * not applicable to the exception.
     *
     * @return the entity authentication data or empty.
     * @see #getMasterToken()
     */
    std::shared_ptr<entityauth::EntityAuthenticationData> getEntityAuthenticationData() const;

    /**
     * Returns the user ID token of the user associated with the exception. May
     * be null if the user is identified by user authentication data or not
     * applicable to the exception.
     *
     * @return the user ID token or empty.
     * @see #getUserAuthenticationData()
     */
    std::shared_ptr<tokens::UserIdToken> getUserIdToken() const;

    /**
     * Returns the user authentication data of the user associated with the
     * exception. May be empty if the user is identified by a user ID token or
     * not applicable to the exception.
     *
     * @return the user authentication data or null.
     * @see #getUserIdToken()
     */
    std::shared_ptr<userauth::UserAuthenticationData> getUserAuthenticationData() const;

    /**
     * Set the message ID of the message associated with the exception. This
     * does nothing if the message ID is already set.
     *
     * @param messageId message ID of the message associated with this error.
     * @return reference to *this, to allow chaining.
     */
    virtual MslException& setMessageId(int64_t messageId);

    /**
     * Set the entity associated with the exception, using a master token. This
     * does nothing if the entity is already set.
     *
     * @param masterToken entity associated with the error. May be empty.
     * @return this.
     */
    virtual MslException& setMasterToken(std::shared_ptr<tokens::MasterToken> masterToken);

    /**
     * Set the entity associated with the exception, using entity
     * authentication data. This does nothing if the entity is already set.
     *
     * @param entityAuthData entity associated with the error. May be empty.
     * @return this.
     */
    virtual MslException& setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData);

    /**
     * Set the user associated with the exception, using a user ID token. This
     * does nothing if the user is already set.
     *
     * @param userIdToken user associated with the error. May be empty.
     * @return this.
     */
    virtual MslException& setUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * Set the user associated with the exception, using user authentication
     * data. This does nothing if the user is already set.
     *
     * @param userAuthData user associated with the error. May be empty.
     * @return this.
     */
    virtual MslException& setUserAuthenticationData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData);

    DECLARE_EXCEPTION_CLONE(MslException);

private:
    MslException();
    /** MSL error. */
    const MslError error_;
    /** Master token. */
    std::shared_ptr<tokens::MasterToken> masterToken_;
    /** Entity authentication data. */
    std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData_;
    /** User ID token. */
    std::shared_ptr<tokens::UserIdToken> userIdToken_;
    /** User authentication data. */
    std::shared_ptr<userauth::UserAuthenticationData> userAuthData_;
    /** Message ID. */
    int64_t messageId_;
};

} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_MSLEXCEPTION_H_ */
