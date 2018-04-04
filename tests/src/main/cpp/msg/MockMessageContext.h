/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#ifndef TEST_MSG_MOCKMESSAGECONTEXT_H_
#define TEST_MSG_MOCKMESSAGECONTEXT_H_

#include <msg/MessageContext.h>
#include <crypto/Key.h>
#include <userauth/UserAuthenticationScheme.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace keyx { class KeyRequestData; }
namespace tokens { class MslUser; }
namespace userauth { class UserAuthenticationData; }
namespace util { class MslContext; }
namespace msg {
class MessageDebugContext; class MessageServiceTokenBuilder; class MessageOutputStream;

/**
 * Test message context.
 *
 * The {@link #updateServiceTokens(MessageServiceTokenBuilder)} and
 * {@link #write(MessageOutputStream)} methods do nothing. Unit tests should
 * override those methods for the specific test.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MockMessageContext : public MessageContext
{
public:
	virtual ~MockMessageContext() {}

    /** Service token name for crypto context. */
    const std::string SERVICE_TOKEN_NAME = "serviceToken";
    /** Default service token crypto context name (empty string). */
    const std::string DEFAULT_SERVICE_TOKEN_NAME = "";

    /**
     * Create a new test message context.
     *
     * The message will not be encrypted or non-replayable.
     *
     * @param ctx MSL context.
     * @param userId user ID. May be the empty string.
     * @param scheme user authentication scheme. May be
     *        {@code userauth::UserAuthenticationScheme::INVALID}.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     * @throws CryptoException if there is an error creating a key.
     * @throws MslCryptoException if the service token crypto context keys are
     *         the wrong length.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     */
    MockMessageContext(std::shared_ptr<util::MslContext> ctx, const std::string& userId, const userauth::UserAuthenticationScheme& scheme);

    /** @inheritDoc */
    virtual std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> getCryptoContexts() { return cryptoContexts_; }

    /**
     * Remove a service token crypto context.
     *
     * @param name service token name.
     */
    virtual void removeCryptoContext(const std::string& name);

    /**
     * @param remoteEntityIdentity the message remote entity identity or {@code null} if unknown.
     */
    virtual void setRemoteEntityIdentity(const std::string& remoteEntityIdentity) { remoteEntityIdentity_ = remoteEntityIdentity; }

    /** @inheritDoc */
    virtual std::string getRemoteEntityIdentity() { return remoteEntityIdentity_; }

    /**
     * @param encrypted true if the message must be encrypted.
     */
    virtual void setEncrypted(bool encrypted) { encrypted_ = encrypted; }

    /** @inheritDoc */
    virtual bool isEncrypted() { return encrypted_; }

    /**
     * @param integrityProtected true if the message must be integrity
     *        protected.
     */
    virtual void setIntegrityProtected(bool integrityProtected) { integrityProtected_ = integrityProtected; }

    /** @inheritDoc */
    virtual bool isIntegrityProtected() { return integrityProtected_; }

    /**
     * @param requestingTokens true if the message is requesting tokens.
     */
    virtual void setRequestingTokens(bool requestingTokens) { requestingTokens_ = requestingTokens; }

    /** @inheritDoc */
    virtual bool isRequestingTokens() { return requestingTokens_; }

    /**
     * @param nonReplayable true if the message must be non-replayable.
     */
    virtual void setNonReplayable(bool nonReplayable) { nonReplayable_ = nonReplayable; }

    /** @inheritDoc */
    virtual bool isNonReplayable() { return nonReplayable_; }

    /** @inheritDoc */
    virtual std::string getUserId() { return userId_; }

    /**
     * @param userAuthData the new user authentication data.
     */
    virtual void setUserAuthData(std::shared_ptr<userauth::UserAuthenticationData> userAuthData) { userAuthData_ = userAuthData; }

    /**
     * @inheritDoc
     *
     * Default implementation just returns the existing user authentication
     * data. Override to implement specific behavior.
     */
    virtual std::shared_ptr<userauth::UserAuthenticationData> getUserAuthData(const ReauthCode& reauth, bool renewable, bool required);

    /**
     * @param user the remote user.
     */
    virtual void setUser(std::shared_ptr<tokens::MslUser> user) { user_ = user; }

    /** @inheritDoc */
    virtual std::shared_ptr<tokens::MslUser> getUser() { return user_; }

    /**
     * @param keyRequestData the new key request data.
     */
    virtual void setKeyRequestData(std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData);

    /** @inheritDoc */
    virtual std::set<std::shared_ptr<keyx::KeyRequestData>> getKeyRequestData() { return keyRequestData_; }

    /**
     * @inheritDoc
     *
     * Default implementation does nothing. Override to implement specific
     * behavior.
     */
    virtual void updateServiceTokens(std::shared_ptr<MessageServiceTokenBuilder> builder, bool handshake);

    /**
     * @inheritDoc
     *
     * Default implementation does nothing. Override to implement specific
     * behavior.
     */
    virtual void write(std::shared_ptr<MessageOutputStream> output);

    /**
     * @param debugContext the new message debug context.
     */
    virtual void setMessageDebugContext(std::shared_ptr<MessageDebugContext> debugContext) { debugContext_ = debugContext; }

    /** @inheritDoc */
    virtual std::shared_ptr<MessageDebugContext> getDebugContext() { return debugContext_; }

private:
    /** Message remote entity identity. */
    std::string remoteEntityIdentity_;
    /** Message requires encryption. */
    bool encrypted_;
    /** Message requires integrity protection. */
    bool integrityProtected_;
    /** Message must be non-replayable. */
    bool nonReplayable_;
    /** Message is requesting tokens. */
    bool requestingTokens_;
    /** Message user ID. */
    std::string userId_;
    /** Message user authentication data. */
    std::shared_ptr<userauth::UserAuthenticationData> userAuthData_;
    /** Message remote user. */
    std::shared_ptr<tokens::MslUser> user_;
    /** Key request data. */
    std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData_;
    /** Service token crypto contexts. */
    std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> cryptoContexts_;
    /** Message debug context. */
    std::shared_ptr<MessageDebugContext> debugContext_;
};

}}} // namespace netflix::msl::msg

#endif /* TEST_MSG_MOCKMESSAGECONTEXT_H_ */
