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

#ifndef SRC_UTIL_MSLCONTEXT_H_
#define SRC_UTIL_MSLCONTEXT_H_

#include <Date.h>
#include <Enum.h>
#include <keyx/KeyExchangeScheme.h>
#include <MslConstants.h>
#include <msg/MessageCapabilities.h>
#include <stdint.h>
#include <memory>
#include <set>

namespace netflix {
namespace msl {
namespace crypto{ class IRandom; class ICryptoContext; }
namespace entityauth { class EntityAuthenticationData; class EntityAuthenticationScheme; class EntityAuthenticationFactory; }
namespace keyx { class KeyExchangeFactory; class KeyExchangeScheme; }
namespace tokens { class TokenFactory; }
namespace userauth { class UserAuthenticationScheme; class UserAuthenticationFactory; }
namespace util {

class MslStore;

/**
 * <p>The context provides access to all factories, builders, and containers
 * that are needed by the MSL library. There is expected to be one global
 * context per trusted services network or peer-to-peer network. By extension,
 * the MSL store instance returned by the context is expected to be specific to
 * the owning context.</p>
 *
 * @see MslStore
 */
class MslContext
{
public:
    class ReauthCode : public Enum<ReauthCode>
    {
    public:
        static const ReauthCode
            /** The master token was rejected as bad or invalid. */
            ENTITY_REAUTH,
            /** The entity authentication data failed to authenticate the entity. */
            ENTITYDATA_REAUTH,
            INVALID;

        /**
         * @return the re-authentication code corresponding to the response
         *         code.
         * @throws IllegalArgumentException if the response code does not map
         *         onto a re-authentication code.
         */
        static ReauthCode valueOf(const MslConstants::ResponseCode& code);

        enum Value { entity_reauth, entitydata_reauth, invalid };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<ReauthCode>& getValues();

    private:
        ReauthCode(const Value& value, const std::string& strValue,
                const MslConstants::ResponseCode& responseCode)
            : Enum(value, strValue), responseCode_(responseCode) {}
        const MslConstants::ResponseCode responseCode_;
    };

    /**
     * Returns the local entity time. This is assumed to be the real time.
     *
     * @return {number} the local entity time in milliseconds since the epoch.
     */
    virtual int64_t getTime() = 0;

    /**
     * <p>Returns a random number generator.</p>
     *
     * <p>It is extremely important to provide a secure (pseudo-)random number
     * generator with a good source of entropy. Many random number generators,
     * including those found in the Java Runtime Environment, JavaScript, and
     * operating systems do not provide sufficient randomness.</p>
     *
     * <p>If in doubt, performing an {@code XOR} on the output of two or more
     * independent random sources can be used to provide better random
     * values.</p>
     *
     * @return a random number generator.
     */
    virtual std::shared_ptr<crypto::IRandom> getRandom() = 0;

    /**
     * <p>Returns the entity authentication scheme identified by the specified
     * name or {@code empty} if there is none.</p>
     *
     * @param name the entity authentication scheme name.
     * @return the scheme identified by the specified name or {@code empty} if
     *         there is none.
     */
    virtual entityauth::EntityAuthenticationScheme
        getEntityAuthenticationScheme(const std::string& name) = 0;

    /**
     * Returns the entity authentication factory for the specified scheme.
     *
     * @param scheme the entity authentication scheme.
     * @return the entity authentication factory, or null if no factory is
     *         available.
     */
    virtual std::shared_ptr<entityauth::EntityAuthenticationFactory>
        getEntityAuthenticationFactory(const entityauth::EntityAuthenticationScheme& scheme) = 0;

    /**
     * <p>Returns the primary crypto context used for MSL-level crypto
     * operations. This is used for the master tokens and user ID tokens.</p>
     *
     * <p>Trusted network clients should return a crypto context that always
     * returns false for verification. The other crypto context methods will
     * not be used by trusted network clients.</p>
     *
     * @return the primary MSL crypto context.
     * @throws MslCryptoException if there is an error creating the crypto
     *         context.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getMslCryptoContext() = 0;

    /**
     * Returns the token factory.
     *
     * This method will not be called by trusted network clients.
     *
     * @return the token factory.
     */
    virtual std::shared_ptr<tokens::TokenFactory> getTokenFactory() = 0;

    /**
     * Returns true if the context is operating in a peer-to-peer network. The
     * message processing logic is slightly different in peer-to-peer networks.
     *
     * @return true if in peer-to-peer mode.
     */
    virtual bool isPeerToPeer() = 0;

    /**
     * Returns the message capabilities for this entity.
     *
     * @return this entity's message capabilities.
     */
    virtual std::shared_ptr<msg::MessageCapabilities> getMessageCapabilities() = 0;

    /**
     * <p>Returns the entity authentication data for this entity. This is used
     * to authenticate messages prior to generation of a master token.</p>
     *
     * <p>This method should never return {@code null} but may do so in the one
     * situation when the {@code reauthCode} parameter is provided and the
     * application knows that the request being sent can no longer succeed
     * because the existing master token, user ID token, or service tokens are
     * no longer valid. This will abort the request.</p>
     *
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITY_REAUTH} then the existing master token has been
     * rejected, along with its bound user ID tokens and service tokens.</p>
     *
     * <p>If the {@code reauthCode} parameter is equal to
     * {@link ReauthCode#ENTITYDATA_REAUTH} then new entity re-authentication
     * data should be returned for this and all subsequent calls.</p>
     *
     * <p>The entity authentication scheme must never change.</p>
     *
     * <p>This method will be called multiple times.</p>
     *
     * @param reauthCode non-{@code null} if the master token or entity
     *        authentication data was rejected. If the entity authentication
     *        data was rejected then new entity authentication data is
     *        required.
     * @return this entity's entity authentication data or null.
     */
    virtual std::shared_ptr<entityauth::EntityAuthenticationData> getEntityAuthenticationData(const ReauthCode& reauthCode = ReauthCode::INVALID) = 0;


    /**
     * <p>Returns the user authentication scheme identified by the specified
     * name or {@code null} if there is none.</p>
     *
     * @param name the user authentication scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    virtual userauth::UserAuthenticationScheme getUserAuthenticationScheme(const std::string& name) = 0;

    /**
     * Returns the user authentication factory for the specified scheme.
     *
     * Trusted network clients should always return null.
     *
     * @param scheme the user authentication scheme.
     * @return the user authentication factory, or null if no factory is
     *         available.
     */
    virtual std::shared_ptr<userauth::UserAuthenticationFactory> getUserAuthenticationFactory(const userauth::UserAuthenticationScheme& scheme) = 0;

    /**
     * <p>Returns the key exchange scheme identified by the specified name or
     * {@code null} if there is none.</p>
     *
     * @param name the key exchange scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    virtual keyx::KeyExchangeScheme getKeyExchangeScheme(const std::string& name) = 0;

    /**
     * Returns the key exchange factory for the specified scheme.
     *
     * @param scheme the key exchange scheme.
     * @return the key exchange factory, or null if no factory is available.
     */
    virtual std::shared_ptr<keyx::KeyExchangeFactory> getKeyExchangeFactory(const keyx::KeyExchangeScheme& scheme) = 0;

    /**
     * Returns the supported key exchange factories in order of preferred use.
     * This should return an immutable collection.
     *
     * @return the key exchange factories, or the empty set.
     */
    virtual std::set<std::shared_ptr<keyx::KeyExchangeFactory>> getKeyExchangeFactories() = 0;

    /**
     * Returns the MSL store specific to this MSL context.
     *
     * @return the MSL store.
     */
    virtual std::shared_ptr<MslStore> getMslStore() = 0;

    /**
     * Returns the MSL encoder factory specific to this MSL context.
     *
     * @return the MSL encoder factory.
     */
    virtual std::shared_ptr<io::MslEncoderFactory> getMslEncoderFactory() = 0;

    /**
     * <p>Update the remote entity time.</p>
     *
     * <p>This function is only used by {@link MslControl} and should not be
     * used by the application.</p>
     *
     * @param time remote entity time.
     */
    void updateRemoteTime(std::shared_ptr<Date> time);

    /**
     * <p>Return the expected remote entity time or {@code null} if the clock
     * is not yet synchronized.</p>
     *
     * <p>This function is only used by {@link MslControl} and should not be
     * used by the application.</p>
     *
     * @return the expected remote entity time or {@code null} if not known.
     */
    std::shared_ptr<Date> getRemoteTime();

    bool equals(std::shared_ptr<const MslContext> other) const;

protected:
    MslContext();
    virtual ~MslContext() {}

private:
    /** Unique is for this instance */
    const uint32_t id_;
    /** Remote clock is synchronized. */
    volatile bool synced_ = false;
    /** Remote entity time offset from local time in seconds. */
    volatile int64_t offset_ = 0;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_MSLCONTEXT_H_ */
