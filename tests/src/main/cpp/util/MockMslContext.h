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

#ifndef TEST_UTIL_MOCKMSLCONTEXT_H_
#define TEST_UTIL_MOCKMSLCONTEXT_H_

#include <util/MslContext.h>
#include <MslInternalException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/IRandom.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFactory.h>
#include <keyx/KeyExchangeFactory.h>
#include <msg/MessageCapabilities.h>
#include <stdint.h>
#include <tokens/TokenFactory.h>
#include <userauth/UserAuthenticationFactory.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/AuthenticationUtils.h>
#include <util/MslStore.h>
#include <map>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class ICryptoContext; }
namespace util {

/**
 * MSL context for unit tests.
 */
class MockMslContext : public MslContext,
                       public std::enable_shared_from_this<MockMslContext>
{
public:
	virtual ~MockMslContext() {}

    /**
     * Create a new test MSL context.
     *
     * @param scheme entity authentication scheme.
     * @param peerToPeer true if the context should operate in peer-to-peer
     *        mode.
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     */
    MockMslContext(const entityauth::EntityAuthenticationScheme& scheme, bool peerToPeer);

    /** @inheritDoc */
    virtual int64_t getTime();

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::IRandom> getRandom() {
    	return random;
    }

    /** @inheritDoc */
    virtual bool isPeerToPeer() {
    	return peerToPeer;
    }

    /**
     * Set the message capabilities.
     *
     * @param capabilities the new message capabilities.
     */
    void setMessageCapabilities(std::shared_ptr<msg::MessageCapabilities> capabilities) {
        this->capabilities = capabilities;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<msg::MessageCapabilities> getMessageCapabilities() {
    	return capabilities;
    }

    /**
     * Set the entity authentication data.
     *
     * @param entityAuthData the new entity authentication data.
     */
    void setEntityAuthenticationData(std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) {
        this->entityAuthData = entityAuthData;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<entityauth::EntityAuthenticationData> getEntityAuthenticationData(const ReauthCode& reauthCode = ReauthCode::INVALID) {
    	(void)reauthCode;
    	if (!entityAuthData)
    		throw MslInternalException("Entity authentication data is not set.");
    	return entityAuthData;
    }

    /**
     * Set the MSL crypto context.
     *
     * @param cryptoContext the new MSL crypto context.
     */
    void setMslCryptoContext(std::shared_ptr<crypto::ICryptoContext> cryptoContext) {
        mslCryptoContext = cryptoContext;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getMslCryptoContext();

    /** @inheritDoc */
    entityauth::EntityAuthenticationScheme getEntityAuthenticationScheme(const std::string& name);

    /**
     * Adds or replaces the entity authentication factory associated with the
     * entity authentication scheme of the provided factory.
     *
     * @param factory entity authentication factory.
     */
    void addEntityAuthenticationFactory(std::shared_ptr<entityauth::EntityAuthenticationFactory> factory);

    /**
     * Removes the entity authentication factory associated with the specified
     * entity authentication scheme.
     *
     * @param scheme entity authentication scheme.
     */
    void removeEntityAuthenticationFactory(const entityauth::EntityAuthenticationScheme& scheme);

    /** @inheritDoc */
    virtual std::shared_ptr<entityauth::EntityAuthenticationFactory> getEntityAuthenticationFactory(const entityauth::EntityAuthenticationScheme& scheme);

    /** @inheritDoc */
    virtual userauth::UserAuthenticationScheme getUserAuthenticationScheme(const std::string& name);

    /**
     * Adds or replaces the user authentication factory associated with the
     * user authentication scheme of the provided factory.
     *
     * @param factory user authentication factory.
     */
    void addUserAuthenticationFactory(std::shared_ptr<userauth::UserAuthenticationFactory> factory);

    /**
     * Removes the user authentication factory associated with the specified
     * user authentication scheme.
     *
     * @param scheme user authentication scheme.
     */
    void removeUserAuthenticationFactory(const userauth::UserAuthenticationScheme& scheme);

    /** @inheritDoc */
    virtual std::shared_ptr<userauth::UserAuthenticationFactory> getUserAuthenticationFactory(const userauth::UserAuthenticationScheme& scheme);

    /**
     * Sets the token factory.
     *
     * @param factory the token factory.
     */
    void setTokenFactory(std::shared_ptr<tokens::TokenFactory> factory) {
        tokenFactory = factory;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<tokens::TokenFactory> getTokenFactory() {
    	return tokenFactory;
    }

    /** @inheritDoc */
    virtual keyx::KeyExchangeScheme getKeyExchangeScheme(const std::string& name);

    /**
     * Adds a key exchange factory to the end of the preferred set.
     *
     * @param factory key exchange factory.
     */
    void addKeyExchangeFactory(std::shared_ptr<keyx::KeyExchangeFactory> factory);

    /**
     * Removes all key exchange factories associated with the specified key
     * exchange scheme.
     *
     * @param scheme key exchange scheme.
     */
    void removeKeyExchangeFactories(const keyx::KeyExchangeScheme& scheme);

    /** @inheritDoc */
    virtual std::shared_ptr<keyx::KeyExchangeFactory> getKeyExchangeFactory(const keyx::KeyExchangeScheme& scheme);

    /** @inheritDoc */
    virtual std::set<std::shared_ptr<keyx::KeyExchangeFactory>> getKeyExchangeFactories();

    /**
     * Sets the MSL store.
     *
     * @param store the MSL store.
     */
    void setMslStore(std::shared_ptr<MslStore> store) {
        this->store = store;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<MslStore> getMslStore() {
    	return store;
    }

    /**
     * Sets the MSL encoder factory.
     *
     * @param encoderFactory the MSL encoder factory.
     */
    void setMslEncoderFactory(std::shared_ptr<io::MslEncoderFactory> encoderFactory) {
        this->encoderFactory = encoderFactory;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<io::MslEncoderFactory> getMslEncoderFactory() {
    	return encoderFactory;
    }

protected:
    std::shared_ptr<crypto::IRandom> random;
    /** Peer-to-peer mode. */
    const bool peerToPeer;
    /** Message capabilities. */
    std::shared_ptr<msg::MessageCapabilities> capabilities;
    /** Entity authentication data. */
    std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData;
    /** MSL crypto context. */
    std::shared_ptr<crypto::ICryptoContext> mslCryptoContext;
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils;
    /** Map of supported entity authentication schemes onto factories. */
    std::map<entityauth::EntityAuthenticationScheme, std::shared_ptr<entityauth::EntityAuthenticationFactory>> entityAuthFactories;
    /** Map of supported user authentication schemes onto factories. */
    std::map<userauth::UserAuthenticationScheme, std::shared_ptr<userauth::UserAuthenticationFactory>> userAuthFactories;
    /** Token factory. */
    std::shared_ptr<tokens::TokenFactory> tokenFactory;
    /** Supported key exchange factories in preferred order. */
    std::set<std::shared_ptr<keyx::KeyExchangeFactory>> keyxFactories;
    /** MSL store. */
    std::shared_ptr<MslStore> store;
    /** MSL encoder factory. */
    std::shared_ptr<io::MslEncoderFactory> encoderFactory;
};

#if 0
/**
 * Key exchange factory comparator.
 */
private static class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
    /** Scheme priorities. Lower values are higher priority. */
    private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

    /**
     * Create a new key exchange factory comparator.
     */
    public KeyExchangeFactoryComparator() {
        schemePriorities.put(KeyExchangeScheme.JWK_LADDER, 0);
        schemePriorities.put(KeyExchangeScheme.JWE_LADDER, 1);
        schemePriorities.put(KeyExchangeScheme.DIFFIE_HELLMAN, 2);
        schemePriorities.put(KeyExchangeScheme.SYMMETRIC_WRAPPED, 3);
        schemePriorities.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, 4);
    }

    /* (non-Javadoc)
     * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
     */
    @Override
    public int compare(final KeyExchangeFactory a, final KeyExchangeFactory b) {
        final KeyExchangeScheme schemeA = a.getScheme();
        final KeyExchangeScheme schemeB = b.getScheme();
        final Integer priorityA = schemePriorities.get(schemeA);
        final Integer priorityB = schemePriorities.get(schemeB);
        return priorityA.compareTo(priorityB);
    }
}


#endif

}}} // namespace netflix::msl::util

#endif /* TEST_UTIL_MOCKMSLCONTEXT_H_ */
