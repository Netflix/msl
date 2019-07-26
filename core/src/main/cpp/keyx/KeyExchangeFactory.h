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

#ifndef SRC_KEYX_KEYEXCHANGEFACTORY_H_
#define SRC_KEYX_KEYEXCHANGEFACTORY_H_

#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <memory>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace entityauth { class EntityAuthenticationData; }
namespace io { class MslEncoderFormat; class MslObject; }
namespace tokens { class MasterToken; }
namespace util { class MslContext; }
namespace keyx {

/**
 * A key exchange factory creates key request and response data instances for
 * a specific key exchange scheme.
 */
class KeyExchangeFactory
{
public:
    virtual ~KeyExchangeFactory() {}

    /**
     * The key exchange data struct contains key response data and a crypto
     * context for the exchanged keys.
     */
    struct KeyExchangeData {
        /**
         * Create a new key key exhange data struct with the provided key
         * response data, master token, and crypto context.
         *
         * @param keyResponseData the key response data.
         * @param cryptoContext the crypto context.
         */
        KeyExchangeData(std::shared_ptr<KeyResponseData> keyResponseData, std::shared_ptr<crypto::ICryptoContext> cryptoContext)
        : keyResponseData(keyResponseData), cryptoContext(cryptoContext) {}

        /** Key response data. */
        std::shared_ptr<KeyResponseData> keyResponseData;
        /** Crypto context for the exchanged keys. */
        std::shared_ptr<crypto::ICryptoContext> cryptoContext;
    };

    /**
     * @return the key exchange scheme this factory is for.
     */
    KeyExchangeScheme getScheme() const { return scheme; }

    /**
     * <p>Generate a new key response data instance and crypto context in
     * response to the provided key request data. The key request data will be
     * from the the remote entity.</p>
     *
     * <p>The provided master token should be renewed by incrementing its
     * sequence number but maintaining its serial number by using the MSL
     * context's token factory.</p>
     *
     * @param ctx MSL context.
     * @param format MSL encoder format.
     * @param keyRequestData the key request data.
     * @param masterToken the master token to renew.
     * @return the key response data and crypto context or {@code null} if the
     *         factory chooses not to perform key exchange.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     * @throws MslException if there is an error renewing the master token.
     */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<tokens::MasterToken> masterToken) = 0;

    /**
     * <p>Generate a new key response data instance and crypto context in
     * response to the provided key request data and entity authentication
     * data. The key request data will be from the the remote entity.</p>
     *
     * @param ctx MSL context.
     * @param format MSL encoder format.
     * @param keyRequestData the key request data.
     * @param entityAuthData the entity authentication data.
     * @return the key response data and crypto context or {@code null} if the
     *         factory chooses not to perform key exchange.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the data.
     * @throws MslEntityAuthException if there is a problem with the entity
     *         identity.
     * @throws MslException if there is an error creating the master token.
     */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData) = 0;

    /**
     * Create a crypto context from the provided key request data and key
     * response data. The key request data will be from the local entity and
     * the key response data from the remote entity.
     *
     * @param ctx MSL context.
     * @param keyRequestData the key request data.
     * @param keyResponseData the key response data.
     * @param masterToken the current master token (not the one inside the key
     *        response data). May be null.
     * @return the crypto context.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<KeyResponseData> keyResponseData,
            std::shared_ptr<tokens::MasterToken> masterToken) = 0;

    /**
     * Construct a new key request data instance from the provided MSL object.
     *
     * @param ctx MSL context.
     * @param keyRequestMo the MSL object.
     * @return the key request data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if there is an error creating the key
     *         request data.
     * @throws MslCryptoException if the keying material cannot be created.
     */
    // FIXME: supposed to be protected?
    virtual std::shared_ptr<KeyRequestData> createRequestData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> keyRequestMo) = 0;

    /**
     * Construct a new key response data instance from the provided MSL object.
     *
     * @param ctx MSL context.
     * @param masterToken the master token for the new key response data.
     * @param keyDataMo the MSL object.
     * @return the key response data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if there is an error creating the key
     *         response data.
     */
    // FIXME: supposed to be protected?
    virtual std::shared_ptr<KeyResponseData> createResponseData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo) = 0;

protected:
    /**
     * Create a new key exchange factory for the specified scheme.
     *
     * @param scheme the key exchange scheme.
     */
    KeyExchangeFactory(const KeyExchangeScheme& scheme) : scheme(scheme) {}

private:
    KeyExchangeFactory(); // not implemented
    /** The factory's key exchange scheme. */
    const KeyExchangeScheme scheme;
};

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_KEYEXCHANGEFACTORY_H_ */
