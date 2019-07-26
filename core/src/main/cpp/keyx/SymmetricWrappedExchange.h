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

#ifndef SRC_KEYX_SYMMETRICWRAPPEDEXCHANGE_H_
#define SRC_KEYX_SYMMETRICWRAPPEDEXCHANGE_H_

#include <Enum.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <Macros.h>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace tokens { class MasterToken; }
namespace util { class MslContext; class AuthenticationUtils; }
namespace keyx {

/**
 * <p>Symmetric key wrapped key exchange.</p>
 */
class SymmetricWrappedExchange: public KeyExchangeFactory
{
public:
    virtual ~SymmetricWrappedExchange() {}

    class KeyId : public Enum<KeyId>
    {
    public:
        static const KeyId PSK, SESSION, INVALID;
        KeyId() : Enum(invalid, "INVALID") {}
        enum Value { psk, session, invalid };
        inline operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<KeyId>& getValues();
    private:
        KeyId(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    /**
     * <p>Symmetric key wrapped key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid" ],
     *   "keyid" : "string",
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that should be used to wrap the session keys</li>
     * </ul></p>
     */
    class RequestData : public KeyRequestData
    {
    public:
        virtual ~RequestData() {}

        /**
         * Create a new symmetric key wrapped key request data instance with
         * the specified key ID.
         *
         * @param keyId symmetric key identifier.
         */
        RequestData(const KeyId& keyId);

        /**
         * Create a new symmetric key wrapped key request data instance from
         * the provided MSL object.
         *
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the key ID is not recognized.
         */
        RequestData(std::shared_ptr<io::MslObject> keyDataMo);

        /**
         * @return the wrapping key ID.
         */
        KeyId getKeyId() const { return keyId; }

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        virtual bool equals(std::shared_ptr<const KeyRequestData> other) const;

    //protected:
        // FIXME: java code has this protected
        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    private:
        RequestData(); // not implemented
        /** Symmetric key ID. */
        KeyId keyId;
    };

    /**
     * <p>Symmetric key wrapped key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid", "encryptionkey", "hmackey" ],
     *   "keyid" : "string",
     *   "encryptionkey" : "binary",
     *   "hmackey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that was used to wrap the session keys</li>
     * <li>{@code encryptionkey} the wrapped session encryption key</li>
     * <li>{@code hmackey} the wrapped session HMAC key</li>
     * </ul></p>
     */
    class ResponseData : public KeyResponseData
    {
    public:
        virtual ~ResponseData() {}

        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token, specified key ID and wrapped encryption
         * and HMAC keys.
         *
         * @param masterToken the master token.
         * @param keyId the wrapping key ID.
         * @param encryptionKey the wrapped encryption key.
         * @param hmacKey the wrapped HMAC key.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, const KeyId& keyId,
        		std::shared_ptr<ByteArray> encryptionKey, std::shared_ptr<ByteArray> hmacKey);

        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token from the provided MSL object.
         *
         * @param masterToken the master token.
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the key ID is not recognized or
         *         a session key is invalid.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

        /**
         * @return the wrapping key ID.
         */
        KeyId getKeyId() const { return keyId; }

        /**
         * @return the wrapped encryption key.
         */
        std::shared_ptr<ByteArray> getEncryptionKey() const { return encryptionKey; }

        /**
         * @return the wrapped HMAC key.
         */
        std::shared_ptr<ByteArray> getHmacKey() const { return hmacKey; }

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        virtual bool equals(std::shared_ptr<const KeyResponseData> other) const;

    //protected:
        // FIXME: java code has getKeydata protected
        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    private:
        ResponseData(); // not implemented
        /** Symmetric key ID. */
        KeyId keyId;
        /** Wrapped encryption key. */
        std::shared_ptr<ByteArray> encryptionKey;
        /** Wrapped HMAC key. */
        std::shared_ptr<ByteArray> hmacKey;
    };

    /**
     * Create a new symmetric wrapped key exchange factory.
     *
     * @param authutils authentication utiliites.
     */
    SymmetricWrappedExchange(std::shared_ptr<util::AuthenticationUtils> authutils);

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.tokens.MasterToken)
     */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<tokens::MasterToken> masterToken);

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#generateResponse(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslEncoderFormat, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData);

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.keyx.KeyRequestData, com.netflix.msl.keyx.KeyResponseData, com.netflix.msl.tokens.MasterToken)
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<KeyResponseData> keyResponseData,
            std::shared_ptr<tokens::MasterToken> masterToken);
protected:

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createRequestData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    virtual std::shared_ptr<KeyRequestData> createRequestData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> keyRequestMo);

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    virtual std::shared_ptr<KeyResponseData> createResponseData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

private:
    /**
     * Create the crypto context identified by the key ID.
     *
     * @param ctx MSL context.
     * @param keyId the key ID.
     * @param masterToken the existing master token. May be null.
     * @param identity the entity identity.
     * @return the crypto context.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslKeyExchangeException if the key ID is unsupported.
     * @throws MslEntityAuthException if there is an problem with the entity
     *         identity.
     */
    static std::shared_ptr<crypto::ICryptoContext> createCryptoContext(std::shared_ptr<util::MslContext> ctx,
            const KeyId& keyId, std::shared_ptr<tokens::MasterToken> masterToken, const std::string& identity);

private:
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils;

    DISALLOW_IMPLICIT_CONSTRUCTORS(SymmetricWrappedExchange);
};

bool operator==(const SymmetricWrappedExchange::RequestData& a, const SymmetricWrappedExchange::RequestData& b);
inline bool operator!=(const SymmetricWrappedExchange::RequestData& a, const SymmetricWrappedExchange::RequestData& b) { return !(a == b); }

bool operator==(const SymmetricWrappedExchange::ResponseData& a, const SymmetricWrappedExchange::ResponseData& b);
inline bool operator!=(const SymmetricWrappedExchange::ResponseData& a, const SymmetricWrappedExchange::ResponseData& b) { return !(a == b); }

bool operator==(const SymmetricWrappedExchange::KeyId& a, const SymmetricWrappedExchange::KeyId& b);
inline bool operator!=(const SymmetricWrappedExchange::KeyId& a, const SymmetricWrappedExchange::KeyId& b) { return !(a == b); }

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_SYMMETRICWRAPPEDEXCHANGE_H_ */
