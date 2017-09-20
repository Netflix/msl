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

#ifndef SRC_KEYX_ASYMMETRICWRAPPEDEXCHANGE_H_
#define SRC_KEYX_ASYMMETRICWRAPPEDEXCHANGE_H_

#include <Enum.h>
#include <Macros.h>
#include <crypto/ICryptoContext.h>
#include <crypto/Key.h>
#include <crypto/JsonWebKey.h>
#include <io/MslEncoderFormat.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class RsaEvpKey; }
namespace entityauth { class EntityAuthenticationData; }
namespace io { class MslEncoderFactory; class MslObject; }
namespace tokens { class MasterToken; }
namespace util { class AuthenticationUtils; class MslContext; }
namespace keyx {

/**
 * <p>Asymmetric key wrapped key exchange.</p>
 */
class AsymmetricWrappedExchange : public KeyExchangeFactory
{
public:
    /**
     * <p>Asymmetric key wrapped key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "mechanism", "publickey" ],
     *   "keypairid" : "string",
     *   "mechanism" : "string",
     *   "publickey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code mechanism} the public key cryptographic mechanism of the key pair</li>
     * <li>{@code publickey} the public key used to wrap the session keys</li>
     * </ul></p>
     */
    class RequestData : public KeyRequestData
	{
	public:
        class Mechanism : public Enum<Mechanism>
        {
        public:
            /** RSA-OAEP encrypt/decrypt */
            static const Mechanism RSA;
            /** ECIES */
            static const Mechanism ECC;
            /** JSON Web Encryption with RSA-OAEP */
            static const Mechanism JWE_RSA;
            /** JSON Web Encryption JSON Serialization with RSA-OAEP */
            static const Mechanism JWEJS_RSA;
            /** JSON Web Key with RSA-OAEP */
            static const Mechanism JWK_RSA;
            /** JSON Web Key with RSA-PKCS v1.5 */
            static const Mechanism JWK_RSAES;
            /** INVALID */
            static const Mechanism INVALID;

            Mechanism() : Enum(invalid, "INVALID") {};
            enum Value { rsa, ecc, jwe_rsa, jwejs_rsa, jwk_rsa, jwk_rsaes, invalid };
            inline operator Value() const { return static_cast<Value>(value()); }
            static const std::vector<Mechanism>& getValues();

        private:
            Mechanism(const Value& value, const std::string& strValue)
        		: Enum(value, strValue)
        	{}
        };

        virtual ~RequestData() {}

        /**
         * Create a new asymmetric key wrapped key request data instance with
         * the specified key pair ID and public key. The private key is also
         * required but is not included in the request data.
         *
         * @param keyPairId the public/private key pair ID.
         * @param mechanism the key exchange mechanism.
         * @param publicKey the public key.
         * @param privateKey the private key.
         */
        RequestData(const std::string& keyPairId, const Mechanism& mechanism,
                std::shared_ptr<crypto::PublicKey> publicKey,
                std::shared_ptr<crypto::PrivateKey> privateKey);

        /**
         * Create a new asymmetric key wrapped key request data instance from
         * the provided MSL object. The private key will be unknown.
         *
         * @param keyRequestMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslCryptoException if the encoded key is invalid or the
         *         specified mechanism is not supported.
         * @throws MslKeyExchangeException if the specified mechanism is not
         *         recognized.
         */
        RequestData(std::shared_ptr<io::MslObject> keyRequestMo);

        /**
         * @return the key pair ID.
         */
        std::string getKeyPairId() const { return keyPairId_; }

        /**
         * @return the key mechanism.
         */
        Mechanism getMechanism() const { return mechanism_; }

        /**
         * @return the public key.
         */
        std::shared_ptr<crypto::PublicKey> getPublicKey() const { return publicKey_; }

        /**
         * @return the private key.
         */
        std::shared_ptr<crypto::PrivateKey> getPrivateKey() const { return privateKey_; }

        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        virtual bool equals(std::shared_ptr<const KeyRequestData> obj) const;

    private:
        /** Public/private key pair ID. */
        std::string keyPairId_;
        /** Key mechanism. */
        Mechanism mechanism_;
        /** Public key. */
        std::shared_ptr<crypto::PublicKey> publicKey_;
        /** Private key. */
        std::shared_ptr<crypto::PrivateKey> privateKey_;
    };

    /**
     * <p>Asymmetric key wrapped key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "encryptionkey", "hmackey" ],
     *   "keypairid" : "string",
     *   "encryptionkey" : "binary",
     *   "hmackey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code encryptionkey} the wrapped session encryption key</li>
     * <li>{@code hmackey} the wrapped session HMAC key</li>
     * </ul></p>
     */
    class ResponseData : public KeyResponseData
    {
    public:
    	virtual ~ResponseData() {}

        /**
         * Create a new asymmetric key wrapped key response data instance with
         * the provided master token, specified key pair ID, and public
         * key-encrypted encryption and HMAC keys.
         *
         * @param masterToken the master token.
         * @param keyPairId the public/private key pair ID.
         * @param encryptionKey the public key-encrypted encryption key.
         * @param hmacKey the public key-encrypted HMAC key.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, const std::string& keyPairId,
                std::shared_ptr<ByteArray> encryptionKey, std::shared_ptr<ByteArray> hmacKey);

        /**
         * Create a new asymmetric key wrapped key response data instance with
         * the provided master token from the provided MSL object.
         *
         * @param masterToken the master token.
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if a session key is invalid.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

        /**
         * @return the key pair ID.
         */
        std::string getKeyPairId() const { return keyPairId_; }

        /**
         * @return the public key-encrypted encryption key.
         */
        std::shared_ptr<ByteArray> getEncryptionKey() const { return encryptionKey_; }

        /**
         * @return the public key-encrypted HMAC key.
         */
        std::shared_ptr<ByteArray> getHmacKey() const { return hmacKey_; }

        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

        /* (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        virtual bool equals(std::shared_ptr<const KeyResponseData> obj) const;

    private:
        /** Public/private key pair ID. */
        std::string keyPairId_;
        /** Public key-encrypted encryption key. */
        std::shared_ptr<ByteArray> encryptionKey_;
        /** Public key-encrypted HMAC key. */
        std::shared_ptr<ByteArray> hmacKey_;
    };

    virtual ~AsymmetricWrappedExchange() {}

    /**
     * Create a new asymmetric wrapped key exchange factory.
     *
     * @param authutils authentication utilities.
     */
    AsymmetricWrappedExchange(std::shared_ptr<util::AuthenticationUtils> authutils);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyRequestData> createRequestData(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> keyRequestMo);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyResponseData> createResponseData(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyExchangeFactory::KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx, const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData, std::shared_ptr<tokens::MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyExchangeFactory::KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx, const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData, std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData);

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<KeyRequestData> keyRequestData, std::shared_ptr<KeyResponseData> keyResponseData, std::shared_ptr<tokens::MasterToken> masterToken);

private:
    /**
     * <p>An RSA wrapping crypto context is unique in that it treats its wrap/
     * unwrap operations as encrypt/decrypt respectively. This is compatible
     * with the Web Crypto API.</p>
     */
    class RsaWrappingCryptoContext : public crypto::ICryptoContext
    {
    public:
        virtual ~RsaWrappingCryptoContext() {}

        /** JWK RSA crypto context mode. */
        enum Mode {
            /** RSA-OAEP wrap/unwrap */
            WRAP_UNWRAP_OAEP,
            /** RSA PKCS#1 wrap/unwrap */
            WRAP_UNWRAP_PKCS1,
            /** Null cipher **/
            NULL_OP
        };

        /**
         * <p>Create a new RSA wrapping crypto context for the specified mode
         * using the provided public and private keys. The mode identifies the
         * operations to enable. All other operations are no-ops and return the
         * data unmodified.</p>
         *
         * @param ctx MSL context.
         * @param id key pair identity.
         * @param privateKey the private key. May be null.
         * @param publicKey the public key. May be null.
         * @param mode crypto context mode.
         */
        RsaWrappingCryptoContext(const std::string& id, std::shared_ptr<crypto::PrivateKey> privateKey,
                std::shared_ptr<crypto::PublicKey> publicKey, const Mode& mode);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.ICryptoContext#wrap(byte[], com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
         */
        virtual bool verify(std::shared_ptr<ByteArray> data, std::shared_ptr<ByteArray> signature, std::shared_ptr<io::MslEncoderFactory> encoder);

    private:
        /** Key pair identity. */
        const std::string id;
        std::shared_ptr<crypto::PrivateKey> privateKey;
        std::shared_ptr<crypto::PublicKey> publicKey;
        /** Wrap/unwrap transform. */
        const Mode mode;
        // OpenSSL key structures stored here as an optimization
        std::shared_ptr<crypto::RsaEvpKey> privateKeyEvp;
        std::shared_ptr<crypto::RsaEvpKey> publicKeyEvp;
    };

    /**
     * Create the crypto context identified by the key ID, mechanism, and
     * provided keys.
     *
     * @param ctx MSL context.
     * @param keyPairId the key pair ID.
     * @param mechanism the key mechanism.
     * @param privateKey the private key. May be null.
     * @param publicKey the public key. May be null.
     * @return the crypto context.
     * @throws MslCryptoException if the key mechanism is unsupported.
     */
    std::shared_ptr<crypto::ICryptoContext> createCryptoContext(std::shared_ptr<util::MslContext> ctx, const std::string& keyPairId,
            const RequestData::Mechanism& mechanism, std::shared_ptr<crypto::PrivateKey> privateKey, std::shared_ptr<crypto::PublicKey> publicKey);

private:
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils_;

    /** Encrypt/decrypt key operations. */
    const std::set<crypto::JsonWebKey::KeyOp> ENCRYPT_DECRYPT;
    /** Sign/verify key operations. */
    const std::set<crypto::JsonWebKey::KeyOp> SIGN_VERIFY;

};

bool operator==(const AsymmetricWrappedExchange::RequestData& a, const AsymmetricWrappedExchange::RequestData& b);
inline bool operator!=(const AsymmetricWrappedExchange::RequestData& a, const AsymmetricWrappedExchange::RequestData& b) { return !(a == b); }
bool operator==(const AsymmetricWrappedExchange::ResponseData& a, const AsymmetricWrappedExchange::ResponseData& b);
inline bool operator!=(const AsymmetricWrappedExchange::ResponseData& a, const AsymmetricWrappedExchange::ResponseData& b) { return !(a == b); }

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_ASYMMETRICWRAPPEDEXCHANGE_H_ */
