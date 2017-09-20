/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
#ifndef SRC_CRYPTO_JSONWEBENCRYPTIONCRYPTOCONTEXT_H_
#define SRC_CRYPTO_JSONWEBENCRYPTIONCRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>
#include <MslCryptoException.h>
#include <MslError.h>
#include <crypto/Key.h>
#include <memory>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslEncoderFactory; class MslEncoderFormat; }
namespace util { class MslContext; }
namespace crypto {

/**
 * <p>This key exchange crypto context provides an implementation of the JSON
 * web encryption algorithm as defined in
 * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-encryption-08">JSON Web Encryption</a>.
 * It supports a limited subset of the algorithms.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class JsonWebEncryptionCryptoContext : public ICryptoContext
{
private:
	/** Supported content encryption key encryption algorithms. */
	class Algorithm : public Enum<Algorithm>
	{
	public:
		static const Algorithm
			/** RSAES-OAEP */
			RSA_OAEP,
			/** AES-128 Key Wrap */
			A128KW,
			INVALID;

	    enum Value { rsa_oaep, a128kw, invalid };
	    Algorithm() : Enum(invalid, "INVALID") {}
	    operator Value() const { return static_cast<Value>(value()); }
	    static const std::vector<Algorithm>& getValues();

	private:
	    Algorithm(const Value& value, const std::string& strValue)
	        : Enum(value, strValue) {}
	};

public:
    /**
     * The Content Encryption Key crypto context is used to encrypt/decrypt the
     * randomly generated content encryption key.
     */
    class CekCryptoContext : public ICryptoContext
	{
	protected:
        /**
         * Create a new content encryption key crypto context with the
         * specified content encryption key encryption algorithm.
         *
         * @param algo content encryption key encryption algorithm.
         */
        CekCryptoContext(const Algorithm& algo) : algo(algo) {}

	public:
        virtual ~CekCryptoContext() {}

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) {
        	throw MslCryptoException(MslError::WRAP_NOT_SUPPORTED);
        }

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>) {
        	throw MslCryptoException(MslError::UNWRAP_NOT_SUPPORTED);
        }

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) {
        	throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED);
        }

        /** @inheritDoc */
        virtual bool verify(std::shared_ptr<ByteArray>, std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>) {
        	throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED);
        }

        /**
         * @return the content encryption key encryption algorithm.
         */
        Algorithm getAlgorithm() {
            return algo;
        }

	private:
        /** Content encryption key encryption algorithm. */
        const Algorithm algo;
    };

    /**
     * RSA-OAEP encrypt/decrypt of the content encryption key.
     */
    class RsaOaepCryptoContext : public CekCryptoContext
	{
	public:
    	virtual ~RsaOaepCryptoContext() {}

        /**
         * <p>Create a new RSA crypto context for encrypt/decrypt using the
         * provided public and private keys. All other operations are
         * unsupported.</p>
         *
         * <p>If there is no private key decryption is unsupported.</p>
         *
         * <p>If there is no public key encryption is unsupported.</p>
         *
         * @param privateKey the private key. May be null.
         * @param publicKey the public key. May be null.
         */
        RsaOaepCryptoContext(const PrivateKey& privateKey, const PublicKey& publicKey)
			: CekCryptoContext(Algorithm::RSA_OAEP)
			, privateKey(privateKey)
            , publicKey(publicKey)
		{}

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

	protected:
        /** Encryption/decryption cipher. */
        const PrivateKey privateKey;
        /** Sign/verify signature. */
        const PublicKey publicKey;
    };

    /**
     * AES key wrap encrypt/decrypt of the content encryption key.
     */
    class AesKwCryptoContext : public CekCryptoContext
	{
	public:
    	virtual ~AesKwCryptoContext() {}

        /**
         * Create a new AES key wrap crypto context with the provided secret
         * key.
         *
         * @param key AES secret key.
         */
        AesKwCryptoContext(const SecretKey& key);

        /**
         * Create a new AES key wrap crypto context backed by the provided
         * AES crypto context.
         *
         * @param cryptoContext AES crypto context.
         */
        AesKwCryptoContext(std::shared_ptr<ICryptoContext> cryptoContext)
        	: CekCryptoContext(Algorithm::A128KW)
            , key(SecretKey())
        	, cryptoContext(cryptoContext)
        {}

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

	protected:
        /** AES secret key. */
        const SecretKey key;
        /** AES crypto context. */
        const std::shared_ptr<ICryptoContext> cryptoContext;
    };

    /** Supported plaintext encryption algorithms. */
    class Encryption : public Enum<Encryption>
    {
    public:
    	static const Encryption
			/** AES-128 GCM */
			A128GCM,
			/** AES-256 GCM */
			A256GCM,
			INVALID;

	    enum Value { a128gcm, a256gcm, invalid};
	    Encryption() : Enum(invalid, "INVALID") {}
	    operator Value() const { return static_cast<Value>(value()); }
	    static const std::vector<Encryption>& getValues();

	private:
	    Encryption(const Value& value, const std::string& strValue)
	        : Enum(value, strValue) {}
    };

    /** Support serialization formats. */
    enum Format {
        /**
         * <a href="http://tools.ietf.org/html/draft-mones-mose-jwe-json-serialization-04">JSON Web Encryption JSON Serialization (JWE-JS)</a>
         */
        JWE_JS,
        /**
         * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-encryption-08">JSON Web Encryption Compact Serialization</a>
         */
        JWE_CS
    };

    virtual ~JsonWebEncryptionCryptoContext() {}

    /**
     * Create a new JSON web encryption crypto context with the provided
     * content encryption key crypto context and specified plaintext encryption
     * algorithm.
     *
     * @param ctx MSL context.
     * @param cryptoContext content encryption key crypto context.
     * @param enc plaintext encryption algorithm.
     * @param format serialization format.
     */
    JsonWebEncryptionCryptoContext(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<CekCryptoContext> cryptoContext, const Encryption& enc, const Format& format)
    	: ctx(ctx)
    	, cekCryptoContext(cryptoContext)
    	, algo(cryptoContext->getAlgorithm())
    	, enc(enc)
    	, format(format)
    {}

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) {
    	throw MslCryptoException(MslError::ENCRYPT_NOT_SUPPORTED);
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>) {
    	throw MslCryptoException(MslError::DECRYPT_NOT_SUPPORTED);
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) {
    	throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED);
    }

    /** @inheritDoc */
    virtual bool verify(std::shared_ptr<ByteArray>, std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>) {
    	throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED);
    }

private:
    /** MSL context. */
    const std::shared_ptr<util::MslContext> ctx;
    /** Content encryption key crypto context. */
    const std::shared_ptr<ICryptoContext> cekCryptoContext;
    /** Wrap algorithm. */
    const Algorithm algo;
    /** Encryption algorithm. */
    const Encryption enc;
    /** Serialization format. */
    const Format format;
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_JSONWEBENCRYPTIONCRYPTOCONTEXT_H_ */
