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

#ifndef SRC_CRYPTO_JSONWEBKEY_H_
#define SRC_CRYPTO_JSONWEBKEY_H_

#include <crypto/Key.h>
#include <Enum.h>
#include <io/MslEncodable.h>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; }
namespace crypto {

/**
 * This class implements the JSON web key structure as defined in
 * <a href="http://tools.ietf.org/html/draft-ietf-mose-json-web-key-08">JSON Web Key</a>.
 */
class JsonWebKey : public io::MslEncodable
{
public:

    /** Supported key types. */
    class Type : public Enum<Type>
    {
    public:
        static const Type
        /** RSA */
        rsa,
        /** Octet Sequence */
        oct,
        /** Invalid */
        invalid;
        Type() : Enum(invalid_, "INVALID") {}
        enum Value { rsa_, oct_, invalid_ };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<Type>& getValues();
    private:
        Type(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    /** Supported key usages. */
    class Usage : public Enum<Usage>
    {
    public:
        static const Usage
        /** Sign/verify. */
        sig,
        /** Encrypt/decrypt. */
        enc,
        /** Wrap/unwrap. */
        wrap,
        /** Invalid */
        invalid;
        Usage() : Enum(invalid_, "INVALID") {}
        enum Value { sig_, enc_, wrap_, invalid_ };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<Usage>& getValues();
    private:
        Usage(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    /** Supported key operations. */
    class KeyOp : public Enum<KeyOp>
    {
    public:
        static const KeyOp
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits,
        invalid;
        KeyOp() : Enum(invalid_, "INVALID") {}
        enum Value { sign_, verify_, encrypt_, decrypt_, wrapKey_, unwrapKey_, deriveKey_, deriveBits_, invalid_ };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<KeyOp>& getValues();
    private:
        KeyOp(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    /** Supported key algorithms. */
    class Algorithm : public Enum<Algorithm>
    {
    public:
        static const Algorithm
        /** HMAC-SHA256 */
        HS256,
        /** RSA PKCS#1 v1.5 */
        RSA1_5,
        /** RSA OAEP */
        RSA_OAEP,
        /** AES-128 Key Wrap */
        A128KW,
        /** AES-128 CBC */
        A128CBC,
        /** INVALID */
        INVALID;
        Algorithm() : Enum(invalid_, "INVALID") {}
        enum Value { hs256_, rsa1_5_, rsa_oaep_, a128kw_, a128cbc_, invalid_ };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<Algorithm>& getValues();
        /**
         * @return the Java Cryptography Architecture standard algorithm name
         *         for this JSON Web Algorithm.
         */
        std::string getJcaAlgorithmName() const;
    private:
        Algorithm(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    /**
     * Create a new JSON web key for an RSA public/private key pair with the
     * specified attributes. At least one of the public key or private key must
     * be encoded.
     *
     * @param usage key usage. May be invalid.
     * @param algo key algorithm. May be invalid.
     * @param extractable true if the key is extractable.
     * @param id key ID. May be empty.
     * @param publicKey RSA public key. May be null.
     * @param privateKey RSA private key. May be null.
     * @throws MslInternalException if both keys are null or the algorithm
     *         is incompatible.
     */
    JsonWebKey(const Usage& usage, const Algorithm& algo, const bool extractable,
            const std::string& id, std::shared_ptr<PublicKey> publicKey,
            std::shared_ptr<PrivateKey> privateKey);

    /**
      * Create a new JSON web key for a symmetric key with the specified
      * attributes.
      *
      * @param usage key usage. May be invalid.
      * @param algo key algorithm. May be invalid.
      * @param extractable true if the key is extractable.
      * @param id key ID. May be empty.
      * @param secretKey symmetric key.
      * @throws MslInternalException if the usage or algorithm is incompatible.
      */
     JsonWebKey(const Usage& usage, const Algorithm& algo, bool extractable,
         const std::string& id, std::shared_ptr<SecretKey> secretKey);

     /**
       * Create a new JSON web key for an RSA public/private key pair with the
       * specified attributes. At least one of the public key or private key must
       * be encoded.
       *
       * @param keyOps key operations. May be null.
       * @param algo key algorithm. May be null.
       * @param extractable true if the key is extractable.
       * @param id key ID. May be null.
       * @param publicKey RSA public key. May be null.
       * @param privateKey RSA private key. May be null.
       * @throws MslInternalException if both keys are null or the algorithm
       *         is incompatible.
       */
      JsonWebKey(const std::set<KeyOp>& keyOps, const Algorithm& algo, bool extractable,
          const std::string& id, std::shared_ptr<PublicKey> publicKey,
          std::shared_ptr<PrivateKey> privateKey);

      /**
       * Create a new JSON web key for a symmetric key with the specified
       * attributes.
       *
       * @param keyOps key operations. May be null.
       * @param algo key algorithm. May be null.
       * @param extractable true if the key is extractable.
       * @param id key ID. May be null.
       * @param secretKey symmetric key.
       * @throws MslInternalException if the usage or algorithm is incompatible.
       */
      JsonWebKey(const std::set<KeyOp>& keyOps, const Algorithm& algo, bool extractable,
          const std::string& id, std::shared_ptr<SecretKey> secretKey);

      /**
       * Create a new JSON web key from the provided MSL object.
       *
       * @param jsonMo JSON web key MSL object.
       * @throws MslCryptoException if the key type is unknown.
       * @throws MslEncodingException if there is an error parsing the data.
       */
      JsonWebKey(std::shared_ptr<io::MslObject> jsonMo);

      /**
       * @return the key type.
       */
      Type getType() const { return type; }

      /**
       * @return the permitted key usage or invalid if not specified.
       */
      Usage getUsage() const { return usage; }

      /**
       * @return the permitted key operations or empty if none specified.
       */
      std::set<KeyOp> getKeyOps() const { return keyOps; }

      /**
       * @return the key algorithm or invalid if not specified.
       */
      Algorithm getAlgorithm() const { return algo; }

      /**
       * @return true if the key is allowed to be extracted.
       */
      bool isExtractable() const { return extractable; }

      /**
       * @return the key ID or null if not specified.
       */
      std::shared_ptr<std::string> getId() const { return id; }

      /**
       * Returns the stored RSA key pair if the JSON web key type is RSA. The
       * public or private key may be null if only one of the pair is stored in
       * this JSON web key.
       *
       * @return the stored RSA key pair or null if the type is not RSA.
       */
      std::shared_ptr<KeyPair> getRsaKeyPair() const { return keyPair; }

      /**
       * Returns the stored symmetric key if the JSON web key type is OCT and an
       * algorithm was specified. Because Java {@code SecretKey} requires a known
       * algorithm when it is constructed, the key material may be present when
       * this method returns {@code null}.
       *
       * @return the stored symmetric key or null if the type is not OCT or no
       *         algorithm was specified.
       * @see #getSecretKey(String)
       */
      std::shared_ptr<SecretKey> getSecretKey() const { return secretKey; }

      /**
       * Returns the stored symmetric key if the JSON web key type is OCT. The
       * returned key algorithm will be the one specified by the JSON web key
       * algorithm. If no JSON web key algorithm was specified the provided
       * algorithm will be used instead.
       *
       * @param algorithm the symmetric key algorithm to use if one was not
       *        specified in the JSON web key.
       * @return the stored symmetric key or null if the type is not OCT.
       * @throws MslCryptoException if the key cannot be constructed.
       * @see #getSecretKey()
       */
      std::shared_ptr<SecretKey> getSecretKey(const std::string& algorithm) const;

      /** @inheritDoc */
      std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

private:
    JsonWebKey(); // not implemented
    /** Key type. */
    Type type;
    /** Key usages. */
    Usage usage;
    /** Key operations. */
    std::set<KeyOp> keyOps;
    /** Key algorithm. */
    Algorithm algo;
    /** Extractable. */
    bool extractable;
    /** Key ID. */
    std::shared_ptr<std::string> id;

    /** RSA key pair. May be null. */
    std::shared_ptr<KeyPair> keyPair;
    /** Symmetric key raw bytes. May be null. */
    std::shared_ptr<ByteArray> key;
    /** Symmetric key. May be null. */
    std::shared_ptr<SecretKey> secretKey;
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_JSONWEBKEY_H_ */
