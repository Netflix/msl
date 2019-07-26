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

#ifndef SRC_CRYPTO_MSLCIPHERTEXTENVELOPE_H_
#define SRC_CRYPTO_MSLCIPHERTEXTENVELOPE_H_

#include <Enum.h>
#include <io/MslEncodable.h>
#include <MslConstants.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace crypto {

/**
 * MSL ciphertext envelopes contain all of the information necessary for
 * decrypting ciphertext using a known key.
 */
class MslCiphertextEnvelope : public io::MslEncodable
{
public:
    class Version : public Enum<Version>
    {
    public:
        static const Version
        /**
         * <p>Version 1.</p>
         *
         * {@code {
         *   "#mandatory" : [ "keyid", "iv", "ciphertext", "sha256" ],
         *   "keyid" : "string",
         *   "iv" : "base64",
         *   "ciphertext" : "base64",
         *   "sha256" : "base64",
         * }} where:
         * <ul>
         * <li>{@code keyid} is the encryption key ID</li>
         * <li>{@code iv} is the Base64-encoded initialization vector</li>
         * <li>{@code ciphertext} is the Base64-encoded ciphertext</li>
         * <li>{@code sha256} is the Base64-encoded SHA-256 of the encryption envelope</li>
         * </ul>
         *
         * <p>The SHA-256 is computed over the concatenation of {@code key ID ||
         * IV || ciphertext}.</p>
         */
        V1,
        /**
         * <p>Version 2.</p>
         *
         * {@code {
         *   "#mandatory" : [ "version", "cipherspec", "ciphertext" ],
         *   "version" : "number",
         *   "cipherspec" : "string",
         *   "iv" : "base64",
         *   "ciphertext" : "base64",
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code cipherspec} is one of the recognized cipher specifications</li>
         * <li>{@code iv} is the optional Base64-encoded initialization vector</li>
         * <li>{@code ciphertext} is the Base64-encoded ciphertext</li>
         * </ul>
         *
         * <p>Supported cipher specifications:
         * <table>
         * <tr><th>Cipher Spec</th><th>Description</th></tr>
         * <tr><td>AES/CBC/PKCS5Padding</td><td>AES CBC w/PKCS#5 Padding</td></tr>
         * </table></p>
         */
        V2,
        INVALID;

        enum Value { invalid = 0, v1 = 1, v2 = 2 };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<Version>& getValues();
        Version() : Enum(invalid, "INVALID") {}

    private:
        Version(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    ~MslCiphertextEnvelope() {}

    MslCiphertextEnvelope(const Version& version, const std::string& keyId,
            const MslConstants::CipherSpec& cipherSpec, std::shared_ptr<ByteArray> iv, std::shared_ptr<ByteArray> ciphertext)

        : version_(version)
        , keyId_(keyId)
        , cipherSpec_(cipherSpec)
        , iv_(iv)
        , ciphertext_(ciphertext)
    {
    }

    /**
     * Create a new version 1 ciphertext envelope with the provided data.
     *
     * @param keyId the key identifier.
     * @param iv the initialization vector. May be null.
     * @param ciphertext the ciphertext.
     */
    MslCiphertextEnvelope(const std::string& keyId, std::shared_ptr<ByteArray> iv, std::shared_ptr<ByteArray> ciphertext)
        : version_(Version::V1)
        , keyId_(keyId)
        , cipherSpec_(MslConstants::CipherSpec::INVALID)
        , iv_(iv)
        , ciphertext_(ciphertext)
    {
    }

    /**
     * Create a new version 2 ciphertext envelope with the provided data.
     *
     * @param cipherSpec the cipher specification.
     * @param iv the initialization vector. May be empty.
     * @param ciphertext the ciphertext.
     */
    MslCiphertextEnvelope(const MslConstants::CipherSpec& cipherSpec, std::shared_ptr<ByteArray> iv, std::shared_ptr<ByteArray> ciphertext)
        : version_(Version::V2)
        //, keyId_()  default empty
        , cipherSpec_(cipherSpec)
        , iv_(iv)
        , ciphertext_(ciphertext)
    {
    }

    /**
     * @return the encryption key ID. May be null.
     */
    std::string getKeyId() const { return keyId_; }

    /**
     * @return the ciphser specification. May be empty.
     */
    MslConstants::CipherSpec getCipherSpec() const { return cipherSpec_; }

    /**
     * @return the initialization vector. May be empty.
     */
    std::shared_ptr<ByteArray> getIv() const { return iv_; }

    /**
     * @return the ciphertext.
     */
    std::shared_ptr<ByteArray> getCiphertext() const { return ciphertext_; }

    /**
     * @return the ciphertext.
     */
    // FIXME: The java code does not have this public method. Why?
    Version getVersion() const { return version_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

private:
    /** Envelope version. */
    const Version version_;
    /** Key identifier. */
    const std::string keyId_;
    /** Cipher specification. */
    const MslConstants::CipherSpec cipherSpec_;
    /** Optional initialization vector. */
    std::shared_ptr<ByteArray> iv_;
    /** Ciphertext. */
    std::shared_ptr<ByteArray> ciphertext_;

    friend class MslCiphertextEnvelopeTest_GetVersion_Test;  // TEST only
};

/**
 * Determines the envelope version of the given MSL object.
 *
 * @param mo the MSL object.
 * @return the envelope version.
 * @throws MslCryptoException if the envelope version is not recognized.
 */
MslCiphertextEnvelope::Version getCiphertextEnvelopeVersion(std::shared_ptr<io::MslObject> mo);

/**
 * Create a new encryption envelope of the specified version from the
 * provided MSL object.
 *
 * @param mo the MSL object.
 * @param version the envelope version.
 * @throws MslCryptoException if there is an error processing the
 *         encryption envelope.
 * @throws MslEncodingException if there is an error parsing the data.
 */
MslCiphertextEnvelope createMslCiphertextEnvelope(std::shared_ptr<io::MslObject> mo, const MslCiphertextEnvelope::Version& version);

/**
 * Create a new encryption envelope from the provided MSL object.
 *
 * @param mo the MSL object.
 * @throws MslCryptoException if there is an error processing the
 *         encryption envelope.
 * @throws MslEncodingException if there is an error parsing the data.
 */
MslCiphertextEnvelope createMslCiphertextEnvelope(std::shared_ptr<io::MslObject> mo);

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_MSLCIPHERTEXTENVELOPE_H_ */
