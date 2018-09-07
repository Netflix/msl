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

#ifndef SRC_CRYPTO_MSLSIGNATUREENVELOPE_H_
#define SRC_CRYPTO_MSLSIGNATUREENVELOPE_H_

#include <Enum.h>
#include <MslConstants.h>
#include <stdint.h>
#include <vector>

namespace netflix {
namespace msl {
namespace io { class MslEncoderFactory; class MslEncoderFormat; }
namespace crypto {

typedef std::vector<uint8_t> ByteArray;

/**
 * <p>MSL signature envelopes contain all of the information necessary for
 * verifying data using a known key.</p>
 */
class MslSignatureEnvelope
{
public:
    class Version : public Enum<Version>
    {
    public:
        static const Version
        /**
         * <p>Version 1.</p>
         *
         * {@code signature}
         *
         * <p>The signature is represented as raw bytes.</p>
         */
        V1,
        /**
         * <p>Version 2.</p>
         *
         * {@code {
         *   "#mandatory" : [ "version", "algorithm", "signature" ],
         *   "version" : "number",
         *   "algorithm" : "string",
         *   "signature" : "base64"
         * }} where:
         * <ul>
         * <li>{@code version} is the number '2'</li>
         * <li>{@code algorithm} is one of the recognized signature algorithms</li>
         * <li>{@code signature} is the Base64-encoded signature</li>
         * </ul>
         *
         * <p>Supported algorithms:
         * <table>
         * <tr><th>Algorithm</th><th>Description</th>
         * <tr><td>HmacSHA256</td><td>HMAC w/SHA-256</td></tr>
         * <tr><td>SHA256withRSA</td><td>RSA signature w/SHA-256</td></tr>
         * <tr><td>AESCmac</td><td>AES CMAC</td></tr>
         * </table></p>
         */
        V2,
        INVALID;

        enum Value { invalid = 0, v1 = 1, v2 = 2 };
        operator Value() const { return static_cast<Value>(value()); }
        static const std::vector<Version>& getValues();
        Version() : Enum(invalid, "INVALID") {}

        /**
         * @param version the integer value of this version.
         * @return the version identified by the integer value.
         * @throws IllegalArgumentException if the version is unknown.
         */
        static Version valueOf(int version);

    private:
        Version(const Value& value, const std::string& strValue)
            : Enum(value, strValue) {}
    };

    ~MslSignatureEnvelope() {}

    /**
     * Create a new version 1 signature envelope with the provided signature.
     *
     * @param signature the signature.
     */
    MslSignatureEnvelope(std::shared_ptr<ByteArray> signature)
        : version_(Version::V1)
        , algorithm_(MslConstants::SignatureAlgo::INVALID)
        , signature_(signature)
    {}

    /**
     * Create a new version 2 signature envelope with the provided data.
     *
     * @param algorithm the signature algorithm.
     * @param signature the signature.
     */
    MslSignatureEnvelope(const MslConstants::SignatureAlgo& algorithm, std::shared_ptr<ByteArray> signature)
        : version_(Version::V2)
        , algorithm_(algorithm)
        , signature_(signature)
    {}

    /**
     * Returns the signature envelope in byte form.
     *
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the byte representation of the signature envelope.
     * @throws MslEncoderException if there is an error encoding the envelope.
     * @throws MslInternalException if the envelope version is not supported.
     */
    std::shared_ptr<ByteArray> getBytes(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /**
     * Create a new signature envelope for the specified version from the
     * provided envelope bytes.
     *
     * @param envelope the raw envelope bytes.
     * @param encoder MSL encoder factory..
     * @param version the envelope version.
     * @return the envelope.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the envelope.
     * @see #getBytes(MslEncoderFactory, MslEncoderFormat)
     */
    static
    MslSignatureEnvelope parse(std::shared_ptr<ByteArray> envelope, std::shared_ptr<io::MslEncoderFactory> encoder,
            const Version& version);

    /**
     * Create a new signature envelope from the provided envelope bytes.
     *
     * @param envelope the raw envelope bytes.
     * @param encoder MSL encoder factory.
     * @return the envelope.
     * @throws MslCryptoException if there is an error processing the signature
     *         envelope.
     * @throws MslEncodingException if there is an error parsing the envelope.
     * @see #getBytes(MslEncoderFactory, MslEncoderFormat)
     */
    static
    MslSignatureEnvelope parse(std::shared_ptr<ByteArray> envelope, std::shared_ptr<io::MslEncoderFactory> encoder);

    /**
     * @return the signature algorithm. May be INVALID.
     */
    MslConstants::SignatureAlgo getAlgorithm() const { return algorithm_; }

    /**
     * @return the signature.
     */
    std::shared_ptr<ByteArray> getSignature() const { return signature_; }

private:
    MslSignatureEnvelope(); // not implemented

private:
    /** Envelope version. */
    const Version version_;
    /** Algorithm. */
    const MslConstants::SignatureAlgo algorithm_;
    /** Signature. */
    std::shared_ptr<ByteArray> signature_;




};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_MSLSIGNATUREENVELOPE_H_ */
