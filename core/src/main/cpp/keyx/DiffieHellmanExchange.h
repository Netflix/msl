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

#ifndef SRC_KEYX_DIFFIEHELLMANEXCHANGE_H_
#define SRC_KEYX_DIFFIEHELLMANEXCHANGE_H_

#include <crypto/Key.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/DiffieHellmanParameters.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace util { class AuthenticationUtils; }
namespace keyx {

/**
 * <p>Diffie-Hellman key exchange.</p>
 */
class DiffieHellmanExchange: public KeyExchangeFactory
{
public:
    virtual ~DiffieHellmanExchange() {}
    /**
     * Create a new Diffie-Hellman key exchange factory.
     *
     * @param params Diffie-Hellman parameters.
     * @param authutils authentication utilities.
     */
    DiffieHellmanExchange(std::shared_ptr<DiffieHellmanParameters> params,
            std::shared_ptr<util::AuthenticationUtils> authutils);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<tokens::MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyExchangeData> generateResponse(std::shared_ptr<util::MslContext> ctx,
            const io::MslEncoderFormat& format, std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData);

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<KeyRequestData> keyRequestData,
            std::shared_ptr<KeyResponseData> keyResponseData,
            std::shared_ptr<tokens::MasterToken> masterToken);

public: // Nested types
    /**
     * <p>Diffie-Hellman key request data. </p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "binary",
     * }} where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the public key used to generate the shared secret</li>
     * </ul>
     * </p>
     */
    // FIXME: Why is publickey passed/stored as raw bytes while privatekey uses an object?
    class RequestData : public KeyRequestData
    {
    public:
        virtual ~RequestData() {}

        /**
         * Create a new Diffie-Hellman request data repository with the
         * specified parameters ID and public key. The private key is also
         * required but is not included in the request data.
         *
         * @param parametersId the parameters ID.
         * @param publicKey the public key Y-value.
         * @param privateKey the private key.
         */
        RequestData(const std::string& parametersId, std::shared_ptr<ByteArray> publicKey,
                std::shared_ptr<crypto::PrivateKey> privateKey);

        /**
         * Create a new Diffie-Hellman request data repository from the
         * provided MSL object. The private key will be unknown.
         *
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the public key is invalid.
         */
        RequestData(std::shared_ptr<io::MslObject> keyDataMo);

        /**
         * @return the parameters ID.
         */
        std::string getParametersId() const;

        /**
         * @return the public key Y-value.
         */
        std::shared_ptr<ByteArray> getPublicKey() const;

        /**
         * @return the private key or null if unknown (reconstructed from a
         *         MSL object).
         */
        std::shared_ptr<crypto::PrivateKey> getPrivateKey() const;

        /** @inheritDoc */
        virtual bool equals(std::shared_ptr<const KeyRequestData> other) const;

        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder,
                const io::MslEncoderFormat& format) const;

    private:
        /** Diffie-Hellman parameters ID. */
        std::string parametersId;
        /** Diffie-Hellman public key Y-value (g^x mod p). */
        std::shared_ptr<ByteArray> publicKey;
        /** Diffie-Hellman private key value (x). */
        std::shared_ptr<crypto::PrivateKey> privateKey;
    };

    /**
     * <p>Diffie-Hellman key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "binary",
     * }} where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the public key used to generate the shared secret</li>
     * </ul>
     * </p>
     */
    class ResponseData : public KeyResponseData
    {
    public:
        ~ResponseData() {}

        /**
         * Create a new Diffie-Hellman response data repository with the
         * provided master token, specified parameters ID and public key.
         *
         * @param masterToken the master token.
         * @param parametersId the parameters ID.
         * @param publicKey the public key Y-value.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, const std::string& parametersId,
                std::shared_ptr<ByteArray> publicKey);

        /**
         * Create a new Diffie-Hellman response data repository with the
         * provided master token from the provided MSL object.
         *
         * @param masterToken the master token.
         * @param keyDataMo the MSL object.
         * @throws MslEncodingException if there is an error parsing the data.
         * @throws MslKeyExchangeException if the public key is invalid.
         */
        ResponseData(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

        /**
         * @return the parameters ID.
         */
        std::string getParametersId() const;

        /**
         * @return the public key Y-value.
         */
        std::shared_ptr<ByteArray> getPublicKey() const;

        /** @inheritDoc */
        virtual bool equals(std::shared_ptr<const KeyResponseData> other) const;

        /** @inheritDoc */
        virtual std::shared_ptr<io::MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory> encoder,
                const io::MslEncoderFormat& format) const;

    private:
        /** Diffie-Hellman parameters ID. */
        std::string parametersId;
        /** Diffie-Hellman public key. */
        std::shared_ptr<ByteArray> publicKey;
    };

protected:
    DiffieHellmanExchange(); // not implemented

    /** @inheritDoc */
    virtual std::shared_ptr<KeyRequestData> createRequestData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> keyRequestMo);

    /** @inheritDoc */
    virtual std::shared_ptr<KeyResponseData> createResponseData(std::shared_ptr<util::MslContext> ctx,
        std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> keyDataMo);

private:
    /** Diffie-Hellman parameters. */
    std::shared_ptr<DiffieHellmanParameters> params;
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils;
};

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_DIFFIEHELLMANEXCHANGE_H_ */
