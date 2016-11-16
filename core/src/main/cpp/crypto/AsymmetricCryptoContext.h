/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_CRYPTO_ASYMMETRICCRYPTOCONTEXT_H_
#define SRC_CRYPTO_ASYMMETRICCRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>
#include <crypto/Key.h>
#include <crypto/OpenSslLib.h>
#include <Macros.h>
#include <util/ScopedDisposer.h>

namespace netflix {
namespace msl {
namespace crypto {

/**
 * An asymmetric crypto context performs encrypt/decrypt and sign/verify using
 * a public/private key pair. Wrap/unwrap are unsupported.
 */
class AsymmetricCryptoContext: public crypto::ICryptoContext
{
public:
    virtual ~AsymmetricCryptoContext() {}

    static const std::string NULL_OP;

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);

    /** @inheritDoc */
    virtual bool verify(std::shared_ptr<ByteArray> data, std::shared_ptr<ByteArray> signature, std::shared_ptr<io::MslEncoderFactory> encoder);

protected:
    /**
     * <p>Create a new asymmetric crypto context using the provided public and
     * private keys and named encrypt/decrypt transform and sign/verify
     * algorithm.</p>
     *
     * <p>If there is no private key, decryption and signing is unsupported.</p>
     *
     * <p>If there is no public key, encryption and verification is
     * unsupported.</p>
     *
     * <p>If {@code #NULL_OP} is specified for the transform then encrypt/
     * decrypt operations will return the data unmodified even if the key is
     * null. Otherwise the operation is unsupported if the key is null.</p>
     *
     * <p>If {@code #NULL_OP} is specified for the algorithm then sign/verify
     * will return an empty signature and always pass verification even if the
     * key is null. Otherwise the operation is unsupported if the key is
     * null.</p>
     *
     * @param id the key pair identity.
     * @param privateKey the private key used for signing. May be null.
     * @param publicKey the public key used for verifying. May be null.
     * @param transform encrypt/decrypt transform.
     * @param algo sign/verify algorithm.
     */
    AsymmetricCryptoContext(const std::string& id, const PrivateKey& privateKey,
        const PublicKey& publicKey, const std::string& transform, const std::string& algo);

protected:
    /** Key pair identity. */
    const std::string id;
    /** Encryption/decryption cipher. */
    const PrivateKey privateKey;
    /** Sign/verify signature. */
    const PublicKey publicKey;
    /** Encryption/decryption transform. */
    const std::string transform;
    /** Sign/verify algorithm. */
    const std::string algo;
    // OpenSSL key structures stored here as an optimization
    std::shared_ptr<RsaEvpKey> privateKeyEvp;
    std::shared_ptr<RsaEvpKey> publicKeyEvp;
private:
    DISALLOW_IMPLICIT_CONSTRUCTORS(AsymmetricCryptoContext);
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_ASYMMETRICCRYPTOCONTEXT_H_ */
