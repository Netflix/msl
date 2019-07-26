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

#ifndef SRC_CRYPTO_RSACRYPTOCONTEXT_H_
#define SRC_CRYPTO_RSACRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>
#include <crypto/Key.h>
#include <crypto/OpenSslLib.h>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace util { class MslContext; }
namespace crypto {

class RsaCryptoContext : public ICryptoContext
{
public:
    virtual ~RsaCryptoContext() {}

    /** RSA crypto context algorithm. .*/
    enum Mode {
        /** RSA-OAEP encrypt/decrypt */
        ENCRYPT_DECRYPT_OAEP,
        /** RSA PKCS#1 encrypt/decrypt */
        ENCRYPT_DECRYPT_PKCS1,
        /** RSA-KEM wrap/unwrap */
        WRAP_UNWRAP,
        /** RSA-SHA256 sign/verify */
        SIGN_VERIFY
    };

    /**
     * <p>Create a new RSA crypto context for encrypt/decrypt and sign/verify
     * using the provided public and private keys. The crypto context algorithm
     * identifies the operations to enable. All other operations are no-ops and
     * return the data unmodified.</p>
     *
     * <p>If there is no private key, decryption and signing is unsupported.</p>
     *
     * <p>If there is no public key, encryption and verification is
     * unsupported.</p>
     *
     * @param ctx MSL context.
     * @param id the key pair identity.
     * @param privateKey the private key. May be null.
     * @param publicKey the public key. May be null.
     * @param mode crypto context mode.
     */
    RsaCryptoContext(std::shared_ptr<util::MslContext> ctx, const std::string& id,
            const crypto::PrivateKey& privateKey, const crypto::PublicKey& publicKey, const Mode& mode);

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
    /** Key pair identity. */
    const std::string id;
    /** Encryption/decryption cipher. */
    const PrivateKey privateKey;
    /** Sign/verify signature. */
    const PublicKey publicKey;
    /** Encryption/decryption transform. */
    std::string transform;
    /** Sign/verify algorithm. */
    std::string algo;
    // OpenSSL key structures stored here as an optimization
    std::shared_ptr<RsaEvpKey> privateKeyEvp;
    std::shared_ptr<RsaEvpKey> publicKeyEvp;

private:
    RsaCryptoContext(); // not implemented
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_RSACRYPTOCONTEXT_H_ */
