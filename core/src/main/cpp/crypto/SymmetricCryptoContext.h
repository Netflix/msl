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

#ifndef SRC_CRYPTO_SYMMETRICCRYPTOCONTEXT_H_
#define SRC_CRYPTO_SYMMETRICCRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>
#include <crypto/Key.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace util { class MslContext; }
namespace crypto {

/**
 * A symmetric crypto context performs AES-128 encryption/decryption, AES-128
 * key wrap/unwrap, and HMAC-SHA256 or AES-CMAC sign/verify.
 */
class SymmetricCryptoContext: public ICryptoContext
{
public:
     virtual ~SymmetricCryptoContext() {}
     SymmetricCryptoContext(std::shared_ptr<util::MslContext> ctx,
             const std::string& id, const SecretKey& encryptionKey,
             const SecretKey& signatureKey, const SecretKey& wrappingKey);
     virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);
     virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);
     virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);
     virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder);
     virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format);
     virtual bool verify(std::shared_ptr<ByteArray> data, std::shared_ptr<ByteArray> signature, std::shared_ptr<io::MslEncoderFactory> encoder);

protected:
     /** MSL context. */
     const std::shared_ptr<util::MslContext> ctx_;
     /** Key set identity. */
     const std::string id_;
     /** Encryption/decryption key. */
     const crypto::SecretKey encryptionKey_;
     /** Signature key. */
     const crypto::SecretKey signatureKey_;
     /** Wrapping key. */
     const crypto::SecretKey wrappingKey_;

private:
     SymmetricCryptoContext();
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_SYMMETRICCRYPTOCONTEXT_H_ */
