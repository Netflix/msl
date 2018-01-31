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

#ifndef SRC_ICRYPTOCONTEXT_H_
#define SRC_ICRYPTOCONTEXT_H_

#include <cstdint>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
namespace io { class MslEncoderFactory; class MslEncoderFormat; }
namespace crypto {

typedef std::vector<uint8_t> ByteArray;

/**
 * A generic cryptographic context suitable for encryption/decryption,
 * wrap/unwrap, and sign/verify operations.
 */
class ICryptoContext
{
public:
    virtual ~ICryptoContext() {}

    /**
     * Encrypts some data.
     *
     * @param data the plaintext.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return ciphertext
     * @throws MslCryptoException if there is an error encrypting the data.
     */
    virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) = 0;

    /**
     * Decrypts some data.
     *
     * @param data the ciphertext.
     * @param encoder MSL encoder factory.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error decrypting the data.
     */
    virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder) = 0;

    /**
     * Wraps some data.
     *
     * @param data the plaintext.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the wrapped data.
     * @throws MslCryptoException if there is an error wrapping the data.
     */
    virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) = 0;

    /**
     * Unwraps some data.
     *
     * @param data the wrapped data.
     * @param encoder MSL encoder factory.
     * @return the plaintext.
     * @throws MslCryptoException if there is an error unwrapping the data.
     */
    virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder) = 0;

    /**
     * Computes the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     *
     * @param data the data.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the signature.
     * @throws MslCryptoException if there is an error computing the signature.
     */
    virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) = 0;

    /**
     * Verifies the signature for some data. The signature may not be a
     * signature proper, but the name suits the concept.
     *
     * @param data the data.
     * @param signature the signature.
     * @param encoder MSL encoder factory.
     * @return true if the data is verified, false if validation fails.
     * @throws MslCryptoException if there is an error verifying the signature.
     */
    virtual bool verify(std::shared_ptr<ByteArray> data, std::shared_ptr<ByteArray> signature, std::shared_ptr<io::MslEncoderFactory> encoder) = 0;
};

} /* namespace crypto */
} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_ICRYPTOCONTEXT_H_ */
