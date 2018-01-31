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

// Portions Copyright 2014 The Chromium Authors. All rights reserved.

#include "../OpenSslLib.h"
#include <MslCryptoException.h>
#include <MslError.h>
#include <util/Hex.h>
#include <assert.h>
#include <numerics/safe_math.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <util/ScopedDisposer.h>

using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace { // anonymous

// The values of these constants correspond with the "enc" parameter of
// EVP_CipherInit_ex(), do not change.
enum EncryptOrDecrypt { DECRYPT = 0, ENCRYPT = 1 };

const uint32_t AES_BLOCK_SIZE = 16;

const EVP_CIPHER* getAESCipherByKeyLength(size_t key_length_bytes) {
    switch (key_length_bytes) {
        case 16:
            return EVP_aes_128_cbc();
        case 24:
            return EVP_aes_192_cbc();
        case 32:
            return EVP_aes_256_cbc();
        default:
            throw MslCryptoException(MslError::INVALID_ENCRYPTION_KEY);
    }
}

void aesCbcEncryptDecrypt(EncryptOrDecrypt operation, const ByteArray& key,
        const ByteArray& iv, const ByteArray& input, ByteArray& output)
{
    OpenSslErrStackTracer errTracer;

    //std::cout << ((operation == DECRYPT) ? "-- Decrypt --" : "-- Encrypt --") << std::endl;
    //std::cout << "key: " << util::toHex(key) << std::endl;
    //std::cout << "input: " << util::toHex(input) << std::endl;

    // this throws if invalid key size
    const EVP_CIPHER* const cipher = getAESCipherByKeyLength(key.size());

    if (iv.size() != 16)
        throw MslCryptoException(MslError::INVALID_IV, "IV wrong size");

    // Due to padding (PKCS5 padding is on by default), the amount of data
    // written may be as large as (data_size + cipher_block_size - 1),
    // constrained to a multiple of cipher_block_size.
    base::CheckedNumeric<int> outputMaxLen = input.size();
    outputMaxLen += AES_BLOCK_SIZE - 1;
    if (!outputMaxLen.IsValid())
        throw MslCryptoException(MslError::DATA_TOO_LARGE, "integer overflow when computing output size");
    const unsigned remainder = static_cast<unsigned>(outputMaxLen.ValueOrDie()) % AES_BLOCK_SIZE;
    if (remainder != 0)
        outputMaxLen += AES_BLOCK_SIZE - remainder;
    if (!outputMaxLen.IsValid())
        throw MslCryptoException(MslError::DATA_TOO_LARGE, "integer overflow when computing output size");

    ScopedDisposer<EVP_CIPHER_CTX, void, EVP_CIPHER_CTX_free> context(EVP_CIPHER_CTX_new());
    if (!context.get())
        throw MslCryptoException(MslError::CRYPTO_ERROR, "EVP_CIPHER_CTX_new failed");

    if (!EVP_CipherInit_ex(context.get(), cipher, NULL, &key[0],  &iv[0], operation)) {
        std::stringstream ss;
        ss << "EVP_CipherInit_ex failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    ByteArray result(static_cast<size_t>(outputMaxLen.ValueOrDie()));
    int outputLen = 0;
    if (!EVP_CipherUpdate(context.get(), &result[0], &outputLen, &input[0], (int)input.size())) {
        std::stringstream ss;
        ss << "EVP_CipherUpdate failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    int finalOutputChunkLen = 0;
    // no need for checked numeric operation because we trust OpenSSL
    if (!EVP_CipherFinal_ex(context.get(), &result[0] + outputLen, &finalOutputChunkLen)) {
        std::stringstream ss;
        ss << "EVP_CipherFinal_ex failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    // no need for checked numeric operation because we trust OpenSSL
    const unsigned int finalOutputLen =
            static_cast<unsigned int>(outputLen) +
            static_cast<unsigned int>(finalOutputChunkLen);
    result.resize(finalOutputLen);

    //std::cout << "output: " << util::toHex(result) << std::endl;

    output.swap(result);
}

} // namespace anonymous

void aesCbcEncrypt(const ByteArray& key, const ByteArray& iv, const ByteArray& plaintext, ByteArray& ciphertext)
{
    aesCbcEncryptDecrypt(ENCRYPT, key, iv, plaintext, ciphertext);
}

void aesCbcDecrypt(const ByteArray& key, const ByteArray& iv, const ByteArray& ciphertext, ByteArray& plaintext)
{
    aesCbcEncryptDecrypt(DECRYPT, key, iv, ciphertext, plaintext);
}

} // namespace crypto
} // namespace msl
} // namespace netflix


