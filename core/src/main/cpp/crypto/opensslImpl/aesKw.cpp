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
#include "../OpenSslLib.h"
#include <MslCryptoException.h>
#include <MslError.h>
#include <numerics/safe_math.h>
#include <openssl/aes.h>
#include <sstream>

namespace netflix {
namespace msl {
namespace crypto {

// NOTE: Unlike BoringSSL, OpenSSL does not have EVP methods for AES key wrap,
// so must use the primitive functions.

void aesKwWrap(const ByteArray& wrappingKey, const ByteArray& keyToWrap, ByteArray& wrappedKey)
{
    if ((wrappingKey.size() != 16 && wrappingKey.size() != 24 && wrappingKey.size() != 32))
        throw IllegalArgumentException("Encryption key must be 16, 24, or 32 bytes only.");

    // OpenSSL implements https://tools.ietf.org/html/rfc3394, which requires
    // that the key to be wrapped must be at least 16 bytes and a multiple of 8
    // bytes.
    if (keyToWrap.size() < 16 || (keyToWrap.size() % 8))
        throw IllegalArgumentException("Input key to wrap size must be at least 8 bytes and a multiple of 8 bytes.");

    AES_KEY aes_key;
    base::CheckedNumeric<int> wrappingKeySizeBits = wrappingKey.size();
    wrappingKeySizeBits *= 8;
    if (!wrappingKeySizeBits.IsValid())
        throw MslCryptoException(MslError::DATA_TOO_LARGE, "integer overflow when computing wrappingKeySizeBits");
    int ret = AES_set_encrypt_key(&wrappingKey[0], wrappingKeySizeBits.ValueOrDie(), &aes_key);
    if (ret != 0)
    {
        std::stringstream ss;
        ss << "AES_set_encrypt_key failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    base::CheckedNumeric<int> wrappedKeySize = keyToWrap.size();
    wrappedKeySize += 8;
    if (!wrappedKeySize.IsValid())
        throw MslCryptoException(MslError::DATA_TOO_LARGE, "integer overflow when computing wrappedKey size");
    ByteArray result(static_cast<size_t>(wrappedKeySize.ValueOrDie()));
    // Note: the RFC default IV will be used if NULL is provided to the API.
    ret = AES_wrap_key(&aes_key, NULL, &result[0], &keyToWrap[0], static_cast<unsigned int>(keyToWrap.size()));
    if (ret < 0 || ret != wrappedKeySize.ValueOrDie())
    {
        std::stringstream ss;
        ss << "AES_wrap_key failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }
    wrappedKey.swap(result);
}

void aesKwUnwrap(const ByteArray& wrappingKey, const ByteArray& wrappedKey, ByteArray& unwrappedKey)
{
    if ((wrappingKey.size() != 16 && wrappingKey.size() != 24 && wrappingKey.size() != 32))
        throw IllegalArgumentException("Encryption key must be 16, 24, or 32 bytes only.");

    // OpenSSL implements https://tools.ietf.org/html/rfc3394, which requires
    // that the wrapped key must be at least 24 bytes and a multiple of 8 bytes.
    if (wrappedKey.size() < 24 || (wrappedKey.size() % 8))
        throw IllegalArgumentException("Input wrapped key size must be at least 24 bytes and a multiple of 8 bytes.");

    AES_KEY aes_key;
    int ret = AES_set_decrypt_key(&wrappingKey[0], (int)wrappingKey.size() * 8, &aes_key);
    if (ret != 0)
    {
        std::stringstream ss;
        ss << "AES_set_decrypt_key failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    base::CheckedNumeric<int> unwrappedKeySize = wrappedKey.size();
    unwrappedKeySize -= 8;
    ByteArray result(static_cast<size_t>(unwrappedKeySize.ValueOrDie()));
    // Note: the RFC default IV will be used if NULL is provided to the API.
    ret = AES_unwrap_key(&aes_key, NULL, &result[0], &wrappedKey[0], static_cast<unsigned int>(wrappedKey.size()));
    if (ret < 0 || ret != unwrappedKeySize.ValueOrDie())
    {
        std::stringstream ss;
        ss << "AES_unwrap_key failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }
    unwrappedKey.swap(result);
}

}}} // namespace netflix::msl::crypto

