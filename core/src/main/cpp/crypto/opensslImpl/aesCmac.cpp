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
#include <assert.h>
#include <crypto/opensslImpl/util.h>
#include <crypto/OpenSslLib.h>
#include <IllegalArgumentException.h>
#include <MslCryptoException.h>
#include <MslError.h>
#include <openssl/cmac.h>
#include <util/ScopedDisposer.h>

// See https://tools.ietf.org/html/rfc4493

using namespace netflix::msl::util;

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace crypto {

namespace {

const size_t AESCMAC_OUTPUT_LENGTH = 16;

void aesCmacSign(const ByteArray& key, const ByteArray& data, ByteArray& signature)
{
    OpenSslErrStackTracer errTracer;

    // RFC4493 defines AES-CMAC as using AES-CBC 128, which requires a key size
    // of 16 bytes.
    if (key.size() != 16)
        throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "AES-CMAC key size must be 16 bytes");

    ScopedDisposer<CMAC_CTX, void, CMAC_CTX_free> context(CMAC_CTX_new());
    if (!context.get())
        throw MslCryptoException(MslError::CRYPTO_ERROR, "CMAC_CTX_new failed");

    if (!CMAC_Init(context.get(), &key[0], key.size(), EVP_aes_128_cbc(), NULL)) {
        std::stringstream ss;
        ss << "CMAC_Init failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    if (!CMAC_Update(context.get(), &data[0], data.size())) {
        std::stringstream ss;
        ss << "CMAC_Update failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    ByteArray result(AESCMAC_OUTPUT_LENGTH);
    size_t actualLength;
    if (!CMAC_Final(context.get(), &result[0], &actualLength) ||
        (actualLength != AESCMAC_OUTPUT_LENGTH))
    {
        std::stringstream ss;
        ss << "CMAC_Final failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }

    result.resize(actualLength);
    signature.swap(result);
}

}

void signAesCmac(const ByteArray& key, const ByteArray& data, ByteArray& sig)
{
    aesCmacSign(key, data, sig);
}

bool verifyAesCmac(const ByteArray& key, const ByteArray& data, const ByteArray& inSig)
{
    if (inSig.size() != AESCMAC_OUTPUT_LENGTH)
        return false;
    if (key.empty())
        throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED, "No signature key.");
    ByteArray signature;
    aesCmacSign(key, data, signature);
    assert(signature.size() == AESCMAC_OUTPUT_LENGTH);
    return safeMemEqual(&inSig[0], &signature[0], inSig.size());
}

}}} // namespace netflix::msl::crypto


