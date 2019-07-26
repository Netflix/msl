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

#include <crypto/OpenSslLib.h>
#include <crypto/opensslImpl/util.h>
#include <MslCryptoException.h>
#include <MslError.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cassert>

namespace netflix {
namespace msl {
namespace crypto {

// FIXME: Should we use the EVP interface instead?

namespace
{

const int SHA256_OUTPUT_LENGTH = 32;

void computeHmac(const std::string& shaAlg, const ByteArray& key, const ByteArray& data,
        ByteArray& signature)
{
    OpenSslErrStackTracer errTracer;

    // There are no restrictions on the key length, it just has to exist
    if (key.empty())
        throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "No signature key.");

    // Hard-code to use SHA-256 digest
    const EVP_MD* digestAlgo = evp_md(shaAlg);
    if (!digestAlgo)
        throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "Unsupported algorithm.");

    // Allocate the max possible space for the result, to ensure no overflow
    // even if there is a bug.
    const size_t expectedLength = static_cast<size_t>(EVP_MD_size(digestAlgo));
    ByteArray result(EVP_MAX_MD_SIZE);

    // Compute the HMAC
    unsigned int actualLength;
    const unsigned char* const success =
        HMAC(digestAlgo, &key[0], (int)key.size(), &data[0], data.size(), &result[0],
            &actualLength);
    if (!success || (actualLength != expectedLength)) {
        std::stringstream ss;
        ss << "EVP_CipherUpdate failed: " << getOpenSSLErrorString();
        throw MslCryptoException(MslError::CRYPTO_ERROR, ss.str());
    }
    result.resize(actualLength);
    signature.swap(result);
}

} // namespace anonymous

void hmacSha(const std::string& shaAlg, const ByteArray& key, const ByteArray& data, ByteArray& sig)
{
    computeHmac(shaAlg, key, data, sig);
}

void signHmacSha256(const ByteArray& key, const ByteArray& data, ByteArray& sig)
{
    computeHmac("SHA256", key, data, sig);
}

bool verifyHmacSha256(const ByteArray& key, const ByteArray& data, const ByteArray& inSig)
{
    if (inSig.size() != SHA256_OUTPUT_LENGTH)
        return false;
    if (key.empty())
        throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED, "No signature key.");
    ByteArray signature;
    computeHmac("SHA256", key, data, signature);
    assert(signature.size() == SHA256_OUTPUT_LENGTH);
    return safeMemEqual(&inSig[0], &signature[0], inSig.size());
}

}}} // namespace netflix::msl::crypto


