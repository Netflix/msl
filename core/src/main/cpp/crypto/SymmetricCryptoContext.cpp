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

#include <crypto/IRandom.h>
#include <crypto/SymmetricCryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/MslCiphertextEnvelope.h>
#include <crypto/MslSignatureEnvelope.h>
#include <crypto/OpenSslLib.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <IllegalArgumentException.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <util/MslContext.h>
#include <sstream>

using netflix::msl::io::MslEncoderException;
using netflix::msl::io::MslObject;

using namespace std;

namespace netflix {
namespace msl {
namespace crypto {

namespace {
/** AES encryption initial value size in bytes. */
const int AES_IV_SIZE = 16;
/** Key wrap initial value. */
const ByteArray AESKW_AIV;
} // namespace anonymous

SymmetricCryptoContext::SymmetricCryptoContext(shared_ptr<util::MslContext> ctx,
        const string& id, const SecretKey& encryptionKey,
        const SecretKey& signatureKey, const SecretKey& wrappingKey)
    : ctx_(ctx), id_(id), encryptionKey_(encryptionKey), signatureKey_(signatureKey),
      wrappingKey_(wrappingKey)
{
    if (!encryptionKey.isNull() && encryptionKey.getAlgorithm() != JcaAlgorithm::AES)
        throw IllegalArgumentException("Encryption key must be an " + JcaAlgorithm::AES + " key.");
    if (!signatureKey.isNull() &&
        signatureKey.getAlgorithm() != JcaAlgorithm::HMAC_SHA256 &&
        signatureKey.getAlgorithm() != JcaAlgorithm::AES_CMAC )
    {
        throw IllegalArgumentException("Signature key must be an " + JcaAlgorithm::HMAC_SHA256 + " or " + JcaAlgorithm::AES_CMAC + " key.");
    }
    if (!wrappingKey.isNull() && wrappingKey.getAlgorithm() != JcaAlgorithm::AESKW)
        throw IllegalArgumentException("Wrapping key must be an " + JcaAlgorithm::AESKW + " key.");

    // key size checks
    if (!encryptionKey.isNull() && (encryptionKey.size() != 16 &&
        encryptionKey.size() != 24 && encryptionKey.size() != 32) )
    {
        throw IllegalArgumentException("Encryption key must be 16, 24, or 32 bytes only.");
    }
    if (!wrappingKey_.isNull() && (wrappingKey_.size() != 16 &&
         wrappingKey_.size() != 24 && wrappingKey_.size() != 32) )
    {
        throw IllegalArgumentException("Wrapping key must be 16, 24, or 32 bytes only.");
    }
    // FIXME: also check signature key size. HMAC key can be any size, CMAC key must be 16
}

std::shared_ptr<ByteArray> SymmetricCryptoContext::encrypt(std::shared_ptr<ByteArray> data,
        std::shared_ptr<io::MslEncoderFactory> encoder,
        const io::MslEncoderFormat& format)
{
    if (encryptionKey_.isNull())
        throw MslCryptoException(MslError::ENCRYPT_NOT_SUPPORTED, "no encryption/decryption key");

    // Generate random IV.
    shared_ptr<IRandom> random = ctx_->getRandom();
    shared_ptr<ByteArray> iv = make_shared<ByteArray>(AES_IV_SIZE);
    random->nextBytes(*iv);

    // Encrypt.
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
    aesCbcEncrypt(*encryptionKey_.getEncoded(), *iv, *data, *ciphertext);

    // Wrap in V1 envelope.
    MslCiphertextEnvelope envelope(id_, iv, ciphertext);

    // Return encoding of envelope.
    return envelope.toMslEncoding(encoder, format);
}

std::shared_ptr<ByteArray> SymmetricCryptoContext::decrypt(std::shared_ptr<ByteArray> data,
        std::shared_ptr<io::MslEncoderFactory> encoder)
{
    if (encryptionKey_.isNull())
        throw MslCryptoException(MslError::DECRYPT_NOT_SUPPORTED, "no encryption/decryption key");

    try {
        // Reconstitute encryption envelope.
        shared_ptr<MslObject> encryptionEnvelopeMo = encoder->parseObject(data);
        const MslCiphertextEnvelope encryptionEnvelope =
            createMslCiphertextEnvelope(encryptionEnvelopeMo, MslCiphertextEnvelope::Version::V1);

        // Get ciphertext and IV.
        shared_ptr<ByteArray> ciphertext = encryptionEnvelope.getCiphertext();
        if (ciphertext->size() == 0)
            throw MslCryptoException(MslError::INSUFFICIENT_CIPHERTEXT);
        shared_ptr<ByteArray> iv = encryptionEnvelope.getIv();

        // Decrypt.
        shared_ptr<ByteArray> result = make_shared<ByteArray>();
        aesCbcDecrypt(*encryptionKey_.getEncoded(), *iv, *ciphertext, *result);
        return result;
    } catch (const io::MslEncoderException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
    } catch (const MslEncodingException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
    }
}

std::shared_ptr<ByteArray> SymmetricCryptoContext::wrap(std::shared_ptr<ByteArray> data,
        shared_ptr<io::MslEncoderFactory>, // unused
        const io::MslEncoderFormat&) // unused
{
    if (wrappingKey_.isNull())
        throw MslCryptoException(MslError::WRAP_NOT_SUPPORTED, "no wrap/unwrap key");
    if (data->size() < 8 || (data->size() % 8 != 0)) {
        stringstream ss;
        ss << "data.length " << data->size();
        throw MslCryptoException(MslError::PLAINTEXT_ILLEGAL_BLOCK_SIZE, ss.str());
    }
    shared_ptr<ByteArray> result = make_shared<ByteArray>();
    aesKwWrap(*wrappingKey_.getEncoded(), *data, *result);
    return result;
}

std::shared_ptr<ByteArray> SymmetricCryptoContext::unwrap(std::shared_ptr<ByteArray> data,
        shared_ptr<io::MslEncoderFactory>) // unused
{
    if (wrappingKey_.isNull())
        throw MslCryptoException(MslError::UNWRAP_NOT_SUPPORTED, "no wrap/unwrap key");
    if (data->size() % 8 != 0) {
        stringstream ss;
        ss << "data.length " << data->size();
        throw MslCryptoException(MslError::CIPHERTEXT_ILLEGAL_BLOCK_SIZE, ss.str());
    }
    shared_ptr<ByteArray> result = make_shared<ByteArray>();
    aesKwUnwrap(*wrappingKey_.getEncoded(), *data, *result);
    return result;
}

std::shared_ptr<ByteArray> SymmetricCryptoContext::sign(std::shared_ptr<ByteArray> data,
        std::shared_ptr<io::MslEncoderFactory> encoder,
        const io::MslEncoderFormat& format)
{
    if (signatureKey_.isNull())
        throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "No signature key.");
    try {
        // Compute the xMac.
        shared_ptr<ByteArray> xmac = make_shared<ByteArray>();
        if (signatureKey_.getAlgorithm() == JcaAlgorithm::HMAC_SHA256) {
            signHmacSha256(*signatureKey_.getEncoded(), *data, *xmac);
        } else if (signatureKey_.getAlgorithm() == JcaAlgorithm::AES_CMAC) {
            signAesCmac(*signatureKey_.getEncoded(), *data, *xmac);
        } else {
            throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "Unsupported algorithm.");
        }

        // Return the signature envelope byte representation.
        return MslSignatureEnvelope(xmac).getBytes(encoder, format);
    } catch (const MslEncoderException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_ENCODE_ERROR, e);
    }
}

bool SymmetricCryptoContext::verify(std::shared_ptr<ByteArray> data,
        std::shared_ptr<ByteArray> signature,
        std::shared_ptr<io::MslEncoderFactory> encoder)
{
    if (signatureKey_.isNull())
        throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED, "No signature key.");
    try {
        // Reconstitute the signature envelope.
        const MslSignatureEnvelope envelope = MslSignatureEnvelope::parse(signature, encoder);

        // Verify the xMac.
        if (signatureKey_.getAlgorithm() == JcaAlgorithm::HMAC_SHA256) {
            return verifyHmacSha256(*signatureKey_.getEncoded(), *data, *envelope.getSignature());
        } else if (signatureKey_.getAlgorithm() == JcaAlgorithm::AES_CMAC) {
            return verifyAesCmac(*signatureKey_.getEncoded(), *data, *envelope.getSignature());
        } else {
            throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED, "Unsupported algorithm.");
        }
    } catch (const MslEncodingException& e) {
        throw MslCryptoException(MslError::SIGNATURE_ENVELOPE_PARSE_ERROR, e);
    }
}

}}} // namespace netflix::msl::crypto
