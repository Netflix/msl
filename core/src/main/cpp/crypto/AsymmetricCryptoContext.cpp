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

#include <crypto/AsymmetricCryptoContext.h>
#include <crypto/Key.h>
#include <crypto/MslCiphertextEnvelope.h>
#include <crypto/MslSignatureEnvelope.h>
#include <crypto/OpenSslLib.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

const string RSAPKCS1 = "RSA/ECB/PKCS1Padding";
const string RSAOAEP = "RSA/ECB/OAEPPadding";
const string ECC = "ECIES";
const string SHA256RSA = "SHA256withRSA";
const string SHAECC = "SHA256withECDSA";

bool isValidEncryptDecryptAlgorithm(const string& alg)
{
    return alg == RSAPKCS1 || alg == RSAOAEP || alg == ECC || alg == AsymmetricCryptoContext::NULL_OP;
}

bool isValidSignVerifyAlgorithm(const string alg)
{
    return alg == SHA256RSA || alg == SHAECC || alg == AsymmetricCryptoContext::NULL_OP;
}

} // namespace anonymous

/** Null transform or algorithm. */
const string AsymmetricCryptoContext::NULL_OP = "nullOp";

AsymmetricCryptoContext::AsymmetricCryptoContext(const std::string& id, const PrivateKey& privateKey,
    const PublicKey& publicKey, const std::string& transform, const std::string& algo)
    : id(id)
    , privateKey(privateKey)
    , publicKey(publicKey)
    , transform(transform)
    , algo(algo)
{
    if (!isValidEncryptDecryptAlgorithm(transform) && !isValidSignVerifyAlgorithm(algo))
        throw MslInternalException("Invalid cipher algorithm specified.");
    // As an optimization, convert any incoming key into their OpenSSL EVP_PKEY version
    if (!privateKey.isNull() && privateKey.getFormat() == PrivateKey::DEFAULT_FORMAT)
        privateKeyEvp = RsaEvpKey::fromPkcs8(privateKey.getEncoded());
    if (!publicKey.isNull() && publicKey.getFormat() == PublicKey::DEFAULT_FORMAT)
        publicKeyEvp = RsaEvpKey::fromSpki(publicKey.getEncoded());
}

shared_ptr<ByteArray> AsymmetricCryptoContext::encrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
{
    const string& encryptAlg = transform; // I don't like the confusing member names
    if (encryptAlg == NULL_OP)
        return data;
    if (publicKey.isNull() || !publicKeyEvp)
        throw MslCryptoException(MslError::ENCRYPT_NOT_SUPPORTED, "no public key");
    if (publicKey.getFormat() != PublicKey::DEFAULT_FORMAT)
        throw MslCryptoException(MslError::ENCRYPT_ERROR, "bad key format");
    try {
    	shared_ptr<ByteArray> result = make_shared<ByteArray>();
        if (encryptAlg == RSAPKCS1) {
            rsaEncrypt(publicKeyEvp->getEvpPkey(), *data, false, *result);
        } else if (encryptAlg == RSAOAEP) {
            rsaEncrypt(publicKeyEvp->getEvpPkey(), *data, true, *result);
        } else {
            throw MslInternalException("Invalid cipher algorithm specified.");
        }
        // Return encryption envelope byte representation.
        const MslCiphertextEnvelope envelope(id, make_shared<ByteArray>(), result);
        return envelope.toMslEncoding(encoder, format);
    } catch (const MslEncoderException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_ENCODE_ERROR, e);
    }
}

std::shared_ptr<ByteArray> AsymmetricCryptoContext::decrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder)
{
    const string& encryptAlg = transform; // I don't like the confusing member names
    if (encryptAlg == NULL_OP)
        return data;
    if (privateKey.isNull() || !privateKeyEvp)
        throw MslCryptoException(MslError::DECRYPT_NOT_SUPPORTED, "no private key");
    try {
        // Reconstitute encryption envelope.
        shared_ptr<MslObject> encryptionEnvelopeMo = encoder->parseObject(data);
        const MslCiphertextEnvelope encryptionEnvelope =
                createMslCiphertextEnvelope(encryptionEnvelopeMo, MslCiphertextEnvelope::Version::V1);

        // Verify key ID.
        if (id != encryptionEnvelope.getKeyId())
            throw MslCryptoException(MslError::ENVELOPE_KEY_ID_MISMATCH);

        // Decrypt ciphertext.
        shared_ptr<ByteArray> result = make_shared<ByteArray>();
        if (encryptAlg == RSAPKCS1) {
            rsaDecrypt(privateKeyEvp->getEvpPkey(), *encryptionEnvelope.getCiphertext(), false, *result);
        } else if (encryptAlg == RSAOAEP) {
            rsaDecrypt(privateKeyEvp->getEvpPkey(), *encryptionEnvelope.getCiphertext(), true, *result);
        } else {
            throw MslInternalException("Invalid cipher algorithm specified.");
        }
        return result;
    } catch (const MslEncoderException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
    } catch (const MslEncodingException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
    }
}

shared_ptr<ByteArray> AsymmetricCryptoContext::wrap(shared_ptr<ByteArray>, shared_ptr<MslEncoderFactory>, const MslEncoderFormat&)
{
    throw MslCryptoException(MslError::WRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> AsymmetricCryptoContext::unwrap(shared_ptr<ByteArray>, shared_ptr<MslEncoderFactory>)
{
    throw MslCryptoException(MslError::UNWRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> AsymmetricCryptoContext::sign(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
{
    const string& signAlg = algo; // I don't like the confusing member names
    if (signAlg == NULL_OP)
    	return make_shared<ByteArray>();
    if (privateKey.isNull() || !privateKeyEvp)
        throw MslCryptoException(MslError::SIGN_NOT_SUPPORTED, "no private key.");
    try {
        shared_ptr<ByteArray> result = make_shared<ByteArray>();
        if (signAlg == SHA256RSA)
            rsaSign(privateKeyEvp->getEvpPkey(), *data, *result);
        else
            throw MslInternalException("Invalid cipher algorithm specified.");
        // Return the signature envelope byte representation.
        return MslSignatureEnvelope(result).getBytes(encoder, format);
    } catch (const MslEncoderException& e) {
        throw MslCryptoException(MslError::SIGNATURE_ENVELOPE_ENCODE_ERROR, e);
    }
}

bool AsymmetricCryptoContext::verify(shared_ptr<ByteArray> data, shared_ptr<ByteArray> signature, shared_ptr<MslEncoderFactory> encoder)
{
    const string& signAlg = algo; // I don't like the confusing member names
    if (signAlg == NULL_OP)
        return true;
    if (publicKey.isNull() || !publicKeyEvp)
        throw MslCryptoException(MslError::VERIFY_NOT_SUPPORTED, "no public key.");
    try {
        // Reconstitute the signature envelope.
        const MslSignatureEnvelope envelope = MslSignatureEnvelope::parse(signature, encoder);
        if (signAlg == SHA256RSA)
            return rsaVerify(publicKeyEvp->getEvpPkey(), *data, *envelope.getSignature());
        else
            throw MslInternalException("Invalid cipher algorithm specified.");
    } catch (const MslEncoderException& e) {
        throw MslCryptoException(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e);
    } catch (const MslEncodingException& e) {
        throw MslCryptoException(MslError::SIGNATURE_ENVELOPE_PARSE_ERROR, e);
    }
}

}}} // namespace netflix::msl::crypto
