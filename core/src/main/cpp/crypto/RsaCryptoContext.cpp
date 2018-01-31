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

#include <crypto/RsaCryptoContext.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslInternalException.h>
#include <crypto/Key.h>
#include <crypto/MslCiphertextEnvelope.h>
#include <crypto/MslSignatureEnvelope.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

const string RSAPKCS1 = "RSA/ECB/PKCS1Padding";
const string RSAOAEP = "RSA/ECB/OAEPPadding";
const string SHA256RSA = "SHA256withRSA";

static const string NULL_OP = "nullOp";

} // namespace anonymous

RsaCryptoContext::RsaCryptoContext(shared_ptr<MslContext>, const string& id,
    const PrivateKey& privateKey, const PublicKey& publicKey, const Mode& mode)
: id(id)
, privateKey(privateKey)
, publicKey(publicKey)
{
	if (mode == Mode::ENCRYPT_DECRYPT_PKCS1) {
		transform = RSAPKCS1;
	} else if (mode == Mode::ENCRYPT_DECRYPT_OAEP) {
		transform = RSAOAEP;
	} else {
		transform = NULL_OP;
	}
	algo = (mode == Mode::SIGN_VERIFY) ? SHA256RSA : NULL_OP;
	if (mode == Mode::WRAP_UNWRAP)
        throw MslInternalException("Wrap/unwrap unsupported.");

    // As an optimization, convert any incoming key into their OpenSSL EVP_PKEY version
    if (!privateKey.isNull() && privateKey.getFormat() == PrivateKey::DEFAULT_FORMAT)
        privateKeyEvp = RsaEvpKey::fromPkcs8(privateKey.getEncoded());
    if (!publicKey.isNull() && publicKey.getFormat() == PublicKey::DEFAULT_FORMAT)
        publicKeyEvp = RsaEvpKey::fromSpki(publicKey.getEncoded());
}

shared_ptr<ByteArray> RsaCryptoContext::encrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
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

std::shared_ptr<ByteArray> RsaCryptoContext::decrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder)
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

shared_ptr<ByteArray> RsaCryptoContext::wrap(shared_ptr<ByteArray>, shared_ptr<MslEncoderFactory>, const MslEncoderFormat&)
{
    throw MslCryptoException(MslError::WRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> RsaCryptoContext::unwrap(shared_ptr<ByteArray>, shared_ptr<MslEncoderFactory>)
{
    throw MslCryptoException(MslError::UNWRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> RsaCryptoContext::sign(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
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

bool RsaCryptoContext::verify(shared_ptr<ByteArray> data, shared_ptr<ByteArray> signature, shared_ptr<MslEncoderFactory> encoder)
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

}}} // namespace netflic::msl::crypto
