/**
 * Copyright (c) 2013-2016 Netflix, Inc.  All rights reserved.
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
#include <crypto/JsonWebEncryptionCryptoContext.h>
#include <crypto/JcaAlgorithm.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderUtils.h>

#include <cstring>
#include <string>

using namespace std;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {
    /** Encoding charset. */
    const Charset UTF_8 = Charset.forName("UTF-8");

    /** JSON key recipients. */
    const std::string KEY_RECIPIENTS = "recipients";
    /** JSON key header. */
    const std::string KEY_HEADER = "header";
    /** JSON key encrypted key. */
    const std::string KEY_ENCRYPTED_KEY = "encrypted_key";
    /** JSON key integrity value. */
    const std::string KEY_INTEGRITY_VALUE = "integrity_value";
    /** JSON key initialization vector. */
    const std::string KEY_INITIALIZATION_VECTOR = "initialization_vector";
    /** JSON key ciphertext. */
    const std::string KEY_CIPHERTEXT = "ciphertext";

    /** JSON key wrap algorithm. */
    const std::string KEY_ALGORITHM = "alg";
    /** JSON key encryption algorithm. */
    const std::string KEY_ENCRYPTION = "enc";

    /** AES-128 GCM authentication tag length in bits. */
    const uint8_t A128_GCM_AT_LENGTH = 128;
    /** AES-128 GCM key length in bytes. */
    const uint8_t A128_GCM_KEY_LENGTH = 16;
    /** AES-128 GCM initialization vector length in bytes. */
    const uint8_t A128_GCM_IV_LENGTH = 12;

    /** AES-256 GCM authentication tag length in bits. */
    const uint8_t A256_GCM_AT_LENGTH = 128;
    /** AES-256 GCM key length in bytes. */
    const uint8_t A256_GCM_KEY_LENGTH = 32;
    /** AES-256 GCM initialization vector length in bytes. */
    const uint8_t A256_GCM_IV_LENGTH = 12;

    /** RSA-OAEP cipher transform. */
    const std::string RSA_OAEP_TRANSFORM = "RSA/ECB/OAEPPadding";
    /** AES key wrap cipher transform. */
    const std::string A128_KW_TRANSFORM = "AESWrap";

    /** Byte size in bits. */
    const uint8_t BYTE_SIZE = 8;
} // namespace anonymous

// ---- Algorithm
const JsonWebEncryptionCryptoContext::Algorithm JsonWebEncryptionCryptoContext::Algorithm::RSA_OAEP(Algorithm::rsa_oaep, "RSA-OAEP");
const JsonWebEncryptionCryptoContext::Algorithm JsonWebEncryptionCryptoContext::Algorithm::A128KW(Algorithm::a128kw, "AES128KW");

// --- Encryption
const JsonWebEncryptionCryptoContext::Encryption JsonWebEncryptionCryptoContext::Encryption::A128GCM(Encryption::a128gcm, "A128GCM");
const JsonWebEncryptionCryptoContext::Encryption JsonWebEncryptionCryptoContext::Encryption::A256GCM(Encryption::a256gcm, "A256GCM");

shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::RsaOaepCryptoContext::encrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
{
	if (publicKey.isNull())
		throw MslCryptoException(MslError::ENCRYPT_NOT_SUPPORTED, "no public key");

	// try {
	// FIXME: Encrypt plaintext.
//    final Cipher cipher = CryptoCache.getCipher(RSA_OAEP_TRANSFORM);
//    cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEPParameterSpec.DEFAULT);
//    return cipher.doFinal(data);
	/*
	} catch (final NoSuchPaddingException e) {
		throw new MslInternalException("Unsupported padding exception.", e);
	} catch (final NoSuchAlgorithmException e) {
		throw new MslInternalException("Invalid cipher algorithm specified.", e);
	} catch (final InvalidKeyException e) {
		throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, e);
	} catch (final IllegalBlockSizeException e) {
		throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
	} catch (final BadPaddingException e) {
		throw new MslCryptoException(MslError.PLAINTEXT_BAD_PADDING, "not expected when encrypting", e);
	} catch (final InvalidAlgorithmParameterException e) {
		throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
	}*/
}

shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::RsaOaepCryptoContext::decrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder)
{
	if (privateKey.isNull())
		throw MslCryptoException(MslError::DECRYPT_NOT_SUPPORTED, "no private key");

	// try {
	// FIXME: Decrypt ciphertext.
//    final Cipher cipher = CryptoCache.getCipher(RSA_OAEP_TRANSFORM);
//    cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEPParameterSpec.DEFAULT);
//    return cipher.doFinal(data);
	/*
            } catch (final NoSuchPaddingException e) {
                reset = e;
                throw new MslInternalException("Unsupported padding exception.", e);
            } catch (final NoSuchAlgorithmException e) {
                reset = e;
                throw new MslInternalException("Invalid cipher algorithm specified.", e);
            } catch (final InvalidKeyException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_PRIVATE_KEY, e);
            } catch (final IllegalBlockSizeException e) {
                reset = e;
                throw new MslCryptoException(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE, e);
            } catch (final BadPaddingException e) {
                reset = e;
                throw new MslCryptoException(MslError.CIPHERTEXT_BAD_PADDING, e);
            } catch (final InvalidAlgorithmParameterException e) {
                reset = e;
                throw new MslCryptoException(MslError.INVALID_ALGORITHM_PARAMS, e);
            }
	 */
}

/**
 * Create a new AES key wrap crypto context with the provided secret
 * key.
 *
 * @param key AES secret key.
 */
JsonWebEncryptionCryptoContext::AesKwCryptoContext::AesKwCryptoContext(const SecretKey& key)
	: CekCryptoContext(Algorithm::A128KW)
	, key(key)
	, cryptoContext(cryptoContext)
{
	if (!key.getAlgorithm() == JcaAlgorithm::AESKW)
		throw IllegalArgumentException("Secret key must be an " + JcaAlgorithm::AESKW + " key.");
}

shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::AesKwCryptoContext::encrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
{
	// If a secret key is provided use it.
	if (!key.isNull()) {
		//                try {
		// FIXME:: Encrypt plaintext.
		//                    final Cipher cipher = CryptoCache.getCipher(A128_KW_TRANSFORM);
		//                    cipher.init(Cipher.WRAP_MODE, key);
		// TODO: The key spec algorithm should be based on the JWE
		// encryption algorithm. Right now that is always AES-GCM.
		//                    final Key secretKey = new SecretKeySpec(data, "AES");
		//                    return cipher.wrap(secretKey);
		/*
                } catch (final NoSuchPaddingException e) {
                    throw new MslInternalException("Unsupported padding exception.", e);
                } catch (final NoSuchAlgorithmException e) {
                    throw new MslInternalException("Invalid cipher algorithm specified.", e);
                } catch (final IllegalArgumentException e) {
                    throw new MslInternalException("Invalid content encryption key provided.", e);
                } catch (final InvalidKeyException e) {
                    throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
                } catch (final IllegalBlockSizeException e) {
                    throw new MslCryptoException(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE, "not expected when padding is specified", e);
                }
		 */
	}

	// Otherwise use the backing crypto context.
	return cryptoContext->wrap(data, encoder, format);
}

shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::AesKwCryptoContext::decrypt(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder)
{
	// If a secret key is provided use it.
	if (!key.isNull()) {
		//		try {
		// FIXME: Decrypt ciphertext.
		//			final Cipher cipher = CryptoCache.getCipher(A128_KW_TRANSFORM);
		//			cipher.init(Cipher.UNWRAP_MODE, key);
		//			return cipher.unwrap(data, "AES", Cipher.SECRET_KEY).getEncoded();
		/*
		} catch (final NoSuchPaddingException e) {
			throw new MslInternalException("Unsupported padding exception.", e);
		} catch (final NoSuchAlgorithmException e) {
			throw new MslInternalException("Invalid cipher algorithm specified.", e);
		} catch (final InvalidKeyException e) {
			throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
		}
		 */
	}

	// Otherwise use the backing crypto context.
	return cryptoContext->unwrap(data, encoder);
}

shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::wrap(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format)
{
	// Create the header.
	shared_ptr<ByteArray> header;
	try {
		shared_ptr<MslObject> headerMo = encoder->createObject();
		headerMo->put(KEY_ALGORITHM, algo.toString());
		headerMo->put(KEY_ENCRYPTION, enc.name());
		header = encoder->encodeObject(headerMo, MslEncoderFormat::JSON);
	} catch (const MslEncoderException& e) {
		throw MslCryptoException(MslError::JWE_ENCODE_ERROR, e);
	}

	// Determine algorithm byte lengths.
	uint8_t keylen, ivlen, atlen;
	if (Encryption::A128GCM == enc) {
		keylen = A128_GCM_KEY_LENGTH;
		ivlen = A128_GCM_IV_LENGTH;
		atlen = A128_GCM_AT_LENGTH;
	} else if (Encryption::A256GCM == enc) {
		keylen = A256_GCM_KEY_LENGTH;
		ivlen = A256_GCM_IV_LENGTH;
		atlen = A256_GCM_AT_LENGTH;
	} else {
		throw new MslCryptoException(MslError::UNSUPPORTED_JWE_ALGORITHM, enc.name());
	}

	// Generate the key and IV.
	shared_ptr<IRandom> random = ctx->getRandom();
	shared_ptr<ByteArray> cek = make_shared<ByteArray>(keylen);
	random->nextBytes(*cek);
	shared_ptr<ByteArray> iv = make_shared<ByteArray>(ivlen);
	random->nextBytes(*iv);

	// Encrypt the CEK.
	shared_ptr<ByteArray> ecek = cekCryptoContext->encrypt(cek, encoder, MslEncoderFormat::JSON);

	// Base64-encode the data.
	const string headerB64 = MslEncoderUtils::b64urlEncode(header);
	const string ecekB64 = MslEncoderUtils::b64urlEncode(ecek);
	const string ivB64 = MslEncoderUtils::b64urlEncode(iv);

	// Create additional authenticated data.
	stringstream aadss;
	aadss << headerB64 << "." << ecekB64 << "." << ivB64;
	const string aad = aadss.str();

	// TODO: AES-GCM is not available via the JCE.
	//
	// Create and initialize the cipher for encryption.
	//        final GCMBlockCipher plaintextCipher = new GCMBlockCipher(new AESEngine());
	//        final AEADParameters params = new AEADParameters(cek, atlen, iv, aad.getBytes(UTF_8));
	//        plaintextCipher.init(true, params);

	// Encrypt the plaintext.
	shared_ptr<ByteArray> ciphertextATag;
	//        try {
	//            const uint8_t clen = plaintextCipher.getOutputSize(data.length);
	//            ciphertextATag = make_shared<ByteArray>(clen);
	//            // Encrypt the plaintext and get the resulting ciphertext length
	//            // which will be used for the authentication tag offset.
	//            const uint8_t offset = plaintextCipher.processBytes(data, 0, data.length, ciphertextATag, 0);
	//            // Append the authentication tag.
	//            plaintextCipher.doFinal(ciphertextATag, offset);
	//        } catch (final IllegalStateException e) {
	//            throw new MslCryptoException(MslError.WRAP_ERROR, e);
	//        } catch (final InvalidCipherTextException e) {
	//            throw new MslInternalException("Invalid ciphertext not expected when encrypting.", e);
	//        }

	// Split the result into the ciphertext and authentication tag.
	shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>(ciphertextATag->begin(), ciphertextATag->end() - atlen/BYTE_SIZE);
	shared_ptr<ByteArray> at = make_shared<ByteArray>(ciphertextATag->begin() + ciphertext->size(), ciphertextATag->end());

	// Base64-encode the ciphertext and authentication tag.
	const string ciphertextB64 = MslEncoderUtils::b64urlEncode(ciphertext);
	const string atB64 = MslEncoderUtils::b64urlEncode(at);

	// Envelope the data.
	switch (this->format) {
	case JWE_CS:
	{
		const stringstream serializationss;
		serializationss << aad << "." << ciphertextB64 << "." << atB64;
		const string serialization = serializationss.str();
		return make_shared<ByteArray>(serialization.begin(), serialization.end());
	}
	case JWE_JS:
	{
		try {
			// Create recipients array.
			shared_ptr<MslArray> recipients = encoder->createArray();
			shared_ptr<MslObject> recipient = encoder->createObject();
			recipient->put(KEY_HEADER, headerB64);
			recipient->put(KEY_ENCRYPTED_KEY, ecekB64);
			recipient->put(KEY_INTEGRITY_VALUE, atB64);
			recipients->put(-1, recipient);

			// Create JSON serialization.
			shared_ptr<MslObject> serialization = encoder->createObject();
			serialization->put(KEY_RECIPIENTS, recipients);
			serialization->put(KEY_INITIALIZATION_VECTOR, ivB64);
			serialization->put(KEY_CIPHERTEXT, ciphertextB64);
			return encoder->encodeObject(serialization, MslEncoderFormat::JSON);
		} catch (const MslEncoderException& e) {
			throw MslCryptoException(MslError::JWE_ENCODE_ERROR, e);
		}
	}
	default:
		throw MslCryptoException(MslError::UNSUPPORTED_JWE_SERIALIZATION, format.name());
	}
}

virtual shared_ptr<ByteArray> JsonWebEncryptionCryptoContext::unwrap(shared_ptr<ByteArray> data, shared_ptr<MslEncoderFactory> encoder)
{
	// Parse the serialization.
	const string serialization(data->begin(), data->end());
	string headerB64, ecekB64, ivB64;
	shared_ptr<ByteArray> ciphertext, at;
	if (data[0] == '{') {
		try {
			shared_ptr<MslObject> serializationMo = encoder->parseObject(data);
			ivB64 = serializationMo->getString(KEY_INITIALIZATION_VECTOR);
			ciphertext = MslEncoderUtils::b64urlDecode(make_shared<string>(serializationMo->getString(KEY_CIPHERTEXT)));

			// TODO: For now, we only support one recipient.
			shared_ptr<MslArray> recipients = serializationMo->getMslArray(KEY_RECIPIENTS);
			if (recipients->size() < 1)
				throw MslCryptoException(MslError::JWE_PARSE_ERROR, serialization);
			shared_ptr<MslObject> recipient = recipients->getMslObject(0, encoder);
			headerB64 = recipient->getString(KEY_HEADER);
			ecekB64 = recipient->getString(KEY_ENCRYPTED_KEY);
			at = MslEncoderUtils::b64urlDecode(make_shared<string>(recipient->getString(KEY_INTEGRITY_VALUE)));
		} catch (const MslEncoderException& e) {
			throw MslCryptoException(MslError::JWE_PARSE_ERROR, serialization, e);
		}
	} else {
		// Separate the compact serialization.
		const vector<string> parts;
		char *serialization_cstr = serialization.c_str();
		char *part = strtok(serialization_cstr, ".");
		while (part != NULL) {
			parts.push_back(string(part));
			part = strtok(NULL, ".");
		}
		if (parts.size() != 5)
			throw MslCryptoException(MslError::JWE_PARSE_ERROR, serialization);

		// Extract the data from the serialization.
		headerB64 = parts[0];
		ecekB64 = parts[1];
		ivB64 = parts[2];
		ciphertext = MslEncoderUtils::b64urlDecode(make_shared<string>(parts[3]));
		at = MslEncoderUtils::b64urlDecode(make_shared<string>(parts[4]));
	}

	// Decode header, encrypted content encryption key, and IV.
	const shared_ptr<ByteArray> headerBytes = MslEncoderUtils::b64urlDecode(make_shared<string>(headerB64));
	const shared_ptr<ByteArray> ecek = MslEncoderUtils::b64urlDecode(make_shared<string>(ecekB64));
	const shared_ptr<ByteArray> iv = MslEncoderUtils::b64urlDecode(make_shared<string>(ivB64));

	// Verify data.
	if (!headerBytes || headerBytes->size() == 0 ||
			!ecek || ecek->size() == 0 ||
			!iv || iv->size() == 0 ||
			!ciphertext || ciphertext->size() == 0 ||
			!at || at->size() == 0)
	{
		throw MslCryptoException(MslError::JWE_PARSE_ERROR, serialization);
	}

	// Reconstruct and parse the header.
	const string header(headerBytes->begin(), headerBytes->end());
	Algorithm algo;
	Encryption enc;
	try {
		shared_ptr<MslObject> headerMo = encoder->parseObject(headerBytes);
		const string algoName = headerMo->getString(KEY_ALGORITHM);
		try {
			algo = Algorithm::fromString(algoName);
		} catch (const IllegalArgumentException& e) {
			throw MslCryptoException(MslError::JWE_PARSE_ERROR, algoName, e);
		}
		const string encName = headerMo->getString(KEY_ENCRYPTION);
		try {
			enc = Encryption::fromString(encName);
		} catch (const IllegalArgumentException& e) {
			throw MslCryptoException(MslError::JWE_PARSE_ERROR, encName, e);
		}
	} catch (const MslEncoderException& e) {
		throw MslCryptoException(MslError::JWE_PARSE_ERROR, header, e);
	}

	// Confirm header matches.
	if (this->algo != algo || this->enc != enc)
		throw MslCryptoException(MslError::JWE_ALGORITHM_MISMATCH, header);

	// Decrypt the CEK.
	//        final KeyParameter cek;
	//        try {
	shared_ptr<ByteArray> cekBytes = cekCryptoContext->decrypt(ecek, encoder);
	//            cek = new KeyParameter(cekBytes);
	//        } catch (final ArrayIndexOutOfBoundsException e) {
	// Thrown if the encrypted content encryption key is an invalid
	// length.
	//            throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, e);
	//        }

	// Create additional authenticated data.
	stringstream aadss;
	aadss << headerB64 << "." << ecekB64 << "." << ivB64;
	const string aad = aadss.str();

	// Determine algorithm byte lengths.
	uint8_t keylen, atlen;
	if (Encryption::A128GCM == enc) {
		keylen = A128_GCM_KEY_LENGTH;
		atlen = A128_GCM_AT_LENGTH;
	} else if (Encryption::A256GCM == enc) {
		keylen = A256_GCM_KEY_LENGTH;
		atlen = A256_GCM_AT_LENGTH;
	} else {
		throw new MslCryptoException(MslError::UNSUPPORTED_JWE_ALGORITHM, enc.name());
	}

	// Verify algorithm parameters.
	//        if (cek.getKey().length != keylen)
	//            throw MslCryptoException(MslError::INVALID_SYMMETRIC_KEY, "content encryption key length: " + cek.getKey().length);
	//        if (at.length != atlen / BYTE_SIZE)
	//            throw MslCryptoException(MslError::INVALID_ALGORITHM_PARAMS, "authentication tag length: " + at->size());

	// TODO: AES-GCM is not available via the JCE.
	//
	// Create and initialize the cipher for decryption.
	//        final GCMBlockCipher plaintextCipher = new GCMBlockCipher(new AESEngine());
	//        final AEADParameters params = new AEADParameters(cek, atlen, iv, aad.getBytes(UTF_8));
	//        plaintextCipher.init(false, params);

	// Decrypt the ciphertext.
	//        try {
	// Reconstruct the ciphertext and authentication tag.
	const shared_ptr<ByteArray> ciphertextAtag(ciphertext->begin(), ciphertext->end());
	ciphertextAtag->insert(ciphertextAtag->end(), at->begin(), at->end());
	//            const uint8_t plen = plaintextCipher.getOutputSize(ciphertextAtag.length);
	//            shared_ptr<ByteArray> plaintext(plen);
	//            // Decrypt the ciphertext and get the resulting plaintext length
	//            // which will be used for the authentication tag offset.
	//            const uint8_t offset = plaintextCipher.processBytes(ciphertextAtag, 0, ciphertextAtag.length, plaintext, 0);
	//            // Verify the authentication tag.
	//            plaintextCipher.doFinal(plaintext, offset);
	return plaintext;
	//        } catch (final IllegalStateException e) {
	//            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
	//        } catch (final InvalidCipherTextException e) {
	//            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
	//        } catch (final ArrayIndexOutOfBoundsException e) {
	//            // Thrown if the ciphertext is an invalid length.
	//            throw new MslCryptoException(MslError.UNWRAP_ERROR, e);
	//        }
}
