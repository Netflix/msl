/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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

#include <keyx/AsymmetricWrappedExchange.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/IRandom.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/SessionCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <tokens/MasterToken.h>
#include <tokens/TokenFactory.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;
using Mechanism = netflix::msl::keyx::AsymmetricWrappedExchange::RequestData::Mechanism;
using RequestData = netflix::msl::keyx::AsymmetricWrappedExchange::RequestData;
using ResponseData = netflix::msl::keyx::AsymmetricWrappedExchange::ResponseData;
using KeyExchangeData = netflix::msl::keyx::KeyExchangeFactory::KeyExchangeData;

namespace netflix {
namespace msl {
namespace keyx {

namespace {
/** Key key pair ID. */
const string KEY_KEY_PAIR_ID = "keypairid";
/** Key mechanism. */
const string KEY_MECHANISM = "mechanism";
/** Key public key. */
const string KEY_PUBLIC_KEY = "publickey";
/** Key encrypted encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key encrypted HMAC key. */
const string KEY_HMAC_KEY = "hmackey";
} // namespace anonymous

// -------- AsymmetricWrappedExchange::RequestData::Mechanism -------- //

const Mechanism Mechanism::RSA(rsa, "RSA");
const Mechanism Mechanism::ECC(ecc, "ECC");
const Mechanism Mechanism::JWE_RSA(jwe_rsa, "JWE_RSA");
const Mechanism Mechanism::JWEJS_RSA(jwejs_rsa, "JWEJS_RSA");
const Mechanism Mechanism::JWK_RSA(jwk_rsa, "JWK_RSA");
const Mechanism Mechanism::JWK_RSAES(jwk_rsaes, "JWK_RSAES");
const Mechanism Mechanism::INVALID(invalid, "INVALID");

const vector<Mechanism>& Mechanism::getValues()
{
	static vector<Mechanism> values;
	if (values.empty()) {
		values.push_back(RSA);
		values.push_back(ECC);
		values.push_back(JWE_RSA);
		values.push_back(JWEJS_RSA);
		values.push_back(JWK_RSA);
		values.push_back(JWK_RSAES);
		values.push_back(INVALID);
	}
	return values;
}

// -------- AsymmetricWrappedExchange::RequestData -------- //

RequestData::RequestData(const string& keyPairId, const Mechanism& mechanism, const PublicKey& publicKey, const PrivateKey& privateKey)
	: KeyRequestData(KeyExchangeScheme::ASYMMETRIC_WRAPPED)
	, keyPairId_(keyPairId)
	, mechanism_(mechanism)
	, publicKey_(publicKey)
	, privateKey_(privateKey)
{}

RequestData::RequestData(shared_ptr<MslObject> keyRequestMo)
	: KeyRequestData(KeyExchangeScheme::ASYMMETRIC_WRAPPED)
{
	shared_ptr<ByteArray> encodedKey;
	try {
		keyPairId_ = keyRequestMo->getString(KEY_KEY_PAIR_ID);
		const string mechanismName = keyRequestMo->getString(KEY_MECHANISM);
		try {
			mechanism_ = Mechanism::fromString(mechanismName);
		} catch (const IllegalArgumentException e) {
			throw MslKeyExchangeException(MslError::UNIDENTIFIED_KEYX_MECHANISM, mechanismName, e);
		}
		encodedKey = keyRequestMo->getBytes(KEY_PUBLIC_KEY);
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "keydata " << keyRequestMo;
		throw new MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
	}

	// FIXME
//	switch (mechanism_) {
//	case Mechanism::RSA:
//	case Mechanism::JWE_RSA:
//	case Mechanism::JWEJS_RSA:
//	case Mechanism::JWK_RSA:
//	case Mechanism::JWK_RSAES:
//	case Mechanism::ECC:
//	default:
//  }
	throw MslCryptoException(MslError::UNSUPPORTED_KEYX_MECHANISM, mechanism_.name());
}

shared_ptr<MslObject> RequestData::getKeydata(shared_ptr<MslEncoderFactory> encoder, const io::MslEncoderFormat& /*format*/) const
{
	shared_ptr<MslObject> mo = encoder->createObject();
	mo->put(KEY_KEY_PAIR_ID, keyPairId_);
	mo->put(KEY_MECHANISM, mechanism_.name());
	mo->put(KEY_PUBLIC_KEY, publicKey_.getEncoded());
	return mo;
}

bool RequestData::equals(shared_ptr<const KeyRequestData> obj) const
{
	if (!obj) return false;
	if (this == obj.get()) return true;
	if (!instanceof<const RequestData>(obj)) return false;
	shared_ptr<const RequestData> that = dynamic_pointer_cast<const RequestData>(obj);
	// Private keys are optional but must be considered.
	const bool privateKeysEqual =
			privateKey_ == that->privateKey_ ||
			privateKey_.getEncoded() == that->privateKey_.getEncoded();
	return KeyRequestData::equals(that) &&
			keyPairId_ == that->keyPairId_ &&
			mechanism_ == that->mechanism_ &&
			publicKey_.getEncoded() == that->publicKey_.getEncoded() &&
			privateKeysEqual;
}

bool operator==(const RequestData& a, const RequestData& b)
{
	shared_ptr<const RequestData> ap(&a, &MslUtils::nullDeleter<RequestData>);
	shared_ptr<const RequestData> bp(&b, &MslUtils::nullDeleter<RequestData>);
	return ap->equals(bp);
}

ResponseData::ResponseData(shared_ptr<MasterToken> masterToken, const string& keyPairId, shared_ptr<ByteArray> encryptionKey, shared_ptr<ByteArray> hmacKey)
	: KeyResponseData(masterToken, KeyExchangeScheme::ASYMMETRIC_WRAPPED)
	, keyPairId_(keyPairId)
	, encryptionKey_(encryptionKey)
	, hmacKey_(hmacKey)
{}

ResponseData::ResponseData(shared_ptr<MasterToken> masterToken, shared_ptr<MslObject> keyDataMo)
	: KeyResponseData(masterToken, KeyExchangeScheme::ASYMMETRIC_WRAPPED)
{
	try {
		keyPairId_ = keyDataMo->getString(KEY_KEY_PAIR_ID);
		encryptionKey_ = keyDataMo->getBytes(KEY_ENCRYPTION_KEY);
		hmacKey_ = keyDataMo->getBytes(KEY_HMAC_KEY);
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "keydata " << keyDataMo;
		throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
	}
}

shared_ptr<MslObject> ResponseData::getKeydata(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& /*format*/) const
{
	shared_ptr<MslObject> mo = encoder->createObject();
	mo->put(KEY_KEY_PAIR_ID, keyPairId_);
	mo->put(KEY_ENCRYPTION_KEY, encryptionKey_);
	mo->put(KEY_HMAC_KEY, hmacKey_);
	return mo;
}

bool ResponseData::equals(shared_ptr<const KeyResponseData> obj) const
{
	if (!obj) return false;
	if (this == obj.get()) return true;
	if (!instanceof<const ResponseData>(obj)) return false;
	shared_ptr<const ResponseData> that = dynamic_pointer_cast<const ResponseData>(obj);
	return KeyResponseData::equals(that) &&
			keyPairId_ == that->keyPairId_ &&
			*encryptionKey_ == *that->encryptionKey_ &&
			*hmacKey_ == *that->hmacKey_;
}

bool operator==(const ResponseData& a, const ResponseData& b)
{
	shared_ptr<const ResponseData> ap(&a, &MslUtils::nullDeleter<ResponseData>);
	shared_ptr<const ResponseData> bp(&b, &MslUtils::nullDeleter<ResponseData>);
	return ap->equals(bp);
}

namespace {
/**
 * Create the crypto context identified by the key ID, mechanism, and
 * provided keys.
 *
 * @param ctx MSL context.
 * @param keyPairId the key pair ID.
 * @param mechanism the key mechanism.
 * @param privateKey the private key. May be null.
 * @param publicKey the public key. May be null.
 * @return the crypto context.
 * @throws MslCryptoException if the key mechanism is unsupported.
 */
shared_ptr<ICryptoContext> createCryptoContext(shared_ptr<MslContext> /*ctx*/, const string& /*keyPairId*/, const RequestData::Mechanism& mechanism, const PrivateKey& /*privateKey*/, const PublicKey& /*publicKey*/)
{
//	switch (mechanism) {
//	case Mechanism::JWE_RSA:
//	{
//		final CekCryptoContext cryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
//		return new JsonWebEncryptionCryptoContext(ctx, cryptoContext, JsonWebEncryptionCryptoContext.Encryption.A128GCM, Format.JWE_CS);
//	}
//	case Mechanism::JWEJS_RSA:
//	{
//		final CekCryptoContext cryptoContext = new JsonWebEncryptionCryptoContext.RsaOaepCryptoContext(privateKey, publicKey);
//		return new JsonWebEncryptionCryptoContext(ctx, cryptoContext, JsonWebEncryptionCryptoContext.Encryption.A128GCM, Format.JWE_JS);
//	}
//	case Mechanism::RSA:
//	case Mechanism::JWK_RSA:
//	{
//		return new RsaWrappingCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaWrappingCryptoContext.Mode.WRAP_UNWRAP_OAEP);
//	}
//	case Mechanism::JWK_RSAES:
//	{
//		return new RsaWrappingCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaWrappingCryptoContext.Mode.WRAP_UNWRAP_PKCS1);
//	}
//	default:
//  }
	throw new MslCryptoException(MslError::UNSUPPORTED_KEYX_MECHANISM, mechanism.name());
}
} // namespace anonymous

AsymmetricWrappedExchange::AsymmetricWrappedExchange(shared_ptr<AuthenticationUtils> authutils)
	: KeyExchangeFactory(KeyExchangeScheme::ASYMMETRIC_WRAPPED)
	, authutils_(authutils)
{}

shared_ptr<KeyRequestData> AsymmetricWrappedExchange::createRequestData(shared_ptr<MslContext> /*ctx*/, shared_ptr<MslObject> keyRequestMo)
{
	return make_shared<RequestData>(keyRequestMo);
}

shared_ptr<KeyResponseData> AsymmetricWrappedExchange::createResponseData(shared_ptr<MslContext> /*ctx*/, shared_ptr<MasterToken> masterToken, shared_ptr<MslObject> keyDataMo)
{
	return make_shared<ResponseData>(masterToken, keyDataMo);
}

shared_ptr<KeyExchangeData> AsymmetricWrappedExchange::generateResponse(shared_ptr<MslContext> ctx, const MslEncoderFormat& /*format*/, shared_ptr<KeyRequestData> keyRequestData, shared_ptr<MasterToken> masterToken)
{
	if (!instanceof<RequestData>(keyRequestData)) {
		const KeyRequestData& krd = *keyRequestData;
		throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
	}
	shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

	// If the master token was not issued by the local entity then we
	// should not be generating a key response for it.
	if (!masterToken->isVerified())
		throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);

	// Verify the scheme is permitted.
	const string identity = masterToken->getIdentity();
	if (!authutils_->isSchemePermitted(identity, getScheme())) {
		stringstream ss;
		ss << "Authentication scheme for entity not permitted " << identity << ":" << getScheme().name();
		throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, ss.str()).setMasterToken(masterToken);
	}

	// Create random AES-128 encryption and SHA-256 HMAC keys.
	shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
	shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
	ctx->getRandom()->nextBytes(*encryptionBytes);
	ctx->getRandom()->nextBytes(*hmacBytes);
	SecretKey encryptionKey, hmacKey;
	try {
		encryptionKey = SecretKey(encryptionBytes, JcaAlgorithm::AES);
		hmacKey = SecretKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);
	} catch (const IllegalArgumentException& e) {
		throw MslCryptoException(MslError::SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
	}

	// Wrap session keys with public key.
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	const string keyPairId = request->getKeyPairId();
	const RequestData::Mechanism mechanism = request->getMechanism();
	const PublicKey publicKey = request->getPublicKey();
	shared_ptr<ICryptoContext> wrapCryptoContext = createCryptoContext(ctx, keyPairId, mechanism, PrivateKey(), publicKey);
	shared_ptr<ByteArray> wrappedEncryptionKey, wrappedHmacKey;
//	switch (mechanism) {
//	case Mechanism::JWE_RSA:
//	case Mechanism::JWEJS_RSA:
//	{
//		final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
//		final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
//		final byte[] encryptionJwkBytes = encryptionJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		final byte[] hmacJwkBytes = hmacJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwkBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacJwkBytes, encoder, format);
//		break;
//	}
//	case Mechanism::JWK_RSA:
//	case Mechanism::JWK_RSAES:
//	{
//		final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
//		final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
//		final byte[] encryptionJwkBytes = encryptionJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		final byte[] hmacJwkBytes = hmacJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwkBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacJwkBytes, encoder, format);
//		break;
//	}
//	default:
//	{
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes, encoder, format);
//		break;
//	}
//	}

	// Create the master token.
	shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
	shared_ptr<MasterToken> newMasterToken = tokenFactory->renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, shared_ptr<MslObject>());

	// Create crypto context.
	shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, newMasterToken);

	// Return the key exchange data.
	shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(newMasterToken, request->getKeyPairId(), wrappedEncryptionKey, wrappedHmacKey);
	return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

shared_ptr<KeyExchangeData> AsymmetricWrappedExchange::generateResponse(shared_ptr<MslContext> ctx, const MslEncoderFormat& /*format*/, shared_ptr<KeyRequestData> keyRequestData, shared_ptr<EntityAuthenticationData> entityAuthData)
{
	if (!instanceof<RequestData>(keyRequestData)) {
		const KeyRequestData& krd = *keyRequestData;
		throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
	}
	shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

	// Verify the scheme is permitted.
	const string identity = entityAuthData->getIdentity();
	if (!authutils_->isSchemePermitted(identity, getScheme())) {
		stringstream ss;
		ss << "Authentication scheme for entity not permitted " << identity << ":" << getScheme().name();
		throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, ss.str()).setEntityAuthenticationData(entityAuthData);
	}

	// Create random AES-128 encryption and SHA-256 HMAC keys.
	shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
	shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
	ctx->getRandom()->nextBytes(*encryptionBytes);
	ctx->getRandom()->nextBytes(*hmacBytes);
	SecretKey encryptionKey, hmacKey;
	try {
		encryptionKey = SecretKey(encryptionBytes, JcaAlgorithm::AES);
		hmacKey = SecretKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);
	} catch (const IllegalArgumentException& e) {
		throw MslCryptoException(MslError::SESSION_KEY_CREATION_FAILURE, e).setEntityAuthenticationData(entityAuthData);
	}

	// Wrap session keys with public key.
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	const string keyPairId = request->getKeyPairId();
	const RequestData::Mechanism mechanism = request->getMechanism();
	const PublicKey publicKey = request->getPublicKey();
	shared_ptr<ICryptoContext> wrapCryptoContext = createCryptoContext(ctx, keyPairId, mechanism, PrivateKey(), publicKey);
	shared_ptr<ByteArray> wrappedEncryptionKey, wrappedHmacKey;
//	switch (mechanism) {
//	case Mechanism::JWE_RSA:
//	case Mechanism::JWEJS_RSA:
//	{
//		final JsonWebKey encryptionJwk = new JsonWebKey(Usage.enc, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
//		final JsonWebKey hmacJwk = new JsonWebKey(Usage.sig, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
//		final byte[] encryptionJwkBytes = encryptionJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		final byte[] hmacJwkBytes = hmacJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwkBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacJwkBytes, encoder, format);
//		break;
//	}
//	case Mechanism::JWK_RSA:
//	case Mechanism::JWK_RSAES:
//	{
//		final JsonWebKey encryptionJwk = new JsonWebKey(ENCRYPT_DECRYPT, JsonWebKey.Algorithm.A128CBC, false, null, encryptionKey);
//		final JsonWebKey hmacJwk = new JsonWebKey(SIGN_VERIFY, JsonWebKey.Algorithm.HS256, false, null, hmacKey);
//		final byte[] encryptionJwkBytes = encryptionJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		final byte[] hmacJwkBytes = hmacJwk.toMslEncoding(encoder, MslEncoderFormat.JSON);
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionJwkBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacJwkBytes, encoder, format);
//		break;
//	}
//	default:
//	{
//		wrappedEncryptionKey = wrapCryptoContext.wrap(encryptionBytes, encoder, format);
//		wrappedHmacKey = wrapCryptoContext.wrap(hmacBytes, encoder, format);
//		break;
//	}
//	}

	// Create the master token.
	shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
	shared_ptr<MasterToken> masterToken = tokenFactory->createMasterToken(ctx, entityAuthData, encryptionKey, hmacKey, shared_ptr<MslObject>());

	// Create crypto context.
	shared_ptr<ICryptoContext> cryptoContext;
	try {
		cryptoContext = make_shared<SessionCryptoContext>(ctx, masterToken);
	} catch (const MslMasterTokenException& e) {
		throw MslInternalException("Master token constructed by token factory is not trusted.", e);
	}

	// Return the key exchange data.
	shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(masterToken, request->getKeyPairId(), wrappedEncryptionKey, wrappedHmacKey);
	return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

shared_ptr<ICryptoContext> AsymmetricWrappedExchange::getCryptoContext(shared_ptr<MslContext> ctx, shared_ptr<KeyRequestData> keyRequestData, shared_ptr<KeyResponseData> keyResponseData, shared_ptr<MasterToken> /*masterToken*/)
{
	const KeyRequestData& krd = *keyRequestData;
	if (!instanceof<RequestData>(keyRequestData))
		throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
	shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);
	if (!instanceof<ResponseData>(keyResponseData))
		throw MslInternalException("Key response data " + string(typeid(krd).name()) + " was not created by this factory.");
	shared_ptr<ResponseData> response = dynamic_pointer_cast<ResponseData>(keyResponseData);

	// Verify response matches request.
	const string requestKeyPairId = request->getKeyPairId();
	const string responseKeyPairId = response->getKeyPairId();
	if (requestKeyPairId != responseKeyPairId)
		throw MslKeyExchangeException(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyPairId + "; response " + responseKeyPairId);

	// Unwrap session keys with identified key.
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	const PrivateKey privateKey = request->getPrivateKey();
	if (privateKey.isNull())
		throw MslKeyExchangeException(MslError::KEYX_PRIVATE_KEY_MISSING, "request Asymmetric private key");
	const RequestData::Mechanism mechanism = request->getMechanism();
	shared_ptr<ICryptoContext> unwrapCryptoContext = createCryptoContext(ctx, requestKeyPairId, mechanism, privateKey, PublicKey());
	SecretKey encryptionKey, hmacKey;
//	switch (mechanism) {
//	case Mechanism::JWE_RSA:
//	case Mechanism::JWEJS_RSA:
//	case Mechanism::JWK_RSA:
//	case Mechanism::JWK_RSAES:
//	{
//		Array encryptionJwkBytes = unwrapCryptoContext.unwrap(response.getEncryptionKey(), encoder);
//		final byte[] hmacJwkBytes = unwrapCryptoContext.unwrap(response.getHmacKey(), encoder);
//		final MslObject encryptionJwkMo, hmacJwkMo;
//		try {
//			encryptionJwkMo = encoder.parseObject(encryptionJwkBytes);
//			hmacJwkMo = encoder.parseObject(hmacJwkBytes);
//		} catch (final MslEncoderException e) {
//			throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
//		}
//		encryptionKey = new JsonWebKey(encryptionJwkMo).getSecretKey();
//		hmacKey = new JsonWebKey(hmacJwkMo).getSecretKey();
//		break;
//	}
//	default:
//	{
//		final byte[] unwrappedEncryptionKey = unwrapCryptoContext.unwrap(response.getEncryptionKey(), encoder);
//		final byte[] unwrappedHmacKey = unwrapCryptoContext.unwrap(response.getHmacKey(), encoder);
//		try {
//			encryptionKey = new SecretKeySpec(unwrappedEncryptionKey, JcaAlgorithm.AES);
//			hmacKey = new SecretKeySpec(unwrappedHmacKey, JcaAlgorithm.HMAC_SHA256);
//		} catch (final IllegalArgumentException e) {
//			throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(masterToken);
//		}
//		break;
//	}
//	}

	// Create crypto context.
	const string identity = ctx->getEntityAuthenticationData()->getIdentity();
	shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
	return make_shared<SessionCryptoContext>(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
}

}}} // namespace netflix::msl::keyx
