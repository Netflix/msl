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

#include <crypto/SessionCryptoContext.h>
#include <crypto/IRandom.h>
#include <crypto/JcaAlgorithm.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <IllegalArgumentException.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <tokens/MasterToken.h>
#include <tokens/TokenFactory.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>
#include <util/MslStore.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

namespace {
/** Key symmetric key ID. */
const string KEY_KEY_ID = "keyid";
/** Key wrapped encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key wrapped HMAC key. */
const string KEY_HMAC_KEY = "hmackey";
}  // namespace anonymous

// -------- SymmetricWrappedExchange::KeyId -------- //

const SymmetricWrappedExchange::KeyId SymmetricWrappedExchange::KeyId::PSK(KeyId::psk, "PSK");
const SymmetricWrappedExchange::KeyId SymmetricWrappedExchange::KeyId::SESSION(KeyId::session, "SESSION");
const SymmetricWrappedExchange::KeyId SymmetricWrappedExchange::KeyId::INVALID(KeyId::invalid, "INVALID");

// static
const vector<SymmetricWrappedExchange::KeyId>& SymmetricWrappedExchange::KeyId::getValues()
{
    static vector<SymmetricWrappedExchange::KeyId> values;
    if (values.empty()) {
        values.push_back(PSK);
        values.push_back(SESSION);
        values.push_back(INVALID);
    }
    return values;
}

// -------- SymmetricWrappedExchange::RequestData -------- //

SymmetricWrappedExchange::RequestData::RequestData(const SymmetricWrappedExchange::KeyId& keyId)
: KeyRequestData(KeyExchangeScheme::SYMMETRIC_WRAPPED), keyId(keyId)
{
}

SymmetricWrappedExchange::RequestData::RequestData(shared_ptr<MslObject> keyDataMo)
: KeyRequestData(KeyExchangeScheme::SYMMETRIC_WRAPPED)
{
    try {
        const string keyIdName = keyDataMo->getString(KEY_KEY_ID);
        try {
            keyId = KeyId::fromString(keyIdName);
        } catch (const IllegalArgumentException& e) {
            throw MslKeyExchangeException(MslError::UNIDENTIFIED_KEYX_KEY_ID, keyIdName, e);
        }
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keydata " + keyDataMo->toString(), e);
    }
}

shared_ptr<MslObject> SymmetricWrappedExchange::RequestData::getKeydata(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat&) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_KEY_ID, keyId.name());
    return mo;
}

bool SymmetricWrappedExchange::RequestData::equals(std::shared_ptr<const KeyRequestData> base) const
{
    if (!base) return false;
    if (this == base.get()) return true;
    if (!instanceof<const RequestData>(base.get())) return false;
    shared_ptr<const RequestData> that = dynamic_pointer_cast<const RequestData>(base);
    return KeyRequestData::equals(base) && (keyId == that->keyId);
}

bool operator==(const SymmetricWrappedExchange::RequestData& a, const SymmetricWrappedExchange::RequestData& b)
{
	shared_ptr<const SymmetricWrappedExchange::RequestData> ap(&a, &MslUtils::nullDeleter<SymmetricWrappedExchange::RequestData>);
	shared_ptr<const SymmetricWrappedExchange::RequestData> bp(&b, &MslUtils::nullDeleter<SymmetricWrappedExchange::RequestData>);
	return ap->equals(bp);
}

// -------- SymmetricWrappedExchange::ResponseData -------- //

SymmetricWrappedExchange::ResponseData::ResponseData(shared_ptr<MasterToken> masterToken,
        const KeyId& keyId, shared_ptr<ByteArray> encryptionKey, shared_ptr<ByteArray> hmacKey)
: KeyResponseData(masterToken, KeyExchangeScheme::SYMMETRIC_WRAPPED)
, keyId(keyId)
, encryptionKey(encryptionKey)
, hmacKey(hmacKey)
{
}

SymmetricWrappedExchange::ResponseData::ResponseData(shared_ptr<MasterToken> masterToken,
        shared_ptr<MslObject> keyDataMo)
: KeyResponseData(masterToken, KeyExchangeScheme::SYMMETRIC_WRAPPED)
{
    try {
        const string keyIdName = keyDataMo->getString(KEY_KEY_ID);
        try {
            keyId = KeyId::fromString(keyIdName);
        } catch (const IllegalArgumentException& e) {
            throw MslKeyExchangeException(MslError::UNIDENTIFIED_KEYX_KEY_ID, keyIdName, e);
        }
        encryptionKey = keyDataMo->getBytes(KEY_ENCRYPTION_KEY);
        hmacKey = keyDataMo->getBytes(KEY_HMAC_KEY);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keydata " + keyDataMo->toString(), e);
    }
}

shared_ptr<MslObject> SymmetricWrappedExchange::ResponseData::getKeydata(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat&) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_KEY_ID, keyId.name());
    mo->put(KEY_ENCRYPTION_KEY, encryptionKey);
    mo->put(KEY_HMAC_KEY, hmacKey);
    return mo;
}

bool SymmetricWrappedExchange::ResponseData::equals(shared_ptr<const KeyResponseData> base) const
{
    if (!base) return false;
    if (this == base.get()) return true;
    if (!instanceof<ResponseData>(base.get())) return false;
    shared_ptr<const ResponseData> that = dynamic_pointer_cast<const ResponseData>(base);
    return KeyResponseData::equals(base) && (keyId == that->keyId) &&
            (*encryptionKey == *that->encryptionKey) && (*hmacKey == *that->hmacKey);
}

bool operator==(const SymmetricWrappedExchange::ResponseData& a, const SymmetricWrappedExchange::ResponseData& b)
{
	shared_ptr<const SymmetricWrappedExchange::ResponseData> ap(&a, &MslUtils::nullDeleter<SymmetricWrappedExchange::ResponseData>);
	shared_ptr<const SymmetricWrappedExchange::ResponseData> bp(&b, &MslUtils::nullDeleter<SymmetricWrappedExchange::ResponseData>);
	return ap->equals(bp);
}

// -------- class SymmetricWrappedExchange -------- //

//static
shared_ptr<ICryptoContext> SymmetricWrappedExchange::createCryptoContext(shared_ptr<MslContext> ctx,
        const KeyId& keyId, shared_ptr<MasterToken> masterToken, const string& identity)
{
    switch (keyId) {
        case SymmetricWrappedExchange::KeyId::session:
        {
            // If the master token is null session wrapped is unsupported.
            if (!masterToken)
                throw MslKeyExchangeException(MslError::KEYX_MASTER_TOKEN_MISSING, keyId.name());

            // Use a stored master token crypto context if we have one.
            shared_ptr<ICryptoContext> cachedCryptoContext = ctx->getMslStore()->getCryptoContext(masterToken);
            if (cachedCryptoContext)
                return cachedCryptoContext;

            // If there was no stored crypto context try making one from the
            // master token. We can only do this if we can open up the master
            // token.
            if (!masterToken->isDecrypted())
                throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);
            shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, masterToken);
            return cryptoContext;
        }
        case SymmetricWrappedExchange::KeyId::psk:
        {
            shared_ptr<EntityAuthenticationData> authdata = make_shared<PresharedAuthenticationData>(identity);
            shared_ptr<EntityAuthenticationFactory> factory = ctx->getEntityAuthenticationFactory(EntityAuthenticationScheme::PSK);
            if (!factory)
                throw MslKeyExchangeException(MslError::UNSUPPORTED_KEYX_KEY_ID, keyId.name());
            return factory->getCryptoContext(ctx, authdata);
        }
        default:
            throw MslKeyExchangeException(MslError::UNSUPPORTED_KEYX_KEY_ID, keyId.name());
    }
}

SymmetricWrappedExchange::SymmetricWrappedExchange(shared_ptr<AuthenticationUtils> authutils)
: KeyExchangeFactory(KeyExchangeScheme::SYMMETRIC_WRAPPED), authutils(authutils)
{
}

shared_ptr<KeyRequestData> SymmetricWrappedExchange::createRequestData(
        shared_ptr<MslContext>, shared_ptr<MslObject> keyRequestMo)
{
    return make_shared<SymmetricWrappedExchange::RequestData>(keyRequestMo);
}

/* (non-Javadoc)
 * @see com.netflix.msl.keyx.KeyExchangeFactory#createResponseData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
 */
shared_ptr<KeyResponseData> SymmetricWrappedExchange::createResponseData(shared_ptr<MslContext>,
        shared_ptr<MasterToken> masterToken, shared_ptr<MslObject> keyDataMo)
{
    return make_shared<SymmetricWrappedExchange::ResponseData>(masterToken, keyDataMo);
}

shared_ptr<KeyExchangeFactory::KeyExchangeData> SymmetricWrappedExchange::generateResponse(
        shared_ptr<MslContext> ctx, const MslEncoderFormat& format,
        shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<MasterToken> masterToken)
{
    if (!(instanceof<RequestData>(keyRequestData.get()))) {
        const KeyRequestData& krd = *keyRequestData;
        throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
    }
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

    // Verify the scheme is permitted.
    const string identity = masterToken->getIdentity();
    if (!authutils->isSchemePermitted(identity, getScheme()))
        throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme().toString()).setMasterToken(masterToken);

    // If the master token was not issued by the local entity then we
    // should not be generating a key response for it.
    if (!masterToken->isVerified())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken).setMasterToken(masterToken);

    // Create random AES-128 encryption and SHA-256 HMAC keys.
    shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
    shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
    ctx->getRandom()->nextBytes(*encryptionBytes);
    ctx->getRandom()->nextBytes(*hmacBytes);
    const SecretKey encryptionKey(encryptionBytes, JcaAlgorithm::AES);
    const SecretKey hmacKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);

    // Wrap session keys with identified key...
    const KeyId keyId = request->getKeyId();
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<ICryptoContext> wrapCryptoContext = createCryptoContext(ctx, keyId, masterToken, masterToken->getIdentity());
    shared_ptr<ByteArray> wrappedEncryptionKey = wrapCryptoContext->wrap(encryptionBytes, encoder, format);
    shared_ptr<ByteArray> wrappedHmacKey = wrapCryptoContext->wrap(hmacBytes, encoder, format);

    // Create the master token.
    shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
    shared_ptr<MasterToken> newMasterToken = tokenFactory->renewMasterToken(ctx, masterToken, encryptionKey, hmacKey, shared_ptr<MslObject>());

    // Create crypto context.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, newMasterToken);

    // Return the key exchange data.
    shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(newMasterToken, keyId, wrappedEncryptionKey, wrappedHmacKey);
    return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

shared_ptr<KeyExchangeFactory::KeyExchangeData> SymmetricWrappedExchange::generateResponse(
        shared_ptr<MslContext> ctx, const MslEncoderFormat& format,
        shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<EntityAuthenticationData> entityAuthData)
{
    if (!(instanceof<RequestData>(keyRequestData.get()))) {
        const KeyRequestData& krd = *keyRequestData;
        throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
    }
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

    // Verify the scheme is permitted.
    const string identity = entityAuthData->getIdentity();
    if (!authutils->isSchemePermitted(identity, getScheme()))
        throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme().toString());

    // Create random AES-128 encryption and SHA-256 HMAC keys.
    shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
    shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
    ctx->getRandom()->nextBytes(*encryptionBytes);
    ctx->getRandom()->nextBytes(*hmacBytes);
    const SecretKey encryptionKey(encryptionBytes, JcaAlgorithm::AES);
    const SecretKey hmacKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);

    // Wrap session keys with identified key.
    const KeyId keyId = request->getKeyId();
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<ICryptoContext> wrapCryptoContext;
    try {
        wrapCryptoContext = createCryptoContext(ctx, keyId, shared_ptr<MasterToken>(), identity);
    } catch (const MslMasterTokenException& e) {
        throw MslInternalException("Master token exception thrown when the master token is null.", e);
    }
    shared_ptr<ByteArray> wrappedEncryptionKey = wrapCryptoContext->wrap(encryptionBytes, encoder, format);
    shared_ptr<ByteArray> wrappedHmacKey = wrapCryptoContext->wrap(hmacBytes, encoder, format);

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
    shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(masterToken, keyId, wrappedEncryptionKey, wrappedHmacKey);
    return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

shared_ptr<ICryptoContext> SymmetricWrappedExchange::getCryptoContext(
        shared_ptr<MslContext> ctx, shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<KeyResponseData> keyResponseData, shared_ptr<MasterToken> masterToken)
{
    const KeyRequestData& krd = *keyRequestData;
    if (!(instanceof<RequestData>(keyRequestData.get())))
        throw MslInternalException("Key request data " + string(typeid(krd).name()) + " was not created by this factory.");
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);
    if (!(instanceof<ResponseData>(keyResponseData.get())))
        throw MslInternalException("Key response data " + string(typeid(krd).name()) + " was not created by this factory.");
    shared_ptr<ResponseData> response = dynamic_pointer_cast<ResponseData>(keyResponseData);

    // Verify response matches request.
    const KeyId requestKeyId = request->getKeyId();
    const KeyId responseKeyId = response->getKeyId();
    if (requestKeyId != responseKeyId)
        throw MslKeyExchangeException(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyId.name() + "; response " + responseKeyId.name()).setMasterToken(masterToken);

    // Unwrap session keys with identified key.
    shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    const string identity = entityAuthData->getIdentity();
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<ICryptoContext> unwrapCryptoContext = createCryptoContext(ctx, responseKeyId, masterToken, identity);
    shared_ptr<ByteArray> unwrappedEncryptionKey = unwrapCryptoContext->unwrap(response->getEncryptionKey(), encoder);
    shared_ptr<ByteArray> unwrappedHmacKey = unwrapCryptoContext->unwrap(response->getHmacKey(), encoder);

    // Create crypto context.
    const SecretKey encryptionKey(unwrappedEncryptionKey, JcaAlgorithm::AES);
    const SecretKey hmacKey(unwrappedHmacKey, JcaAlgorithm::HMAC_SHA256);
    shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
    return make_shared<SessionCryptoContext>(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
}

bool operator==(const SymmetricWrappedExchange::KeyId& a, const SymmetricWrappedExchange::KeyId& b)
{
    return a.value() == b.value();
}

}}} // namespace netflix::msl::keyx
