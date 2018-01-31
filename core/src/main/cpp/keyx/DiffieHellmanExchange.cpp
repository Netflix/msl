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

#include <crypto/JcaAlgorithm.h>
#include <crypto/OpenSslLib.h>
#include <crypto/SessionCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <keyx/DiffieHellmanExchange.h>
#include <keyx/KeyExchangeScheme.h>
#include <tokens/MasterToken.h>
#include <tokens/TokenFactory.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

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

/**
 * If the provided byte array begins with one and only one null byte this
 * function simply returns the original array. Otherwise a new array is
 * created that is a copy of the original array with exactly one null byte
 * in position zero, and this new array is returned.
 *
 * @param b the original array.
 * @return the resulting byte array.
 */
shared_ptr<ByteArray> correctNullBytes(shared_ptr<ByteArray> b)
{
    // Count the number of leading nulls.
    size_t leadingNulls = 0;
    for (size_t i = 0; i < b->size(); ++i) {
        if (b->at(i) != 0x00)
            break;
        ++leadingNulls;
    }

    // If there is exactly one leading null, return the original array.
    if (leadingNulls == 1)
        return b;

    // Create a copy of the non-null bytes and prepend exactly one null
    // byte.
    const size_t copyLength = b->size() - leadingNulls;
    shared_ptr<ByteArray> result = make_shared<ByteArray>(copyLength + 1);
    result->at(0) = 0x00;
    copy(b->begin() + static_cast<ptrdiff_t>(leadingNulls), b->end(), result->begin() + 1);
    return result;
}

/** Key Diffie-Hellman parameters ID. */
string KEY_PARAMETERS_ID = "parametersid";
/** Key Diffie-Hellman public key. */
string KEY_PUBLIC_KEY = "publickey";

/**
 * Container struct for session keys.
 */
struct SessionKeys
{
    /**
     * @param encryptionKey the encryption key.
     * @param hmacKey the HMAC key.
     */
    SessionKeys(const SecretKey& encryptionKey, const SecretKey& hmacKey)
    : encryptionKey(encryptionKey), hmacKey(hmacKey) {}

    /** Encryption key. */
    const SecretKey encryptionKey;
    /** HMAC key. */
    const SecretKey hmacKey;
};

/**
 * Derives the encryption and HMAC session keys from a Diffie-Hellman
 * shared secret.
 *
 * @param publicKey Diffie-Hellman public key.
 * @param privateKey Diffie-Hellman private key.
 * @param params Diffie-Hellman parameter specification.
 * @return the derived session keys.
 */
SessionKeys deriveSessionKeys(const ByteArray& publicKey, const ByteArray& privateKey, const DHParameterSpec& params)
{
    // Compute Diffie-Hellman shared secret.
    ByteArray sharedSecret;
    dhComputeSharedSecret(publicKey, *params.getP(), privateKey, sharedSecret);

    // Derive encryption and HMAC keys.
    ByteArray hash;
    digest("SHA384", sharedSecret, hash);
    ByteArray kcedata(16, 0);
    copy(hash.begin(), hash.begin() + 16, kcedata.begin());
    assert(kcedata.size() == 16);
    ByteArray kchdata(32, 0);
    copy(hash.begin() + 16, hash.begin() + 16 + 32, kchdata.begin());
    assert(kchdata.size() == 32);

    // Return encryption and HMAC keys.
    const SecretKey encryptionKey(make_shared<ByteArray>(kcedata), JcaAlgorithm::AES);
    const SecretKey hmacKey(make_shared<ByteArray>(kchdata), JcaAlgorithm::HMAC_SHA256);
    return SessionKeys(encryptionKey, hmacKey);
}

} // namespace anonymous

DiffieHellmanExchange::RequestData::RequestData(const string& parametersId, shared_ptr<ByteArray> pk,
        std::shared_ptr<crypto::PrivateKey> privateKey)
: KeyRequestData(KeyExchangeScheme::DIFFIE_HELLMAN)
, parametersId(parametersId)
, privateKey(privateKey)
{
    publicKey = correctNullBytes(pk);
}

DiffieHellmanExchange::RequestData::RequestData(shared_ptr<MslObject> keyDataMo) : KeyRequestData(KeyExchangeScheme::DIFFIE_HELLMAN)
{
    try {
        parametersId = keyDataMo->getString(KEY_PARAMETERS_ID);
        shared_ptr<ByteArray> publicKeyY = keyDataMo->getBytes(KEY_PUBLIC_KEY);
        if (!publicKeyY || publicKeyY->size() == 0)
            throw MslKeyExchangeException(MslError::KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo->toString());
        publicKey = correctNullBytes(publicKeyY);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keydata " + keyDataMo->toString(), e);
    }
}

string DiffieHellmanExchange::RequestData::getParametersId() const
{
    return parametersId;
}

shared_ptr<ByteArray> DiffieHellmanExchange::RequestData::getPublicKey() const {
    return publicKey;
}

std::shared_ptr<crypto::PrivateKey> DiffieHellmanExchange::RequestData::getPrivateKey() const {
    return privateKey;
}

bool DiffieHellmanExchange::RequestData::equals(shared_ptr<const KeyRequestData> obj) const
{
    if (!obj) return false;
    if (this == obj.get()) return true;
    if (!instanceof<const RequestData>(obj)) return false;
    shared_ptr<const RequestData> that = dynamic_pointer_cast<const RequestData>(obj);
    return KeyRequestData::equals(obj) &&
           (parametersId == that->parametersId) &&
           MslUtils::sharedPtrCompare(publicKey, that->publicKey) &&
           MslUtils::sharedPtrCompare(privateKey, that->privateKey);
}

shared_ptr<MslObject> DiffieHellmanExchange::RequestData::getKeydata(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat&) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_PARAMETERS_ID, parametersId);
    shared_ptr<ByteArray> publicKeyY = publicKey;
    mo->put(KEY_PUBLIC_KEY, correctNullBytes(publicKeyY));
    return mo;
}

DiffieHellmanExchange::ResponseData::ResponseData(shared_ptr<MasterToken> masterToken, const string& parametersId,
        shared_ptr<ByteArray> pk)
: KeyResponseData(masterToken, KeyExchangeScheme::DIFFIE_HELLMAN)
, parametersId(parametersId)
{
    publicKey = correctNullBytes(pk);
}

DiffieHellmanExchange::ResponseData::ResponseData(shared_ptr<MasterToken> masterToken, shared_ptr<MslObject> keyDataMo)
: KeyResponseData(masterToken, KeyExchangeScheme::DIFFIE_HELLMAN)
{
    try {
        parametersId = keyDataMo->getString(KEY_PARAMETERS_ID);
        shared_ptr<ByteArray> publicKeyY = keyDataMo->getBytes(KEY_PUBLIC_KEY);
        if (publicKeyY->size() == 0)
            throw MslKeyExchangeException(MslError::KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo->toString());
        publicKey = correctNullBytes(publicKeyY);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keydata " + keyDataMo->toString(), e);
    }
}

string DiffieHellmanExchange::ResponseData::getParametersId() const {
    return parametersId;
}

shared_ptr<ByteArray> DiffieHellmanExchange::ResponseData::getPublicKey() const {
    return publicKey;
}

bool DiffieHellmanExchange::ResponseData::equals(shared_ptr<const KeyResponseData> obj) const
{
    if (!obj) return false;
    if (this == obj.get()) return true;
    if (!instanceof<const ResponseData>(obj)) return false;
    shared_ptr<const ResponseData> that = dynamic_pointer_cast<const ResponseData>(obj);
    return KeyResponseData::equals(obj) &&
           (parametersId == that->parametersId) &&
           MslUtils::sharedPtrCompare(publicKey, that->publicKey);
}

shared_ptr<MslObject> DiffieHellmanExchange::ResponseData::getKeydata(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat&) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_PARAMETERS_ID, parametersId);
    shared_ptr<ByteArray> publicKeyY = publicKey;
    mo->put(KEY_PUBLIC_KEY, correctNullBytes(publicKeyY));
    return mo;
}

DiffieHellmanExchange::DiffieHellmanExchange(shared_ptr<DiffieHellmanParameters> params,
        shared_ptr<AuthenticationUtils> authutils)
: KeyExchangeFactory(KeyExchangeScheme::DIFFIE_HELLMAN)
, params(params)
, authutils(authutils)
{
}

shared_ptr<KeyRequestData> DiffieHellmanExchange::createRequestData(shared_ptr<MslContext>,
        shared_ptr<MslObject> keyRequestMo)
{
    return make_shared<RequestData>(keyRequestMo);
}

shared_ptr<KeyResponseData> DiffieHellmanExchange::createResponseData(shared_ptr<MslContext>,
    shared_ptr<tokens::MasterToken> masterToken, shared_ptr<MslObject> keyDataMo)
{
    return make_shared<ResponseData>(masterToken, keyDataMo);
}

shared_ptr<KeyExchangeFactory::KeyExchangeData> DiffieHellmanExchange::generateResponse(
        shared_ptr<MslContext> ctx, const MslEncoderFormat&,
        shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<MasterToken> masterToken)
{
    if (!instanceof<RequestData>(keyRequestData.get()))
        throw MslInternalException("Key request data keyRequestData was not created by this factory.");
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

    // If the master token was not issued by the local entity then we
    // should not be generating a key response for it.
    if (!masterToken->isVerified())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);

    // Verify the scheme is permitted.
    const string identity = masterToken->getIdentity();
    if (!authutils->isSchemePermitted(identity, getScheme()))
        throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ":" + getScheme().toString()).setMasterToken(masterToken);

    // Load matching Diffie-Hellman parameter specification.
    const string parametersId = request->getParametersId();
    DHParameterSpec paramSpec;
    try {
        paramSpec = params->getParameterSpec(parametersId);
    } catch (const Exception& e) {
        throw MslKeyExchangeException(MslError::UNKNOWN_KEYX_PARAMETERS_ID, parametersId);
    }

    // Reconstitute request public key.
    shared_ptr<ByteArray> requestPublicKey = request->getPublicKey();
    if (!requestPublicKey)
        throw MslKeyExchangeException(MslError::KEYX_PUBLIC_KEY_MISSING);

    // Generate public/private key pair.
    ByteArray responsePublicKey, responsePrivateKey;
    dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), responsePublicKey, responsePrivateKey);

    // Construct encryption and HMAC keys.
    const SessionKeys sessionKeys = deriveSessionKeys(*requestPublicKey, responsePrivateKey, paramSpec);

    // Create the master token.
    shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
    shared_ptr<MasterToken> newMasterToken = tokenFactory->renewMasterToken(ctx, masterToken, sessionKeys.encryptionKey, sessionKeys.hmacKey, shared_ptr<MslObject>());

    // Create crypto context.
    shared_ptr<ICryptoContext> cryptoContext = make_shared<SessionCryptoContext>(ctx, newMasterToken);

    // Return the key exchange data.
    shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(newMasterToken, parametersId, make_shared<ByteArray>(responsePublicKey));
    return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

shared_ptr<KeyExchangeFactory::KeyExchangeData> DiffieHellmanExchange::generateResponse(
        shared_ptr<MslContext> ctx, const MslEncoderFormat&,
        shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<EntityAuthenticationData> entityAuthData)
{
    if (!instanceof<RequestData>(keyRequestData.get()))
        throw MslInternalException("Key request data keyRequestData was not created by this factory.");
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);

    // Verify the scheme is permitted.
    const string identity = entityAuthData->getIdentity();
    if (!authutils->isSchemePermitted(identity, getScheme()))
        throw MslKeyExchangeException(MslError::KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ":" + getScheme().toString()).setEntityAuthenticationData(entityAuthData);

    // Load matching Diffie-Hellman parameter specification.
    const string parametersId = request->getParametersId();
    DHParameterSpec paramSpec;
    try {
        paramSpec = params->getParameterSpec(parametersId);
    } catch (const Exception& e) {
        throw MslKeyExchangeException(MslError::UNKNOWN_KEYX_PARAMETERS_ID, parametersId).setEntityAuthenticationData(entityAuthData);
    }

    // Reconstitute request public key.
    shared_ptr<ByteArray> requestPublicKey = request->getPublicKey();
    if (!requestPublicKey)
        throw MslKeyExchangeException(MslError::KEYX_PUBLIC_KEY_MISSING);

    // Generate public/private key pair.
    ByteArray responsePublicKey, responsePrivateKey;
    dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), responsePublicKey, responsePrivateKey);

    // Construct encryption and HMAC keys.
    const SessionKeys sessionKeys = deriveSessionKeys(*requestPublicKey, responsePrivateKey, paramSpec);

    // Create the master token.
    shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
    shared_ptr<MasterToken> masterToken = tokenFactory->createMasterToken(ctx, entityAuthData, sessionKeys.encryptionKey, sessionKeys.hmacKey, shared_ptr<MslObject>());

    // Create crypto context.
    shared_ptr<ICryptoContext> cryptoContext;
    try {
        cryptoContext = make_shared<SessionCryptoContext>(ctx, masterToken);
    } catch (const MslMasterTokenException& e) {
        throw MslInternalException("Master token constructed by token factory is not trusted.", e);
    }

    // Return the key exchange data.
    shared_ptr<KeyResponseData> keyResponseData = make_shared<ResponseData>(masterToken, parametersId, make_shared<ByteArray>(responsePublicKey));
    return make_shared<KeyExchangeData>(keyResponseData, cryptoContext);
}

// FIXME: This method diverges from the java code. It might not work.
std::shared_ptr<crypto::ICryptoContext> DiffieHellmanExchange::getCryptoContext(
        shared_ptr<MslContext> ctx,
        shared_ptr<KeyRequestData> keyRequestData,
        shared_ptr<KeyResponseData> keyResponseData,
        shared_ptr<MasterToken> masterToken)
{
    if (!instanceof<RequestData>(keyRequestData.get()))
        throw MslInternalException("Key request data keyRequestData was not created by this factory.");
    shared_ptr<RequestData> request = dynamic_pointer_cast<RequestData>(keyRequestData);
    if (!instanceof<ResponseData>(keyResponseData.get()))
        throw MslInternalException("Key response data keyResponseData was not created by this factory.");
    shared_ptr<ResponseData> response = dynamic_pointer_cast<ResponseData>(keyResponseData);

    // Verify response matches request.
    const string requestParametersId = request->getParametersId();
    const string responseParametersId = response->getParametersId();
    if (requestParametersId != responseParametersId)
        throw MslKeyExchangeException(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestParametersId + "; response " + responseParametersId).setMasterToken(masterToken);

    // Load matching Diffie-Hellman parameter specification.
    // FIXME: The java code gets the params from the request's private key, but we get
    // get the params by lookup using the request's parmId. Our private key structure
    // does not carry DH params.
    const string parametersId = request->getParametersId();
    DHParameterSpec paramSpec;
    try {
        paramSpec = params->getParameterSpec(parametersId);
    } catch (const Exception& e) {
        throw MslKeyExchangeException(MslError::UNKNOWN_KEYX_PARAMETERS_ID, parametersId);
    }

    // Reconstitute response public key.
    shared_ptr<PrivateKey> privateKey = request->getPrivateKey();
    if (!privateKey)
        throw MslKeyExchangeException(MslError::KEYX_PRIVATE_KEY_MISSING, "request Diffie-Hellman private key").setMasterToken(masterToken);
    //final DHParameterSpec params = privateKey.getParams();  // See above.
    shared_ptr<ByteArray> publicKey = response->getPublicKey();
    if (!publicKey)
        throw MslKeyExchangeException(MslError::KEYX_PUBLIC_KEY_MISSING, "response Diffie-Hellman public key").setMasterToken(masterToken);

    // Create crypto context.
    const string identity = ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID)->getIdentity();
    const SessionKeys sessionKeys = deriveSessionKeys(*publicKey, *privateKey->getEncoded(), paramSpec);
    shared_ptr<MasterToken> responseMasterToken = response->getMasterToken();
    return make_shared<SessionCryptoContext>(ctx, responseMasterToken, identity, sessionKeys.encryptionKey, sessionKeys.hmacKey);
}

}}} // namespace netflix::msl::keyx
