/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#include <entityauth/EccAuthenticationFactory.h>
#include <crypto/EccCryptoContext.h>
#include <crypto/ICryptoContext.h>
#include <entityauth/EccAuthenticationData.h>
#include <entityauth/EccStore.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslObject.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>
#include <MslEntityAuthException.h>
#include <MslInternalException.h>

#include <memory>
#include <sstream>
#include <string>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

EccAuthenticationFactory::EccAuthenticationFactory(
        shared_ptr<EccStore> store, shared_ptr<AuthenticationUtils> authutils)
    : EccAuthenticationFactory("", store, authutils)
{}

EccAuthenticationFactory::EccAuthenticationFactory(
        const string& keyPairId, shared_ptr<EccStore> store, shared_ptr<AuthenticationUtils> authutils)
    : keyPairId_(keyPairId)
    , store_(store)
    , authutils_(authutils)
{}

shared_ptr<EntityAuthenticationData> EccAuthenticationFactory::createData(
    shared_ptr<MslContext> ctx, shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<EccAuthenticationData>(entityAuthMo);
}

shared_ptr<ICryptoContext> EccAuthenticationFactory::getCryptoContext(
    shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<EccAuthenticationData>(authdata)) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata).name() << ".";
        throw MslInternalException(ss.str());
    }
    shared_ptr<EccAuthenticationData> ead = dynamic_pointer_cast<EccAuthenticationData>(authdata);

    // Check for revocation.
    const string identity = ead->getIdentity();
    if (authutils_->isEntityRevoked(identity))
        throw MslEntityAuthException(MslError::ENTITY_REVOKED, "ecc" + identity).setEntityAuthenticationData(ead);

    // Verify the scheme is permitted.
    if (!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslEntityAuthException(MslError::INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " +
            identity + ":" + getScheme()).setEntityAuthenticationData(ead);

    // Extract ECC authentication data.
    const string pubkeyid = ead->getPublicKeyId();
    shared_ptr<PublicKey> publicKey = store_->getPublicKey(pubkeyid);
    shared_ptr<PrivateKey> privateKey = store_->getPrivateKey(pubkeyid);

    // The local entity must have a private key.
    if (pubkeyid == keyPairId_ && !privateKey)
        throw MslEntityAuthException(MslError::ECC_PRIVATEKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(ead);

    // Remote entities must have a public key.
    else if (pubkeyid != keyPairId_ && !publicKey)
        throw MslEntityAuthException(MslError::ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(ead);

    // Return the crypto context.
    return make_shared<EccCryptoContext>(identity, privateKey, publicKey, EccCryptoContext::Mode::SIGN_VERIFY);
}

}}} // namespace netflix::msl::entityauth
