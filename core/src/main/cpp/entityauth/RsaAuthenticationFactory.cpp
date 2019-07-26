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

#include <crypto/Key.h>
#include <crypto/RsaCryptoContext.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/RsaAuthenticationData.h>
#include <entityauth/RsaAuthenticationFactory.h>
#include <entityauth/RsaStore.h>
#include <Macros.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <io/MslEncoderFormat.h>
#include <util/AuthenticationUtils.h>
#include <sstream>
#include <typeinfo>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

RsaAuthenticationFactory::RsaAuthenticationFactory(shared_ptr<RsaStore> store,
		shared_ptr<AuthenticationUtils> authutils)
	: EntityAuthenticationFactory(EntityAuthenticationScheme::RSA)
	, store_(store)
	, authutils_(authutils)
{}

/**
 * <p>Construct a new RSA asymmetric keys authentication factory
 * instance.</p>
 *
 * @param store RSA key store.
 * @param authutils authentication utilities.
 */
RsaAuthenticationFactory::RsaAuthenticationFactory(const string keyPairId,
		shared_ptr<RsaStore> store,
        shared_ptr<AuthenticationUtils> authutils)
    : EntityAuthenticationFactory(EntityAuthenticationScheme::RSA)
	, keyPairId_(keyPairId)
    , store_(store)
    , authutils_(authutils)
{}

shared_ptr<EntityAuthenticationData> RsaAuthenticationFactory::createData(
        shared_ptr<MslContext>, shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<RsaAuthenticationData>(entityAuthMo);
}

/* (non-Javadoc)
 * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
 */
shared_ptr<ICryptoContext> RsaAuthenticationFactory::getCryptoContext(
        shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<RsaAuthenticationData>(authdata.get())) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata).name() << ".";
        throw MslInternalException(ss.str());
    }
    shared_ptr<RsaAuthenticationData> rad = dynamic_pointer_cast<RsaAuthenticationData>(authdata);

    // Check for revocation.
    const string identity = rad->getIdentity();
    if (authutils_->isEntityRevoked(identity))
        throw MslEntityAuthException(MslError::ENTITY_REVOKED, "rsa " + identity).setEntityAuthenticationData(rad);

    // Verify the scheme is permitted.
    if (!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslEntityAuthException(MslError::INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " +
                identity + ":" + getScheme().name()).setEntityAuthenticationData(rad);

    // Extract RSA authentication data.
    const string pubkeyid = rad->getPublicKeyId();
    const PublicKey publicKey = store_->getPublicKey(pubkeyid);
    const PrivateKey privateKey = store_->getPrivateKey(pubkeyid);

    // The local entity must have a private key.
    if (pubkeyid == keyPairId_ && privateKey.isNull())
        throw MslEntityAuthException(MslError::RSA_PRIVATEKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);

    // Remote entities must have a public key.
    else if (pubkeyid != keyPairId_ && publicKey.isNull())
        throw MslEntityAuthException(MslError::RSA_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);

    // Return the crypto context.
    return make_shared<RsaCryptoContext>(ctx, identity, privateKey, publicKey, RsaCryptoContext::Mode::SIGN_VERIFY);
}

}}} // namespace netflix::msl::entityauth
