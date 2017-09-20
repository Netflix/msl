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

#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/KeySetStore.h>
#include <entityauth/PresharedAuthenticationFactory.h>
#include <entityauth/PresharedAuthenticationData.h>
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

/**
 * Construct a new preshared keys authentication factory instance.
 *
 * @param store preshared key store.
 * @param authutils authentication utilities.
 */
PresharedAuthenticationFactory::PresharedAuthenticationFactory(shared_ptr<KeySetStore> store,
        shared_ptr<AuthenticationUtils> authutils)
    : EntityAuthenticationFactory(EntityAuthenticationScheme::PSK)
    , store_(store)
    , authutils_(authutils)
{}

shared_ptr<EntityAuthenticationData> PresharedAuthenticationFactory::createData(
        shared_ptr<MslContext>, shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<PresharedAuthenticationData>(entityAuthMo);
}

/* (non-Javadoc)
 * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
 */
shared_ptr<ICryptoContext> PresharedAuthenticationFactory::getCryptoContext(
        shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<PresharedAuthenticationData>(authdata.get())) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata).name() << ".";
        throw MslInternalException(ss.str());
    }

    // Check for revocation.
    const string identity = authdata->getIdentity();
    if (authutils_->isEntityRevoked(identity))
        throw MslEntityAuthException(MslError::ENTITY_REVOKED, "psk " + identity).setEntityAuthenticationData(authdata);

    // Verify the scheme is permitted.
    if (!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslEntityAuthException(MslError::INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " +
                identity + ":" + getScheme().name()).setEntityAuthenticationData(authdata);

    // Load key set.
    KeySetStore::KeySet keys;
    bool found = store_->getKeys(identity, keys);
    if (!found || keys.encryptionKey.isNull())
        throw MslEntityAuthException(MslError::ENTITY_NOT_FOUND, "psk " + identity).setEntityAuthenticationData(authdata);

    // Return the crypto context.
    return make_shared<SymmetricCryptoContext>(ctx, identity, keys.encryptionKey, keys.hmacKey, keys.wrappingKey);
}

}}} // namespace netflix::msl::entityauth
