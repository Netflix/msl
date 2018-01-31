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
#include <crypto/NullCryptoContext.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationFactory.h>
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
 * Construct a new unauthenticated authentication factory instance.
 *
 * @param authutils authentication utilities.
 */
UnauthenticatedAuthenticationFactory::UnauthenticatedAuthenticationFactory(shared_ptr<AuthenticationUtils> authutils)
    : EntityAuthenticationFactory(EntityAuthenticationScheme::NONE)
    , authutils_(authutils)
{}

shared_ptr<EntityAuthenticationData> UnauthenticatedAuthenticationFactory::createData(
        shared_ptr<MslContext>, shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<UnauthenticatedAuthenticationData>(entityAuthMo);
}

/* (non-Javadoc)
 * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
 */
shared_ptr<ICryptoContext> UnauthenticatedAuthenticationFactory::getCryptoContext(
        shared_ptr<MslContext> /*ctx*/, shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<UnauthenticatedAuthenticationData>(authdata.get())) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata).name() << ".";
        throw MslInternalException(ss.str());
    }
    shared_ptr<UnauthenticatedAuthenticationData> uad = dynamic_pointer_cast<UnauthenticatedAuthenticationData>(authdata);

    // Check for revocation.
    const string identity = uad->getIdentity();
    if (authutils_->isEntityRevoked(identity))
        throw MslEntityAuthException(MslError::ENTITY_REVOKED, "none " + identity).setEntityAuthenticationData(uad);

    // Verify the scheme is permitted.
    if (!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslEntityAuthException(MslError::INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " +
                identity + ":" + getScheme().name()).setEntityAuthenticationData(uad);

    // Return the crypto context.
    return make_shared<NullCryptoContext>();
}

}}} // namespace netflix::msl::entityauth
