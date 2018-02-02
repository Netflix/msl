/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include <io/MslEncoderFactory.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslUserAuthException.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/TokenFactory.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserIdTokenAuthenticationFactory.h>
#include <userauth/UserIdTokenAuthenticationData.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

namespace {

} // namespace anonymous

UserIdTokenAuthenticationFactory::UserIdTokenAuthenticationFactory(
        shared_ptr<AuthenticationUtils> authutils)
    : UserAuthenticationFactory(UserAuthenticationScheme::USER_ID_TOKEN)
    , authutils_(authutils)
{
}

shared_ptr<UserAuthenticationData> UserIdTokenAuthenticationFactory::createData(
        shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> /*masterToken*/,
        shared_ptr<MslObject> userAuthMo)
{
    return make_shared<UserIdTokenAuthenticationData>(ctx, userAuthMo);
}

shared_ptr<MslUser> UserIdTokenAuthenticationFactory::authenticate(
        shared_ptr<MslContext> ctx,
        const string& identity,
        shared_ptr<UserAuthenticationData> data,
        shared_ptr<UserIdToken> userIdToken)
{
    // Make sure we have the right kind of user authentication data.
    if (!instanceof<UserIdTokenAuthenticationData>(data.get()))
        throw MslInternalException("Incorrect authentication data type.");
    shared_ptr<UserIdTokenAuthenticationData> uitad = static_pointer_cast<UserIdTokenAuthenticationData>(data);

    // Verify the scheme is permitted.
    if(!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslUserAuthException(MslError::USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " +
                getScheme().name() + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

    // Extract and check master token.
    shared_ptr<MasterToken> uitadMasterToken = uitad->getMasterToken();
    const string uitadIdentity = uitadMasterToken->getIdentity();
    if (uitadIdentity.empty())
        throw MslUserAuthException(MslError::USERAUTH_MASTERTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);
    if (identity != uitadIdentity)
        throw MslUserAuthException(MslError::USERAUTH_ENTITY_MISMATCH, "entity identity " +
                identity + "; uad identity " + uitadIdentity).setUserAuthenticationData(uitad);

    // Authenticate the user.
    shared_ptr<UserIdToken> uitadUserIdToken = uitad->getUserIdToken();
    shared_ptr<MslUser> user = uitadUserIdToken->getUser();
    if (!user)
        throw MslUserAuthException(MslError::USERAUTH_USERIDTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);

    // Verify the scheme is still permitted.
    if (!authutils_->isSchemePermitted(identity, user, getScheme()))
        throw MslUserAuthException(MslError::USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " +
                getScheme().name() + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

    // Verify token has not been revoked.
    MslError revokeMslError = MslError::OK;
    try {
        revokeMslError = ctx->getTokenFactory()->isUserIdTokenRevoked(ctx, uitadMasterToken, uitadUserIdToken);
    } catch (const MslException& e) {
        throw MslUserAuthException(MslError::USERAUTH_USERIDTOKEN_REVOKE_CHECK_ERROR, "Error while checking user ID token for revocation.", e).setUserAuthenticationData(uitad);
    }
    if (revokeMslError != MslError::OK)
        throw MslUserAuthException(revokeMslError, "User ID token used to authenticate was revoked.").setUserAuthenticationData(uitad);

    // If a user ID token was provided validate the user identities.
    if (userIdToken) {
        shared_ptr<MslUser> uitUser = userIdToken->getUser();
        if (!user->equals(uitUser))
            throw MslUserAuthException(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " +
                    user->getEncoded() + "; uit user " + uitUser->getEncoded()).setUserAuthenticationData(uitad);
    }

    // Return the user.
    return user;
}
}}} // netflix::msl::userauth
