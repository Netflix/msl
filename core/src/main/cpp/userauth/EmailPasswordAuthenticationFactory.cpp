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

#include <io/MslEncoderFactory.h>
#include <userauth/EmailPasswordAuthenticationFactory.h>
#include <Macros.h>
#include <MslInternalException.h>
#include <MslUserAuthException.h>
#include <tokens/MslUser.h>
#include <tokens/UserIdToken.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <userauth/EmailPasswordStore.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/AuthenticationUtils.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

EmailPasswordAuthenticationFactory::EmailPasswordAuthenticationFactory(
        shared_ptr<EmailPasswordStore> store,
        shared_ptr<AuthenticationUtils> authutils)
    : UserAuthenticationFactory(UserAuthenticationScheme::EMAIL_PASSWORD)
    , store_(store)
    , authutils_(authutils)
{
}

shared_ptr<UserAuthenticationData> EmailPasswordAuthenticationFactory::createData(
        shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MasterToken> /*masterToken*/,
        shared_ptr<MslObject> userAuthMo)
{
    return make_shared<EmailPasswordAuthenticationData>(userAuthMo);
}

shared_ptr<MslUser> EmailPasswordAuthenticationFactory::authenticate(
        shared_ptr<MslContext> /*ctx*/,
        const string& identity,
        shared_ptr<UserAuthenticationData> data,
        shared_ptr<UserIdToken> userIdToken)
{
    // Make sure we have the right kind of user authentication data.
    if (!instanceof<EmailPasswordAuthenticationData>(data.get()))
        throw MslInternalException("Incorrect authentication data type.");
    shared_ptr<EmailPasswordAuthenticationData> epad = static_pointer_cast<EmailPasswordAuthenticationData>(data);

    // Verify the scheme is permitted.
    if(!authutils_->isSchemePermitted(identity, getScheme()))
        throw MslUserAuthException(MslError::USERAUTH_ENTITY_INCORRECT_DATA, "Authentication scheme " +
            getScheme().name() + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);

    // Extract and check email and password values.
    const string epadEmail = epad->getEmail();
    const string epadPassword = epad->getPassword();
    if (epadEmail.empty() || epadPassword.empty())
        throw MslUserAuthException(MslError::EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
    const string email = strTrim(epadEmail);
    const string password = strTrim(epadPassword);
    if (email.empty() || password.empty())
        throw MslUserAuthException(MslError::EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);

    // Authenticate the user.
    shared_ptr<MslUser> user = store_->isUser(email, password);
    if (!user)
        throw MslUserAuthException(MslError::EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);

    // Verify the scheme is still permitted.
    if (!authutils_->isSchemePermitted(identity, user, getScheme()))
        throw MslUserAuthException(MslError::USERAUTH_ENTITYUSER_INCORRECT_DATA, string("Authentication scheme ") +
                getScheme().name() + " not permitted for entity " + identity + ".").setUserAuthenticationData(epad);

    // If a user ID token was provided validate the user identities.
    if (userIdToken) {
        shared_ptr<MslUser> uitUser = userIdToken->getUser();
        if (!user->equals(uitUser))
            throw MslUserAuthException(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, string("uad user ") +
                    user->getEncoded() + "; uit user " + uitUser->getEncoded()).setUserAuthenticationData(epad);
    }

    // Return the user.
    return user;
}

string strTrim(const string& str)
{
    size_t first = str.find_first_not_of(' ');
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last-first+1));
}

}}} // namespace netflix::msl::userauth
