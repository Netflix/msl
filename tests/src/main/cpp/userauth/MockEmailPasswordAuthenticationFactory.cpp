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

#include "MockEmailPasswordAuthenticationFactory.h"

#include <MslError.h>
#include <MslInternalException.h>
#include <MslUserAuthException.h>
#include <tokens/UserIdToken.h>
#include <userauth/EmailPasswordAuthenticationData.h>

#include <gtest/gtest.h>
#include <tokens/MockMslUser.h>

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

const string MockEmailPasswordAuthenticationFactory::EMAIL = "email1@domain.com";
const string MockEmailPasswordAuthenticationFactory::PASSWORD = "password";
const string MockEmailPasswordAuthenticationFactory::EMAIL_2 = "email2@domain.com";
const string MockEmailPasswordAuthenticationFactory::PASSWORD_2 = "password2";

shared_ptr<MslUser> MockEmailPasswordAuthenticationFactory::USER()
{
	static shared_ptr<MslUser> user = make_shared<MockMslUser>(312204600);
	return user;
}

shared_ptr<MslUser> MockEmailPasswordAuthenticationFactory::USER_2()
{
	static shared_ptr<MslUser> user2 = make_shared<MockMslUser>(880083944);
	return user2;
}

shared_ptr<UserAuthenticationData> MockEmailPasswordAuthenticationFactory::createData(
        shared_ptr<MslContext> /*ctx*/, shared_ptr<MasterToken> /*masterToken*/,
        shared_ptr<MslObject> userAuthMo)
{
    return make_shared<EmailPasswordAuthenticationData>(userAuthMo);
}

shared_ptr<MslUser> MockEmailPasswordAuthenticationFactory::authenticate(shared_ptr<MslContext> /*ctx*/,
        const string& /*identity*/, shared_ptr<UserAuthenticationData> data, shared_ptr<UserIdToken> userIdToken)
{
    // Make sure we have the right kind of user authentication data.
     if (!instanceof<EmailPasswordAuthenticationData>(data.get()))
         throw MslInternalException("Incorrect authentication data type.");
     shared_ptr<EmailPasswordAuthenticationData> epad = dynamic_pointer_cast<EmailPasswordAuthenticationData>(data);

     // Extract and check email and password values.
     const std::string epadEmail = epad->getEmail();
     const std::string epadPassword = epad->getPassword();
     if (epadEmail.empty() || epadPassword.empty())
         throw MslUserAuthException(MslError::EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);
     const std::string email = strTrim(epadEmail);
     const std::string password = strTrim(epadPassword);
     if (email.empty() || password.empty())
         throw MslUserAuthException(MslError::EMAILPASSWORD_BLANK).setUserAuthenticationData(epad);

     // Identify the user.
     shared_ptr<MslUser> user;
     if (EMAIL == email && PASSWORD == password)
         user = USER();
     else if (EMAIL_2 == email && PASSWORD_2 == password)
         user = USER_2();
     else
         throw MslUserAuthException(MslError::EMAILPASSWORD_INCORRECT).setUserAuthenticationData(epad);

     // If a user ID token was provided validate the user identities.
     if (userIdToken) {
         shared_ptr<MslUser> uitUser = userIdToken->getUser();
         if (*user != *uitUser)
             throw MslUserAuthException(MslError::USERIDTOKEN_USERAUTH_DATA_MISMATCH, string("uad user ") + user->getEncoded() + "; uit user " + uitUser->getEncoded());
     }

     // Return the user.
     return user;
}

}}} // netflix::msl::userauth
