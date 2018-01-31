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

#include <userauth/EmailPasswordAuthenticationData.h>
#include <MslEncodingException.h>
#include <io/MslObject.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/MslUtils.h>

namespace netflix {
namespace msl {
namespace userauth {

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace {
/** Key email. */
const string KEY_EMAIL = "email";
/** Key password. */
const string KEY_PASSWORD = "password";
}

EmailPasswordAuthenticationData::EmailPasswordAuthenticationData(const string email,
        const string password)
    : UserAuthenticationData(UserAuthenticationScheme::EMAIL_PASSWORD)
    , email_(email)
    , password_(password)
{
}

EmailPasswordAuthenticationData::EmailPasswordAuthenticationData(
        shared_ptr<MslObject> emailPasswordAuthMo)
    : UserAuthenticationData(UserAuthenticationScheme::EMAIL_PASSWORD)
{
    try {
        email_ = emailPasswordAuthMo->getString(KEY_EMAIL);
        password_ = emailPasswordAuthMo->getString(KEY_PASSWORD);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, string("email/password authdata ") + emailPasswordAuthMo->toString(), e);
    }
}

shared_ptr<MslObject> EmailPasswordAuthenticationData::getAuthData(
        shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& /*format*/) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_EMAIL, email_);
    mo->put(KEY_PASSWORD, password_);
    return mo;
}

bool EmailPasswordAuthenticationData::equals(shared_ptr<const UserAuthenticationData> base) const
{
    if (!base) return false;
    if (this == base.get()) return true;
    if (!instanceof<EmailPasswordAuthenticationData>(base.get())) return false;
    shared_ptr<const EmailPasswordAuthenticationData> that = dynamic_pointer_cast<const EmailPasswordAuthenticationData>(base);
    return UserAuthenticationData::equals(base) &&
           email_ == that->email_ &&
           password_ == that->password_;
}

bool operator==(const EmailPasswordAuthenticationData& a, const EmailPasswordAuthenticationData& b)
{
	shared_ptr<const EmailPasswordAuthenticationData> ap(&a, &MslUtils::nullDeleter<EmailPasswordAuthenticationData>);
	shared_ptr<const EmailPasswordAuthenticationData> bp(&b, &MslUtils::nullDeleter<EmailPasswordAuthenticationData>);
	return ap->equals(bp);
}

}}} // netflix::msl::userauth
