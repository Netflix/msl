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
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslUserAuthException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserIdTokenAuthenticationData.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::tokens;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

namespace {
/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";
/** Key user ID token. */
const string KEY_USER_ID_TOKEN = "useridtoken";
} // namespace anonymous

UserIdTokenAuthenticationData::UserIdTokenAuthenticationData(
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken)
    : UserAuthenticationData(UserAuthenticationScheme::USER_ID_TOKEN)
    , masterToken_(masterToken)
    , userIdToken_(userIdToken)
{
    if (!userIdToken->isBoundTo(masterToken))
        throw MslInternalException("User ID token must be bound to master token.");
}

UserIdTokenAuthenticationData::UserIdTokenAuthenticationData(
        shared_ptr<MslContext> ctx,
        shared_ptr<MslObject> userIdTokenAuthMo)
    : UserAuthenticationData(UserAuthenticationScheme::USER_ID_TOKEN)
{
    // Extract master token and user ID token representations.
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<MslObject> masterTokenMo, userIdTokenMo;
    try {
        masterTokenMo = userIdTokenAuthMo->getMslObject(KEY_MASTER_TOKEN, encoder);
        userIdTokenMo = userIdTokenAuthMo->getMslObject(KEY_USER_ID_TOKEN, encoder);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, string("user ID token authdata ") + userIdTokenAuthMo->toString(), e);
    }

    // Convert any MslExceptions into MslUserAuthException because we don't
    // want to trigger entity or user re-authentication incorrectly.
    try {
        masterToken_ = make_shared<MasterToken>(ctx, masterTokenMo);
    } catch (const MslException& e) {
        throw MslUserAuthException(MslError::USERAUTH_MASTERTOKEN_INVALID, string("user ID token authdata ") + userIdTokenAuthMo->toString(), e);
    }
    try {
        userIdToken_ = make_shared<UserIdToken>(ctx, userIdTokenMo, masterToken_);
    } catch (const MslException& e) {
        throw MslUserAuthException(MslError::USERAUTH_USERIDTOKEN_INVALID, string("user ID token authdata ") + userIdTokenAuthMo->toString(), e);
    }
}

shared_ptr<MslObject> UserIdTokenAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& format) const
{
    shared_ptr<MslObject> authdata = encoder->createObject();
    authdata->put(KEY_MASTER_TOKEN, dynamic_pointer_cast<MslEncodable>(masterToken_));
    authdata->put(KEY_USER_ID_TOKEN, dynamic_pointer_cast<MslEncodable>(userIdToken_));
    shared_ptr<ByteArray> ba = encoder->encodeObject(authdata, format);
    return encoder->parseObject(ba);
}

// FIXME: debug only
std::string UserIdTokenAuthenticationData::toString() const
{
    stringstream ss;
    ss << "mastertoken: " << masterToken_->toString() << "  ";
    ss << "userIdToken: " << userIdToken_->toString();
    return ss.str();
}

bool UserIdTokenAuthenticationData::equals(shared_ptr<const UserAuthenticationData> base) const
{
    if (!base) return false;
    if (this == base.get()) return true;
    if (!instanceof<const UserIdTokenAuthenticationData>(base.get())) return false;
    shared_ptr<const UserIdTokenAuthenticationData> that = dynamic_pointer_cast<const UserIdTokenAuthenticationData>(base);
    return UserAuthenticationData::equals(base) &&
           masterToken_->equals(that->masterToken_) &&
           userIdToken_->equals(that->userIdToken_);
}

bool operator==(const UserIdTokenAuthenticationData& a, const UserIdTokenAuthenticationData& b)
{
	shared_ptr<const UserIdTokenAuthenticationData> ap(&a, &MslUtils::nullDeleter<UserIdTokenAuthenticationData>);
	shared_ptr<const UserIdTokenAuthenticationData> bp(&b, &MslUtils::nullDeleter<UserIdTokenAuthenticationData>);
	return ap->equals(bp);
}

}}} // netflix::msl::userauth
