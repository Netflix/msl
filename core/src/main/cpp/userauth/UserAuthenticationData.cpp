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
#include <io/MslObject.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslUserAuthException.h>
#include <tokens/MasterToken.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationFactory.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

namespace {

/** Key user authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key user authentication data. */
const string KEY_AUTHDATA = "authdata";

} // namespace anonymous

// static
shared_ptr<UserAuthenticationData> UserAuthenticationData::create(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<MslObject> userAuthMo)
{
    try {
        // Pull the scheme.
        const string schemeName = userAuthMo->getString(KEY_SCHEME);
        UserAuthenticationScheme scheme = ctx->getUserAuthenticationScheme(schemeName);
        if (scheme == UserAuthenticationScheme::INVALID)
            throw MslUserAuthException(MslError::UNIDENTIFIED_USERAUTH_SCHEME, schemeName);

        // Construct an instance of the concrete subclass.
        shared_ptr<UserAuthenticationFactory> factory = ctx->getUserAuthenticationFactory(scheme);
        if (!factory)
            throw MslUserAuthException(MslError::USERAUTH_FACTORY_NOT_FOUND, scheme.name());
        shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
        return factory->createData(ctx, masterToken, userAuthMo->getMslObject(KEY_AUTHDATA, encoder));
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "userauthdata " + userAuthMo->toString(), e);
    }
}

shared_ptr<ByteArray> UserAuthenticationData::toMslEncoding(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& format) const
{
    // Return any cached encoding.
    map<MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings_.find(format);
    if (it != encodings_.end())
        return it->second;

    // Encode the user authentication data.
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, scheme_.name());
    mo->put<shared_ptr<MslObject>>(KEY_AUTHDATA, getAuthData(encoder, format));
    shared_ptr<ByteArray> encoding = encoder->encodeObject(mo, format);

    // Cache and return the encoding.
    encodings_.insert(make_pair(format, encoding));
    return encoding;
}

bool UserAuthenticationData::equals(shared_ptr<const UserAuthenticationData> that) const
{
    if (!that) return false;
    if (this == that.get()) return true;
    return scheme_ == that->scheme_;
}

bool operator==(const UserAuthenticationData& a, const UserAuthenticationData& b)
{
	shared_ptr<const UserAuthenticationData> ap(&a, &MslUtils::nullDeleter<UserAuthenticationData>);
	shared_ptr<const UserAuthenticationData> bp(&b, &MslUtils::nullDeleter<UserAuthenticationData>);
	return ap->equals(bp);
}


}}} // namespace netflix::msl::userauth
