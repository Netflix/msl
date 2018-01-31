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

#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <memory>
#include <sstream>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key entity authentication data. */
const string KEY_AUTHDATA = "authdata";
}

//static
shared_ptr<EntityAuthenticationData> EntityAuthenticationData::create(
        shared_ptr<MslContext> ctx, shared_ptr<MslObject> entityAuthMo)
{
    try {
        // Identify the concrete subclass from the authentication scheme.
        const string schemeName = entityAuthMo->getString(KEY_SCHEME);
        const EntityAuthenticationScheme scheme =
                ctx->getEntityAuthenticationScheme(schemeName);
        if (scheme == EntityAuthenticationScheme::INVALID)
            throw MslEntityAuthException(MslError::UNIDENTIFIED_ENTITYAUTH_SCHEME, schemeName);
        shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
        shared_ptr<MslObject> authdata = entityAuthMo->getMslObject(KEY_AUTHDATA, encoder);

        // Construct an instance of the concrete subclass.
        shared_ptr<EntityAuthenticationFactory> factory = ctx->getEntityAuthenticationFactory(scheme);
        if (!factory)
            throw MslEntityAuthException(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
        return factory->createData(ctx, authdata);
    } catch (const MslEncoderException& e) {
        stringstream ss;
        ss << "entityauthdata " << entityAuthMo;
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
    }
}

shared_ptr<ByteArray> EntityAuthenticationData::toMslEncoding(
        shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& format) const
{
    // Return any cached encoding.
    const MapType::const_iterator it = encodings_.find(format);
    if (it != encodings_.end())
        return it->second;

    // Encode the entity authentication data.
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put<string>(KEY_SCHEME, scheme_.name());
    mo->put(KEY_AUTHDATA, getAuthData(encoder, format));
    shared_ptr<ByteArray> encoding = encoder->encodeObject(mo, format);

    // Cache and return the encoding.
    encodings_.insert(make_pair(format, encoding));
    return encoding;
}

bool EntityAuthenticationData::equals(shared_ptr<const EntityAuthenticationData> obj) const
{
    if (obj.get() == this) return true;
    return scheme_ == obj->scheme_;
}

bool operator==(const EntityAuthenticationData& a, const EntityAuthenticationData& b)
{
	shared_ptr<const EntityAuthenticationData> ap(&a, &MslUtils::nullDeleter<EntityAuthenticationData>);
	shared_ptr<const EntityAuthenticationData> bp(&b, &MslUtils::nullDeleter<EntityAuthenticationData>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::entityauth
