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

#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/RsaAuthenticationData.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity identity. */
const string KEY_IDENTITY = "identity";
/** Key public key ID. */
const string KEY_PUBKEY_ID = "pubkeyid";
}

RsaAuthenticationData::RsaAuthenticationData(const string identity, const string pubkeyid)
    : EntityAuthenticationData(EntityAuthenticationScheme::RSA), identity_(identity), pubkeyid_(pubkeyid)
{
}

// note weird syntax to handle an exception thrown in initializer list
RsaAuthenticationData::RsaAuthenticationData(shared_ptr<MslObject> rsaAuthMo)
try
    : EntityAuthenticationData(EntityAuthenticationScheme::RSA)
    , identity_(rsaAuthMo->getString(KEY_IDENTITY))
	, pubkeyid_(rsaAuthMo->getString(KEY_PUBKEY_ID))
{
}
catch (const MslEncoderException& e)
{
    stringstream ss;
    ss << "rsa authdata " << rsaAuthMo;
    throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
}

shared_ptr<MslObject> RsaAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> factory,
        const MslEncoderFormat& ) const
{
    shared_ptr<MslObject> mo = factory->createObject();
    mo->put<string>(KEY_IDENTITY, identity_);
    mo->put<string>(KEY_PUBKEY_ID, pubkeyid_);
    return mo;
}

bool RsaAuthenticationData::equals(shared_ptr<const EntityAuthenticationData> obj) const
{
    if (this == obj.get()) return true;
    if (!instanceof<const RsaAuthenticationData>(obj.get())) return false;
    shared_ptr<const RsaAuthenticationData> that = dynamic_pointer_cast<const RsaAuthenticationData>(obj);
    return EntityAuthenticationData::equals(obj) && identity_ == that->identity_ && pubkeyid_ == that->pubkeyid_;
}

bool operator==(const RsaAuthenticationData& a, const RsaAuthenticationData& b)
{
	shared_ptr<const RsaAuthenticationData> ap(&a, &MslUtils::nullDeleter<RsaAuthenticationData>);
	shared_ptr<const RsaAuthenticationData> bp(&b, &MslUtils::nullDeleter<RsaAuthenticationData>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::entityauth
