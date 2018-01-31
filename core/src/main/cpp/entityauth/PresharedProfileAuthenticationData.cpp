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
#include <entityauth/PresharedProfileAuthenticationData.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <util/MslUtils.h>
#include <cassert>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity preshared keys identity. */
const string KEY_PSKID = "pskid";
/** Key entity profile. */
const string KEY_PROFILE = "profile";

/** Identity concatenation character. */
const string CONCAT_CHAR = "-";

} // namespace anonymous


PresharedProfileAuthenticationData::PresharedProfileAuthenticationData(const string& pskid, const string& profile)
: EntityAuthenticationData(EntityAuthenticationScheme::PSK_PROFILE)
, pskid(pskid)
, profile(profile)
{
}

PresharedProfileAuthenticationData::PresharedProfileAuthenticationData(shared_ptr<MslObject> authMo)
: EntityAuthenticationData(EntityAuthenticationScheme::PSK_PROFILE)
{
    assert(authMo);
    try {
        pskid = authMo->getString(KEY_PSKID);
        profile = authMo->getString(KEY_PROFILE);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "psk profile authdata " + authMo->toString(), e);
    }
}

string PresharedProfileAuthenticationData::getIdentity() const
{
    return pskid + CONCAT_CHAR + profile;
}

shared_ptr<MslObject> PresharedProfileAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat&) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_PSKID, pskid);
    mo->put(KEY_PROFILE, profile);
    return mo;
}

bool PresharedProfileAuthenticationData::equals(shared_ptr<const EntityAuthenticationData> obj) const
{
	if (!obj) return false;
    if (this == obj.get()) return true;
    if (!instanceof<const PresharedProfileAuthenticationData>(obj)) return false;
    shared_ptr<const PresharedProfileAuthenticationData> that = dynamic_pointer_cast<const PresharedProfileAuthenticationData>(obj);
    return EntityAuthenticationData::equals(obj) && pskid == that->pskid && profile == that->profile;
}

bool operator==(const PresharedProfileAuthenticationData& a, const PresharedProfileAuthenticationData& b)
{
	shared_ptr<const PresharedProfileAuthenticationData> ap(&a, &MslUtils::nullDeleter<PresharedProfileAuthenticationData>);
	shared_ptr<const PresharedProfileAuthenticationData> bp(&b, &MslUtils::nullDeleter<PresharedProfileAuthenticationData>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl:entityauth
