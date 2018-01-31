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
#include <entityauth/EccAuthenticationData.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <util/MslUtils.h>
#include <MslEncodingException.h>
#include <MslError.h>

using namespace std;
using namespace netflix::msl;
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
} // namespace anonymous

EccAuthenticationData::EccAuthenticationData(shared_ptr<MslObject> eccAuthMo)
	: EntityAuthenticationData(EntityAuthenticationScheme::ECC)
{
	try {
		// Extract ECC authentication data.
		identity_ = eccAuthMo->getString(KEY_IDENTITY);
		pubkeyid_ = eccAuthMo->getString(KEY_PUBKEY_ID);
	} catch (const MslEncoderException& e) {
		stringstream ss;
		ss << "ECC authdata " << eccAuthMo;
		throw new MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
	}
}

shared_ptr<MslObject> EccAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat&) const
{
	shared_ptr<MslObject> mo = encoder->createObject();
	mo->put(KEY_IDENTITY, identity_);
	mo->put(KEY_PUBKEY_ID, pubkeyid_);
	return mo;
}

bool EccAuthenticationData::equals(shared_ptr<const EntityAuthenticationData> obj) const
{
	if (this == obj.get()) return true;
	if (!instanceof<const EccAuthenticationData>(obj.get())) return false;
	shared_ptr<const EccAuthenticationData> that = dynamic_pointer_cast<const EccAuthenticationData>(obj);
	return EntityAuthenticationData::equals(obj) && identity_ == that->identity_ && pubkeyid_ == that->pubkeyid_;
}

bool operator==(const EccAuthenticationData& a, const EccAuthenticationData& b)
{
	shared_ptr<const EccAuthenticationData> ap(&a, &MslUtils::nullDeleter<EccAuthenticationData>);
	shared_ptr<const EccAuthenticationData> bp(&b, &MslUtils::nullDeleter<EccAuthenticationData>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::entityauth
