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

#include <entityauth/PresharedAuthenticationData.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <util/MslUtils.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
const string KEY_IDENTITY = "identity";
}

PresharedAuthenticationData::PresharedAuthenticationData(const string identity)
    : EntityAuthenticationData(EntityAuthenticationScheme::PSK), identity_(identity)
{
}

// note weird syntax to handle an exception thrown in initializer list
PresharedAuthenticationData::PresharedAuthenticationData(shared_ptr<MslObject> presharedAuthMo)
try
    : EntityAuthenticationData(EntityAuthenticationScheme::PSK)
    , identity_(presharedAuthMo->getString(KEY_IDENTITY))
{
}
catch (const MslEncoderException& e)
{
    stringstream ss;
    ss << "psk authdata " << presharedAuthMo;
    throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
}


shared_ptr<MslObject> PresharedAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> factory,
        const MslEncoderFormat& ) const
{
    shared_ptr<MslObject> mo = factory->createObject();
    mo->put<string>(KEY_IDENTITY, identity_);
    return mo;
}

bool PresharedAuthenticationData::equals(std::shared_ptr<const EntityAuthenticationData> obj) const
{
    if (this == obj.get()) return true;
    if (!instanceof<const PresharedAuthenticationData>(obj.get())) return false;
    shared_ptr<const PresharedAuthenticationData> that = dynamic_pointer_cast<const PresharedAuthenticationData>(obj);
    return EntityAuthenticationData::equals(obj) && (identity_ == that->getIdentity());
}

bool operator==(const PresharedAuthenticationData& a, const PresharedAuthenticationData& b)
{
	shared_ptr<const PresharedAuthenticationData> ap(&a, &MslUtils::nullDeleter<PresharedAuthenticationData>);
	shared_ptr<const PresharedAuthenticationData> bp(&b, &MslUtils::nullDeleter<PresharedAuthenticationData>);
	return ap->equals(bp);
}
}}} // namespace netflix::msl::entityauth
