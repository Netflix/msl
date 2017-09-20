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
#include <entityauth/UnauthenticatedAuthenticationData.h>
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
}

UnauthenticatedAuthenticationData::UnauthenticatedAuthenticationData(const string identity)
    : EntityAuthenticationData(EntityAuthenticationScheme::NONE), identity_(identity)
{
}

// note weird syntax to handle an exception thrown in initializer list
UnauthenticatedAuthenticationData::UnauthenticatedAuthenticationData(shared_ptr<MslObject> unauthenticatedAuthMo)
try
    : EntityAuthenticationData(EntityAuthenticationScheme::NONE)
    , identity_(unauthenticatedAuthMo->getString(KEY_IDENTITY))
{
}
catch (const MslEncoderException& e)
{
    stringstream ss;
    ss << "unauthenticated authdata " << unauthenticatedAuthMo;
    throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
}

shared_ptr<MslObject> UnauthenticatedAuthenticationData::getAuthData(shared_ptr<MslEncoderFactory> factory,
        const MslEncoderFormat& ) const
{
    shared_ptr<MslObject> mo = factory->createObject();
    mo->put<string>(KEY_IDENTITY, identity_);
    return mo;
}

bool UnauthenticatedAuthenticationData::equals(shared_ptr<const EntityAuthenticationData> obj) const
{
	if (!obj) return false;
    if (this == obj.get()) return true;
    if (!instanceof<const UnauthenticatedAuthenticationData>(obj.get())) return false;
    shared_ptr<const UnauthenticatedAuthenticationData> that = dynamic_pointer_cast<const UnauthenticatedAuthenticationData>(obj);
    return EntityAuthenticationData::equals(obj) && identity_ == that->identity_;
}

bool operator==(const UnauthenticatedAuthenticationData& a, const UnauthenticatedAuthenticationData& b)
{
	shared_ptr<const UnauthenticatedAuthenticationData> ap(&a, &MslUtils::nullDeleter<UnauthenticatedAuthenticationData>);
	shared_ptr<const UnauthenticatedAuthenticationData> bp(&b, &MslUtils::nullDeleter<UnauthenticatedAuthenticationData>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::entityauth
