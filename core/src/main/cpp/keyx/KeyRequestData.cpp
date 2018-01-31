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

#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <keyx/KeyRequestData.h>
#include <io/MslObject.h>
#include <keyx/KeyExchangeFactory.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslKeyExchangeException.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

namespace {
/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key request data. */
const string KEY_KEYDATA = "keydata";
} // namespace anonymous

//static
shared_ptr<KeyRequestData> KeyRequestData::create(shared_ptr<MslContext> ctx,
        shared_ptr<MslObject> keyRequestDataMo)
{
    try {
        // Pull the key data.
        const string schemeName = keyRequestDataMo->getString(KEY_SCHEME);
        const KeyExchangeScheme scheme = ctx->getKeyExchangeScheme(schemeName);
        if (scheme == KeyExchangeScheme::INVALID)
            throw MslKeyExchangeException(MslError::UNIDENTIFIED_KEYX_SCHEME, schemeName);
        shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
        shared_ptr<MslObject> keyData = keyRequestDataMo->getMslObject(KEY_KEYDATA, encoder);

        // Construct an instance of the concrete subclass.
        shared_ptr<KeyExchangeFactory> keyFactory = ctx->getKeyExchangeFactory(scheme);
        if (!keyFactory)
            throw MslKeyExchangeException(MslError::KEYX_FACTORY_NOT_FOUND, scheme.name());
        return keyFactory->createRequestData(ctx, keyData);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keyrequestdata " + keyRequestDataMo->toString(), e);
    }
}

shared_ptr<ByteArray> KeyRequestData::toMslEncoding(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, scheme.name());
    mo->put(KEY_KEYDATA, getKeydata(encoder, format));
    return encoder->encodeObject(mo, format);
}

bool KeyRequestData::equals(shared_ptr<const KeyRequestData> base) const
{
    if (!base) return false;
    if (this == base.get()) return true;
    return scheme == base->scheme;
}

bool operator==(const KeyRequestData& a, const KeyRequestData& b)
{
	shared_ptr<const KeyRequestData> ap(&a, &MslUtils::nullDeleter<KeyRequestData>);
	shared_ptr<const KeyRequestData> bp(&b, &MslUtils::nullDeleter<KeyRequestData>);
	return ap->equals(bp);
}

ostream& operator<<(ostream& os, const KeyRequestData& data)
{
	// FIXME
	return os << data.scheme.name();
}

ostream& operator<<(ostream& os, shared_ptr<KeyRequestData> data)
{
	return os << *data;
}

}}} // namespace netflix::msl::keyx
