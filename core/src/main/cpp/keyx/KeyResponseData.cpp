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
#include <io/MslObject.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyResponseData.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslKeyExchangeException.h>
#include <tokens/MasterToken.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

namespace {
/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";
/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key data. */
const string KEY_KEYDATA = "keydata";
} // namespace anonymous

KeyResponseData::KeyResponseData(shared_ptr<MasterToken> masterToken, const KeyExchangeScheme& scheme)
: masterToken(masterToken), scheme(scheme)
{
}

//static
shared_ptr<KeyResponseData> KeyResponseData::create(shared_ptr<MslContext> ctx, shared_ptr<MslObject> keyResponseDataMo)
{
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();

    try {
        // Pull the key data.
        shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, keyResponseDataMo->getMslObject(KEY_MASTER_TOKEN, encoder));
        const string schemeName = keyResponseDataMo->getString(KEY_SCHEME);
        const KeyExchangeScheme scheme = ctx->getKeyExchangeScheme(schemeName);
        if (scheme == KeyExchangeScheme::INVALID)
            throw MslKeyExchangeException(MslError::UNIDENTIFIED_KEYX_SCHEME, schemeName);
        shared_ptr<MslObject> keyData = keyResponseDataMo->getMslObject(KEY_KEYDATA, encoder);

        // Construct an instance of the concrete subclass.
        shared_ptr<KeyExchangeFactory> factory = ctx->getKeyExchangeFactory(scheme);
        if (!factory)
            throw MslKeyExchangeException(MslError::KEYX_FACTORY_NOT_FOUND, scheme.name());
        return factory->createResponseData(ctx, masterToken, keyData);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "keyresponsedata " + keyResponseDataMo->toString(), e);
    }
}

shared_ptr<ByteArray> KeyResponseData::toMslEncoding(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_MASTER_TOKEN, dynamic_pointer_cast<MslEncodable>(masterToken));
    mo->put(KEY_SCHEME, scheme.name());
    mo->put(KEY_KEYDATA, getKeydata(encoder, format));
    return encoder->encodeObject(mo, format);
}

bool KeyResponseData::equals(std::shared_ptr<const KeyResponseData> that) const
{
    if (!that) return false;
    if (that.get() == this) return true;
    return *masterToken == *that->masterToken && scheme == that->scheme;
}

bool operator==(const KeyResponseData& a, const KeyResponseData& b)
{
	shared_ptr<const KeyResponseData> ap(&a, &MslUtils::nullDeleter<KeyResponseData>);
	shared_ptr<const KeyResponseData> bp(&b, &MslUtils::nullDeleter<KeyResponseData>);
	return ap->equals(bp);
}

ostream& operator<<(ostream& os, const KeyResponseData& data)
{
	return os << data.scheme.name();
}

ostream& operator<<(ostream& os, shared_ptr<KeyResponseData> data)
{
	return os << *data;
}

}}} // namespace netflix::msl::keyx
