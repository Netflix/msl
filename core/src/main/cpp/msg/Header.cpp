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

#include <crypto/ICryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslEncoderException.h>
#include <io/MslObject.h>
#include <msg/MessageHeader.h>
#include <msg/ErrorHeader.h>
#include <msg/Header.h>
#include <msg/HeaderKeys.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslMessageException.h>
#include <tokens/MasterToken.h>
#include <util/MslContext.h>
#include <util/MslStore.h>
#include <util/MslUtils.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

// static
shared_ptr<Header> Header::parseHeader(shared_ptr<MslContext> ctx,
        shared_ptr<MslObject> headerMo,
        const map<string, shared_ptr<ICryptoContext>> cryptoContexts)
{
    // Pull authentication data.
    shared_ptr<entityauth::EntityAuthenticationData> entityAuthData;
    shared_ptr<MasterToken> masterToken;
    shared_ptr<ByteArray> signature;
    try {
        // Pull message data.
        shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
        entityAuthData = (headerMo->has(HeaderKeys::KEY_ENTITY_AUTHENTICATION_DATA))
                     ? EntityAuthenticationData::create(ctx, headerMo->getMslObject(HeaderKeys::KEY_ENTITY_AUTHENTICATION_DATA, encoder))
                     : shared_ptr<EntityAuthenticationData>();
        masterToken = (headerMo->has(HeaderKeys::KEY_MASTER_TOKEN))
                     ? make_shared<MasterToken>(ctx, headerMo->getMslObject(HeaderKeys::KEY_MASTER_TOKEN, encoder))
                     : shared_ptr<MasterToken>();
        signature = headerMo->getBytes(HeaderKeys::KEY_SIGNATURE);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "header/errormsg " + headerMo->toString(), e);
    }

    try {
        // Process message headers.
        if (headerMo->has(HeaderKeys::KEY_HEADERDATA)) {
            shared_ptr<ByteArray> headerdata = headerMo->getBytes(HeaderKeys::KEY_HEADERDATA);
            if (headerdata->empty())
                throw MslMessageException(MslError::HEADER_DATA_MISSING, *Base64::encode(headerdata)).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
            return make_shared<MessageHeader>(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts);
        }

        // Process error headers.
        else if (headerMo->has(HeaderKeys::KEY_ERRORDATA)) {
            shared_ptr<ByteArray> errordata = headerMo->getBytes(HeaderKeys::KEY_ERRORDATA);
            if (errordata->empty())
                throw MslMessageException(MslError::HEADER_DATA_MISSING, *Base64::encode(errordata)).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
            return make_shared<ErrorHeader>(ctx, errordata, entityAuthData, signature);
        }

        // Unknown header.
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, headerMo->toString());
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "header/errormsg " + headerMo->toString(), e);
    }
    return shared_ptr<Header>();
}

bool operator==(const Header& a, const Header& b)
{
	shared_ptr<const Header> ap(&a, &MslUtils::nullDeleter<Header>);
	shared_ptr<const Header> bp(&b, &MslUtils::nullDeleter<Header>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::msg
