/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include <msg/IdempotentResponseMessageBuilder.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <crypto/IRandom.h>
#include <crypto/NullCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <msg/ErrorHeader.h>
#include <msg/MessageHeader.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/ServiceToken.h>
#include <tokens/TokenFactory.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationFactory.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/MslContext.h>
#include <util/MslStore.h>
#include <util/MslUtils.h>
#include <vector>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;
using KeyExchangeData = netflix::msl::keyx::KeyExchangeFactory::KeyExchangeData;
using HeaderData = netflix::msl::msg::MessageHeader::HeaderData;
using HeaderPeerData = netflix::msl::msg::MessageHeader::HeaderPeerData;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace msg {

IdempotentResponseMessageBuilder::IdempotentResponseMessageBuilder(
        shared_ptr<MslContext> ctx,
        shared_ptr<MessageHeader> requestHeader)
    : MessageBuilder(ctx)
{
    shared_ptr<MasterToken> masterToken = requestHeader->getMasterToken();
    shared_ptr<EntityAuthenticationData> entityAuthData = requestHeader->getEntityAuthenticationData();
    shared_ptr<UserIdToken> userIdToken = requestHeader->getUserIdToken();
    shared_ptr<UserAuthenticationData> userAuthData = requestHeader->getUserAuthenticationData();

    // The response message ID must be equal to the request message ID + 1.
    const int64_t requestMessageId = requestHeader->getMessageId();
    const int64_t messageId = incrementMessageId(requestMessageId);

    // Compute the intersection of the request and response message
    // capabilities.
    shared_ptr<MessageCapabilities> capabilities = MessageCapabilities::intersection(requestHeader->getMessageCapabilities(), ctx->getMessageCapabilities());

    // Create the message builder.
    //
    // Peer-to-peer responses swap the tokens.
    try {
        shared_ptr<KeyResponseData> keyResponseData = requestHeader->getKeyResponseData();
        set<shared_ptr<ServiceToken>> serviceTokens = requestHeader->getServiceTokens();
        if (ctx->isPeerToPeer()) {
            shared_ptr<MasterToken> peerMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : requestHeader->getPeerMasterToken();
            shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
            set<shared_ptr<ServiceToken>> peerServiceTokens = requestHeader->getPeerServiceTokens();
            initializeMessageBuilder(messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, shared_ptr<KeyExchangeData>());
        } else {
            shared_ptr<MasterToken> localMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : masterToken;
            initializeMessageBuilder(messageId, capabilities, localMasterToken, userIdToken, serviceTokens, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
        }
    } catch (MslException& e) {
        e.setMasterToken(masterToken);
        e.setEntityAuthenticationData(entityAuthData);
        e.setUserIdToken(userIdToken);
        e.setUserAuthenticationData(userAuthData);
        e.setMessageId(requestMessageId);
        throw e;
    }
}

}}} // namespace netflix::msl::msg
