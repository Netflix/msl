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

#include <msg/MessageFactory.h>
#include <msg/MessageInputStream.h>
#include <msg/MessageOutputStream.h>
#include <msg/MessageBuilder.h>
#include <msg/ResponseMessageBuilder.h>
#include <msg/IdempotentResponseMessageBuilder.h>
#include <msg/ErrorHeader.h>
#include <msg/ErrorHeader.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <entityauth/EntityAuthenticationData.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <MslConstants.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;
using namespace netflix::msl::tokens;
using namespace netflix::msl::entityauth;

namespace netflix {
namespace msl {
namespace msg {


shared_ptr<MessageInputStream> MessageFactory::createInputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<InputStream> source,
		set<shared_ptr<keyx::KeyRequestData>> keyRequestData,
		map<string,shared_ptr<ICryptoContext>> cryptoContexts)
{
	return make_shared<MessageInputStream>(ctx, source, keyRequestData, cryptoContexts);
}

shared_ptr<MessageOutputStream> MessageFactory::createOutputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<ErrorHeader> header,
		const MslEncoderFormat& format)
{
	return make_shared<MessageOutputStream>(ctx, destination, header, format);
}

shared_ptr<MessageOutputStream> MessageFactory::createOutputStream(
		shared_ptr<MslContext> ctx,
		shared_ptr<OutputStream> destination,
		shared_ptr<MessageHeader> header,
		shared_ptr<ICryptoContext> cryptoContext)
{
	return make_shared<MessageOutputStream>(ctx, destination, header, cryptoContext);
}

shared_ptr<MessageBuilder> MessageFactory::createRequest(
        shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        int64_t messageId)
{
	return make_shared<MessageBuilder>(ctx, masterToken, userIdToken, messageId);
}

shared_ptr<MessageBuilder> MessageFactory::createRequest(
        shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken)
{
	return make_shared<MessageBuilder>(ctx, masterToken, userIdToken);
}

shared_ptr<ErrorHeader> MessageFactory::createErrorResponse(
        shared_ptr<MslContext> ctx,
		int64_t requestMessageId,
		MslError error,
		string userMessage)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	// If we have the request message ID then the error response message ID
	// must be equal to the request message ID + 1.
	int64_t messageId;
	if (requestMessageId != -1) {
		messageId = MessageBuilder::incrementMessageId(requestMessageId);
	}
	// Otherwise use a random message ID.
	else {
	    messageId = MslUtils::getRandomLong(ctx);
	}
	const MslConstants::ResponseCode errorCode = error.getResponseCode();
	const int32_t internalCode = error.getInternalCode();
	const string errorMsg = error.getMessage();
	return make_shared<ErrorHeader>(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMessage);
}

shared_ptr<MessageBuilder> MessageFactory::createResponse(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageHeader> requestHeader)
{
    return make_shared<ResponseMessageBuilder>(ctx, requestHeader);
}

shared_ptr<MessageBuilder> MessageFactory::createIdempotentResponse(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MessageHeader> requestHeader)
{
    return make_shared<IdempotentResponseMessageBuilder>(ctx, requestHeader);
}

}}} // namespace netflix::msl::msg
