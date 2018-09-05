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

#include <msg/ResponseMessageBuilder.h>
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

namespace {

/**
 * Issue a new master token for the specified identity or renew an existing
 * master token.
 *
 * @param ctx MSL context.
 * @param format MSL encoder format.
 * @param keyRequestData available key request data.
 * @param masterToken master token to renew. Null if the identity is
 *        provided.
 * @param entityAuthData entity authentication data. Null if a master token
 *        is provided.
 * @return the new master token and crypto context or {@code} null if the
 *         factory chooses not to perform key exchange.
 * @throws MslCryptoException if the crypto context cannot be created.
 * @throws MslKeyExchangeException if there is an error with the key
 *         request data or the key response data cannot be created or none
 *         of the key exchange schemes are supported.
 * @throws MslMasterTokenException if the master token is not trusted.
 * @throws MslEncodingException if there is an error parsing or encoding
 *         the JSON.
 * @throws MslEntityAuthException if there is a problem with the master
 *         token identity or entity identity.
 * @throws MslException if there is an error creating or renewing the
 *         master token.
 */
shared_ptr<KeyExchangeData> issueMasterToken(shared_ptr<MslContext> ctx,
		const MslEncoderFormat& format,
		set<shared_ptr<KeyRequestData>> keyRequestData,
		shared_ptr<MasterToken> masterToken,
		shared_ptr<EntityAuthenticationData> entityAuthData)
{
	// Attempt key exchange in the preferred order.
	shared_ptr<IException> keyxException;
	set<shared_ptr<KeyExchangeFactory>> factorySet = ctx->getKeyExchangeFactories();
	for (set<shared_ptr<KeyExchangeFactory>>::iterator factories = factorySet.begin();
		 factories != factorySet.end();
		 ++factories)
	{
		shared_ptr<KeyExchangeFactory> factory = *factories;
		set<shared_ptr<KeyRequestData>>::iterator requests = keyRequestData.begin();
		while (requests != keyRequestData.end()) {
			shared_ptr<KeyRequestData> request = *requests;
			if (factory->getScheme() != request->getKeyExchangeScheme()) {
			    requests++;
				continue;
			}

			// Attempt the key exchange, but if it fails try with the next
			// combination before giving up.
			try {
				if (masterToken)
					return factory->generateResponse(ctx, format, request, masterToken);
				else
					return factory->generateResponse(ctx, format, request, entityAuthData);
			} catch (const MslCryptoException& e) {
				if (requests == keyRequestData.end()) throw e;
				keyxException = e.clone();
			} catch (const MslKeyExchangeException& e) {
				if (requests == keyRequestData.end()) throw e;
				keyxException = e.clone();
			} catch (const MslEncodingException& e) {
				if (requests == keyRequestData.end()) throw e;
				keyxException = e.clone();
			} catch (const MslMasterTokenException& e) {
				if (requests == keyRequestData.end()) throw e;
				keyxException = e.clone();
			} catch (const MslEntityAuthException& e) {
				if (requests == keyRequestData.end()) throw e;
				keyxException = e.clone();
			}

			requests++;
		}
	}

	// We did not perform a successful key exchange. If we caught an
	// exception then throw that exception now.
	if (keyxException) {
		MslUtils::rethrow(keyxException);
		throw MslInternalException("Unexpected exception caught during key exchange.", *keyxException);
	}

	// If we didn't find any then we're unable to perform key exchange.
	stringstream ss;
	ss << "[ ";
	for (set<shared_ptr<KeyRequestData>>::iterator keyRequests = keyRequestData.begin();
		 keyRequests != keyRequestData.end();
		 ++keyRequests)
	{
		ss << *keyRequests << " ";
	}
	ss << "]";
	throw MslKeyExchangeException(MslError::KEYX_FACTORY_NOT_FOUND, ss.str());
}

} // namespace anonymous


ResponseMessageBuilder::ResponseMessageBuilder(
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

	// Identify the response format.
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	set<MslEncoderFormat> formats;
	if (capabilities) formats = capabilities->getEncoderFormats();
	const MslEncoderFormat format = encoder->getPreferredFormat(formats);

	try {
		// If the message contains key request data and is renewable...
		shared_ptr<KeyExchangeData> keyExchangeData;
		set<shared_ptr<KeyRequestData>> keyRequestData = requestHeader->getKeyRequestData();
		if (requestHeader->isRenewable() && !keyRequestData.empty()) {
			// If the message contains a master token...
			if (masterToken) {
				// If the master token is renewable or expired then renew
				// the master token.
				if (masterToken->isRenewable() || masterToken->isExpired())
					keyExchangeData = issueMasterToken(ctx, format, keyRequestData, masterToken, shared_ptr<EntityAuthenticationData>());
				// Otherwise we don't need to do anything special.
				else
					keyExchangeData.reset();
			}

			// Otherwise use the entity authentication data to issue a
			// master token.
			else {
				// The message header is already authenticated via the
				// entity authentication data's crypto context so we can
				// simply proceed with the master token issuance.
				keyExchangeData = issueMasterToken(ctx, format, keyRequestData, shared_ptr<MasterToken>(), entityAuthData);
			}
		}

		// If the message does not contain key request data there is no key
		// exchange for us to do.
		else {
			keyExchangeData.reset();
		}

		// If we successfully performed key exchange, use the new master
		// token for user authentication.
		shared_ptr<MasterToken> userAuthMasterToken;
		if (keyExchangeData) {
			userAuthMasterToken = keyExchangeData->keyResponseData->getMasterToken();
		} else {
			userAuthMasterToken = masterToken;
		}

		// If the message contains a user ID token issued by the local
		// entity...
		if (userIdToken && userIdToken->isVerified()) {
			// If the user ID token is renewable and the message is
			// renewable, or it is expired, or it needs to be rebound
			// to the new master token then renew the user ID token.
			if ((userIdToken->isRenewable() && requestHeader->isRenewable()) ||
					userIdToken->isExpired() ||
					!userIdToken->isBoundTo(userAuthMasterToken))
			{
				shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
				userIdToken = tokenFactory->renewUserIdToken(ctx, userIdToken, userAuthMasterToken);
			}
		}

		// If the message is renewable and contains user authentication
		// data and a master token then we need to attempt user
		// authentication and issue a user ID token.
		else if (requestHeader->isRenewable() && userAuthMasterToken && userAuthData) {
			// If this request was parsed then its user authentication data
			// should have been authenticated and the user will exist. If
			// it was not parsed, then we need to perform user
			// authentication now.
			shared_ptr<MslUser> user = requestHeader->getUser();
			if (!user) {
				const UserAuthenticationScheme scheme = userAuthData->getScheme();
				shared_ptr<UserAuthenticationFactory> factory = ctx->getUserAuthenticationFactory(scheme);
				if (!factory) {
					throw MslUserAuthException(MslError::USERAUTH_FACTORY_NOT_FOUND, scheme.name())
					.setMasterToken(masterToken)
					.setUserAuthenticationData(userAuthData)
					.setMessageId(requestMessageId);
				}
				user = factory->authenticate(ctx, userAuthMasterToken->getIdentity(), userAuthData, shared_ptr<UserIdToken>());
			}
			shared_ptr<TokenFactory> tokenFactory = ctx->getTokenFactory();
			userIdToken = tokenFactory->createUserIdToken(ctx, user, userAuthMasterToken);
		}

		// Create the message builder.
		//
		// Peer-to-peer responses swap the tokens.
		shared_ptr<KeyResponseData> keyResponseData = requestHeader->getKeyResponseData();
		set<shared_ptr<ServiceToken>> serviceTokens = requestHeader->getServiceTokens();
		if (ctx->isPeerToPeer()) {
			shared_ptr<MasterToken> peerMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : requestHeader->getPeerMasterToken();
			shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
			set<shared_ptr<ServiceToken>> peerServiceTokens = requestHeader->getPeerServiceTokens();
			initializeMessageBuilder(messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, keyExchangeData);
		} else {
			shared_ptr<MasterToken> localMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : masterToken;
			initializeMessageBuilder(messageId, capabilities, localMasterToken, userIdToken, serviceTokens, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), keyExchangeData);
		}
	} catch (MslException& e) {
		e.setMasterToken(masterToken);
		e.setEntityAuthenticationData(entityAuthData);
		e.setUserIdToken(userIdToken);
		e.setUserAuthenticationData(userAuthData);
		e.setMessageId(requestMessageId);
		MslUtils::rethrow(e);
		throw e;
	}
}

}}} // namespace netflix::msl::msg
