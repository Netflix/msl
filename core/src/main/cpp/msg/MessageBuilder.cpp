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

#include <msg/MessageBuilder.h>
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

/** Empty service token data. */
shared_ptr<ByteArray> EMPTY_DATA = make_shared<ByteArray>();

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

int64_t MessageBuilder::incrementMessageId(const int64_t messageId) {
	if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Message ID " << messageId << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}
	return (messageId == MslConstants::MAX_LONG_VALUE) ? 0 : messageId + 1;
}

int64_t MessageBuilder::decrementMessageId(const int64_t messageId) {
	if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Message ID " << messageId << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}
	return (messageId == 0) ? MslConstants::MAX_LONG_VALUE : messageId - 1;
}

shared_ptr<MessageBuilder> MessageBuilder::createRequest(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        int64_t messageId)
{
	if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Message ID " << messageId << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}
	shared_ptr<MessageCapabilities> capabilities = ctx->getMessageCapabilities();
	return make_shared<MessageBuilder>(ctx, messageId, capabilities, masterToken, userIdToken, set<shared_ptr<ServiceToken>>(), shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
}

shared_ptr<MessageBuilder> MessageBuilder::createRequest(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken)
{
	const int64_t messageId = MslUtils::getRandomLong(ctx);
	shared_ptr<MessageCapabilities> capabilities = ctx->getMessageCapabilities();
	return make_shared<MessageBuilder>(ctx, messageId, capabilities, masterToken, userIdToken, set<shared_ptr<ServiceToken>>(), shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
}

shared_ptr<MessageBuilder> MessageBuilder::createResponse(shared_ptr<MslContext> ctx,
        shared_ptr<MessageHeader> requestHeader)
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
			return make_shared<MessageBuilder>(ctx, messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, keyExchangeData);
		} else {
			shared_ptr<MasterToken> localMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : masterToken;
			return make_shared<MessageBuilder>(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), keyExchangeData);
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

shared_ptr<MessageBuilder> MessageBuilder::createIdempotentResponse(shared_ptr<MslContext> ctx,
        shared_ptr<MessageHeader> requestHeader)
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
            return make_shared<MessageBuilder>(ctx, messageId, capabilities, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, shared_ptr<KeyExchangeData>());
        } else {
            shared_ptr<MasterToken> localMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : masterToken;
            return make_shared<MessageBuilder>(ctx, messageId, capabilities, localMasterToken, userIdToken, serviceTokens, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
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

shared_ptr<ErrorHeader> MessageBuilder::createErrorResponse(shared_ptr<MslContext> ctx,
		int64_t requestMessageId,
		MslError error,
		string userMessage)
{
	shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData();
	// If we have the request message ID then the error response message ID
	// must be equal to the request message ID + 1.
	int64_t messageId;
	if (requestMessageId != -1) {
		messageId = incrementMessageId(requestMessageId);
	}
	// Otherwise use a random message ID.
	else {
	    messageId = MslUtils::getRandomLong(ctx);
	}
	const ResponseCode errorCode = error.getResponseCode();
	const int32_t internalCode = error.getInternalCode();
	const string errorMsg = error.getMessage();
	return make_shared<ErrorHeader>(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMessage);
}

MessageBuilder::MessageBuilder(shared_ptr<MslContext> ctx,
        int64_t messageId,
        shared_ptr<MessageCapabilities> capabilities,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        set<shared_ptr<ServiceToken>> serviceTokens,
        shared_ptr<MasterToken> peerMasterToken,
        shared_ptr<UserIdToken> peerUserIdToken,
        set<shared_ptr<ServiceToken>> peerServiceTokens,
        shared_ptr<KeyExchangeData> keyExchangeData)
	: ctx_(ctx)
	, masterToken_(masterToken)
	, messageId_(messageId)
	, keyExchangeData_(keyExchangeData)
	, capabilities_(capabilities)
	, userIdToken_(userIdToken)
{
	// Primary and peer token combinations will be verified when the
	// message header is constructed. So delay those checks in favor of
	// avoiding duplicate code.
	if (!ctx->isPeerToPeer() && (peerMasterToken || peerUserIdToken))
		throw MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");

	// If key exchange data is provided and we are not in peer-to-peer mode
	// then its master token should be used for querying service tokens.
	shared_ptr<MasterToken> serviceMasterToken;
	if (keyExchangeData && !ctx->isPeerToPeer()) {
		serviceMasterToken = keyExchangeData->keyResponseData->getMasterToken();
	} else {
		serviceMasterToken = masterToken;
	}

	// Set the initial service tokens based on the MSL store and provided
	// service tokens.
	set<shared_ptr<ServiceToken>> tokens = ctx->getMslStore()->getServiceTokens(serviceMasterToken, userIdToken);
	for (set<shared_ptr<ServiceToken>>::iterator token = tokens.begin();
		 token != tokens.end();
		 ++token)
	{
		serviceTokens_.insert(make_pair((*token)->getName(), *token));
	}
	for (set<shared_ptr<ServiceToken>>::iterator token = serviceTokens.begin();
		 token != serviceTokens.end();
		 ++token)
	{
		serviceTokens_.erase((*token)->getName());
		serviceTokens_.insert(make_pair((*token)->getName(), *token));
	}

	// Set the peer-to-peer data.
	if (ctx->isPeerToPeer()) {
		peerMasterToken_ = peerMasterToken;
		peerUserIdToken_ = peerUserIdToken;

		// If key exchange data is provided then its master token should
		// be used to query peer service tokens.
		shared_ptr<MasterToken> peerServiceMasterToken;
		if (keyExchangeData)
			peerServiceMasterToken = keyExchangeData->keyResponseData->getMasterToken();
		else
			peerServiceMasterToken = peerMasterToken_;

		// Set the initial peer service tokens based on the MSL store and
		// provided peer service tokens.
		set<shared_ptr<ServiceToken>> peerTokens = ctx->getMslStore()->getServiceTokens(peerServiceMasterToken, peerUserIdToken);
		for (set<shared_ptr<ServiceToken>>::iterator peerToken = peerTokens.begin();
				peerToken != peerTokens.end();
				++peerToken)
		{
			peerServiceTokens_.insert(make_pair((*peerToken)->getName(), *peerToken));
		}
		for (set<shared_ptr<ServiceToken>>::iterator peerToken = peerServiceTokens.begin();
			 peerToken != peerServiceTokens.end();
			 ++peerToken)
		{
			peerServiceTokens_.erase((*peerToken)->getName());
			peerServiceTokens_.insert(make_pair((*peerToken)->getName(), *peerToken));
		}
	}
}

bool MessageBuilder::willEncryptHeader()
{
	const EntityAuthenticationScheme scheme = ctx_->getEntityAuthenticationData()->getScheme();
	return masterToken_ || scheme.encrypts();
}

bool MessageBuilder::willEncryptPayloads()
{
	const EntityAuthenticationScheme scheme = ctx_->getEntityAuthenticationData()->getScheme();
	return masterToken_ ||
			(!ctx_->isPeerToPeer() && keyExchangeData_) ||
			scheme.encrypts();
}

bool MessageBuilder::willIntegrityProtectHeader()
{
	const EntityAuthenticationScheme scheme = ctx_->getEntityAuthenticationData()->getScheme();
	return masterToken_ || scheme.protectsIntegrity();
}

bool MessageBuilder::willIntegrityProtectPayloads() {
	const EntityAuthenticationScheme scheme = ctx_->getEntityAuthenticationData()->getScheme();
	return masterToken_ ||
			(!ctx_->isPeerToPeer() && keyExchangeData_) ||
			scheme.protectsIntegrity();
}

shared_ptr<MessageHeader> MessageBuilder::getHeader()
{
	shared_ptr<KeyResponseData> response;
	if (keyExchangeData_) response = keyExchangeData_->keyResponseData;
	set<shared_ptr<ServiceToken>> tokens;
	for (map<string,shared_ptr<ServiceToken>>::iterator token = serviceTokens_.begin();
		 token != serviceTokens_.end();
		 ++token)
	{
		tokens.insert(token->second);
	}
	int64_t nonReplayableId;
	if (nonReplayable_) {
		if (!masterToken_)
			throw MslMessageException(MslError::NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN);
		nonReplayableId = ctx_->getMslStore()->getNonReplayableId(masterToken_);
	} else {
		nonReplayableId = -1;
	}
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>( messageId_, nonReplayableId, renewable_, handshake_, capabilities_, keyRequestData_, response, userAuthData_, userIdToken_, tokens);
	set<shared_ptr<ServiceToken>> peerTokens;
	for (map<string,shared_ptr<ServiceToken>>::iterator token = peerServiceTokens_.begin();
		 token != peerServiceTokens_.end();
		 ++token)
	{
		peerTokens.insert(token->second);
	}
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(peerMasterToken_, peerUserIdToken_, peerTokens);

	return make_shared<MessageHeader>(ctx_, ctx_->getEntityAuthenticationData(), masterToken_, headerData, peerData);
}

shared_ptr<MessageBuilder> MessageBuilder::setMessageId(int64_t messageId)
{
    if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Message ID " << messageId << " is out of range.";
        throw MslInternalException(ss.str());
    }
    messageId_ = messageId;
    return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::setNonReplayable(bool nonReplayable)
{
	nonReplayable_ = nonReplayable;
	if (nonReplayable_)
		handshake_ = false;
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::setRenewable(bool renewable)
{
	renewable_ = renewable;
	if (!renewable_)
		handshake_ = false;
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::setHandshake(bool handshake) {
	handshake_ = handshake;
	if (handshake_) {
		nonReplayable_ = false;
		renewable_ = true;
	}
	return shared_from_this();
}

void MessageBuilder::setAuthTokens(shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken)
{
	// Make sure the assumptions hold. Otherwise a bad message could be
	// built.
	if (userIdToken && !userIdToken->isBoundTo(masterToken))
		throw MslInternalException("User ID token must be bound to master token.");
	// In trusted network mode key exchange data should only exist if this
	// is a server response. In which case this method should not be
	// getting called.
	if (keyExchangeData_ && !ctx_->isPeerToPeer())
		throw MslInternalException("Attempt to set message builder master token when key exchange data exists as a trusted network server.");

	// Load the stored service tokens.
	set<shared_ptr<ServiceToken>> storedTokens;
	try {
		storedTokens = ctx_->getMslStore()->getServiceTokens(masterToken, userIdToken);
	} catch (const MslException& e) {
		// This should never happen because we already checked that the
		// user ID token is bound to the master token.
		throw MslInternalException("Invalid master token and user ID token combination despite checking above.", e);
	}

	// Remove any service tokens that will no longer be bound.
	map<string,shared_ptr<ServiceToken>>::iterator tokens = serviceTokens_.begin();
	while (tokens != serviceTokens_.end()) {
		shared_ptr<ServiceToken> token = tokens->second;
		if ((token->isUserIdTokenBound() && !token->isBoundTo(userIdToken)) ||
			(token->isMasterTokenBound() && !token->isBoundTo(masterToken)))
		{
			serviceTokens_.erase(tokens++);
		} else {
			++tokens;
		}
	}

	// Add any service tokens based on the MSL store replacing ones already
	// set as they may be newer. The application will have a chance to
	// manage the service tokens before the message is constructed and
	// sent.
	for (set<shared_ptr<ServiceToken>>::iterator token = storedTokens.begin();
		 token != storedTokens.end();
		 ++token)
	{
		serviceTokens_.erase((*token)->getName());
		serviceTokens_.insert(make_pair((*token)->getName(), *token));
	}

	// Set the new authentication tokens.
	masterToken_ = masterToken;
	userIdToken_ = userIdToken;
	if (userIdToken_)
		userAuthData_.reset();
}

shared_ptr<MessageBuilder> MessageBuilder::setUserAuthenticationData(shared_ptr<UserAuthenticationData> userAuthData)
{
	userAuthData_ = userAuthData;
	return shared_from_this();
}

void MessageBuilder::setUser(shared_ptr<MslUser> user)
{
	// Make sure the assumptions hold. Otherwise a bad message could be
	// built.
	if ((!ctx_->isPeerToPeer() && userIdToken_) ||
		(ctx_->isPeerToPeer() && peerUserIdToken_))
	{
		throw MslInternalException("User ID token or peer user ID token already exists for the remote user.");
	}

	// If key exchange data is provided then its master token should be
	// used for the new user ID token and for querying service tokens.
	shared_ptr<MasterToken> uitMasterToken;
	if (keyExchangeData_) {
		uitMasterToken = keyExchangeData_->keyResponseData->getMasterToken();
	} else {
		uitMasterToken = (!ctx_->isPeerToPeer()) ? masterToken_ : peerMasterToken_;
	}

	// Make sure we have a master token to create the user for.
	if (!uitMasterToken)
		throw MslInternalException("User ID token or peer user ID token cannot be created because no corresponding master token exists.");

	// Create the new user ID token.
	shared_ptr<TokenFactory> factory = ctx_->getTokenFactory();
	shared_ptr<UserIdToken> userIdToken = factory->createUserIdToken(ctx_, user, uitMasterToken);

	// Set the new user ID token.
	if (!ctx_->isPeerToPeer()) {
		userIdToken_ = userIdToken;
		userAuthData_.reset();
	} else {
		peerUserIdToken_ = userIdToken;
	}
}

shared_ptr<MessageBuilder> MessageBuilder::addKeyRequestData(shared_ptr<KeyRequestData> keyRequestData) {
	keyRequestData_.insert(keyRequestData);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::removeKeyRequestData(shared_ptr<KeyRequestData> keyRequestData) {
	keyRequestData_.erase(keyRequestData);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::addServiceToken(shared_ptr<ServiceToken> serviceToken)
{
	// If key exchange data is provided and we are not in peer-to-peer mode
	// then its master token should be used for querying service tokens.
	shared_ptr<MasterToken> serviceMasterToken;
	if (keyExchangeData_ && !ctx_->isPeerToPeer()) {
		serviceMasterToken = keyExchangeData_->keyResponseData->getMasterToken();
	} else {
		serviceMasterToken = masterToken_;
	}

	// Make sure the service token is properly bound.
	if (serviceToken->isMasterTokenBound() && !serviceToken->isBoundTo(serviceMasterToken)) {
		stringstream ss;
		ss << "st " << serviceToken << "; mt " << serviceMasterToken;
		throw MslMessageException(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(serviceMasterToken);
	}
	if (serviceToken->isUserIdTokenBound() && !serviceToken->isBoundTo(userIdToken_)) {
		stringstream ss;
		ss << "st " << serviceToken << "; uit " << userIdToken_;
		throw MslMessageException(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, ss.str()).setMasterToken(serviceMasterToken).setUserIdToken(userIdToken_);
	}

	// Add the service token.
	serviceTokens_.erase(serviceToken->getName());
	serviceTokens_.insert(make_pair(serviceToken->getName(), serviceToken));
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::addServiceTokenIfAbsent(shared_ptr<ServiceToken> serviceToken)
{
	map<string,shared_ptr<ServiceToken>>::iterator it = serviceTokens_.find(serviceToken->getName());
	if (it == serviceTokens_.end())
		addServiceToken(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::excludeServiceToken(const string& name)
{
	serviceTokens_.erase(name);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::deleteServiceToken(const string& name)
{
	// Do nothing if the original token does not exist.
	map<string,shared_ptr<ServiceToken>>::iterator it = serviceTokens_.find(name);
	if (it == serviceTokens_.end())
		return shared_from_this();
	shared_ptr<ServiceToken> originalToken = it->second;

	// Rebuild the original token with empty service data.
	shared_ptr<MasterToken> masterToken;
	if (originalToken->isMasterTokenBound()) masterToken = masterToken_;
	shared_ptr<UserIdToken> userIdToken;
	if (originalToken->isUserIdTokenBound()) userIdToken = userIdToken_;
	try {
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx_, name, EMPTY_DATA, masterToken, userIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
		return addServiceToken(token);
	} catch (const MslException& e) {
		throw MslInternalException("Failed to create and add empty service token to message.", e);
	}
}

set<shared_ptr<ServiceToken>> MessageBuilder::getServiceTokens() {
	set<shared_ptr<ServiceToken>> tokens;
	for (map<string,shared_ptr<ServiceToken>>::iterator serviceToken = serviceTokens_.begin();
		 serviceToken != serviceTokens_.end();
		 ++serviceToken)
	{
		tokens.insert(serviceToken->second);
	}
	return tokens;
}

void MessageBuilder::setPeerAuthTokens(shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken)
{
	if (!ctx_->isPeerToPeer())
		throw MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");
	if (userIdToken && !masterToken)
		throw MslInternalException("Peer master token cannot be null when setting peer user ID token.");
	if (userIdToken && !userIdToken->isBoundTo(masterToken)) {
		stringstream ss;
		ss << "uit " << userIdToken << "; mt " << masterToken;
		throw MslMessageException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(masterToken).setUserIdToken(userIdToken);
	}

	// Load the stored peer service tokens.
	set<shared_ptr<ServiceToken>> storedTokens;
	try {
		storedTokens = ctx_->getMslStore()->getServiceTokens(masterToken, userIdToken);
	} catch (const MslException& e) {
		// The checks above should have prevented any invalid master token,
		// user ID token combinations.
		throw MslInternalException("Invalid peer master token and user ID token combination despite proper check.", e);
	}

	// Remove any peer service tokens that will no longer be bound.
	set<shared_ptr<ServiceToken>> tokens;
	for (map<string,shared_ptr<ServiceToken>>::iterator token = peerServiceTokens_.begin();
		 token != peerServiceTokens_.end();
		 ++token)
	{
		tokens.insert(token->second);
	}
	for (set<shared_ptr<ServiceToken>>::iterator token = tokens.begin();
		 token != tokens.end();
		 ++token)
	{
		if ((*token)->isUserIdTokenBound() && !(*token)->isBoundTo(userIdToken)) {
			peerServiceTokens_.erase((*token)->getName());
			continue;
		}
		if ((*token)->isMasterTokenBound() && !(*token)->isBoundTo(masterToken)) {
			peerServiceTokens_.erase((*token)->getName());
			continue;
		}
	}

	// Add any peer service tokens based on the MSL store if they are not
	// already set (as a set one may be newer than the stored one).
	for (set<shared_ptr<ServiceToken>>::iterator token = storedTokens.begin();
		 token != storedTokens.end();
		 ++token)
	{
		map<string,shared_ptr<ServiceToken>>::iterator found = peerServiceTokens_.find((*token)->getName());
		if (found == peerServiceTokens_.end())
			peerServiceTokens_.insert(make_pair((*token)->getName(), (*token)));
	}

	// Set the new peer authentication tokens.
	peerUserIdToken_ = userIdToken;
	peerMasterToken_ = masterToken;
}

shared_ptr<MessageBuilder> MessageBuilder::addPeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
	if (!ctx_->isPeerToPeer())
		throw MslInternalException("Cannot set peer service tokens when not in peer-to-peer mode.");
	if (serviceToken->isMasterTokenBound() && !serviceToken->isBoundTo(peerMasterToken_)) {
		stringstream ss;
		ss << "st " << serviceToken << "; mt " << peerMasterToken_;
		throw MslMessageException(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(peerMasterToken_);
	}
	if (serviceToken->isUserIdTokenBound() && !serviceToken->isBoundTo(peerUserIdToken_)) {
		stringstream ss;
		ss << "st " << serviceToken << "; uit " << peerUserIdToken_;
		throw MslMessageException(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, ss.str()).setMasterToken(peerMasterToken_).setUserIdToken(peerUserIdToken_);
	}

	// Add the peer service token.
	peerServiceTokens_.erase(serviceToken->getName());
	peerServiceTokens_.insert(make_pair(serviceToken->getName(), serviceToken));
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::addPeerServiceTokenIfAbsent(shared_ptr<ServiceToken> serviceToken)
{
	map<string,shared_ptr<ServiceToken>>::iterator it = peerServiceTokens_.find(serviceToken->getName());
	if (it == peerServiceTokens_.end())
		addPeerServiceToken(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::excludePeerServiceToken(const string& name)
{
	peerServiceTokens_.erase(name);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::deletePeerServiceToken(const string& name)
{
	// Do nothing if the original token does not exist.
	map<string,shared_ptr<ServiceToken>>::iterator it = peerServiceTokens_.find(name);
	if (it == peerServiceTokens_.end())
		return shared_from_this();
	shared_ptr<ServiceToken> originalToken = it->second;

	// Rebuild the original token with empty service data.
	shared_ptr<MasterToken> peerMasterToken;
	if (originalToken->isMasterTokenBound()) peerMasterToken = peerMasterToken_;
	shared_ptr<UserIdToken> peerUserIdToken;
	if (originalToken->isUserIdTokenBound()) peerUserIdToken = peerUserIdToken_;
	try {
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx_, name, EMPTY_DATA, peerMasterToken, peerUserIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
		return addPeerServiceToken(token);
	} catch (const MslException& e) {
		throw MslInternalException("Failed to create and add empty peer service token to message.", e);
	}
}


set<shared_ptr<ServiceToken>> MessageBuilder::getPeerServiceTokens()
{
	set<shared_ptr<ServiceToken>> tokens;
	for (map<string,shared_ptr<ServiceToken>>::iterator serviceToken = peerServiceTokens_.begin();
		 serviceToken != peerServiceTokens_.end();
		 ++serviceToken)
	{
		tokens.insert(serviceToken->second);
	}
	return tokens;
}

}}} // namespace netflix::msl::msg
