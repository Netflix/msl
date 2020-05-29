/**
 * Copyright (c) 2016-2020 Netflix, Inc.  All rights reserved.
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

MessageBuilder::MessageBuilder(
        shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        int64_t messageId)
    : MessageBuilder(ctx)
{
	if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
		stringstream ss;
		ss << "Message ID " << messageId << " is outside the valid range.";
		throw MslInternalException(ss.str());
	}
	shared_ptr<MessageCapabilities> capabilities = ctx->getMessageCapabilities();
	initializeMessageBuilder(messageId, capabilities, masterToken, userIdToken, set<shared_ptr<ServiceToken>>(), shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
}

MessageBuilder::MessageBuilder(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken)
    : MessageBuilder(ctx)
{
	const int64_t messageId = MslUtils::getRandomLong(ctx);
	shared_ptr<MessageCapabilities> capabilities = ctx->getMessageCapabilities();
	initializeMessageBuilder(messageId, capabilities, masterToken, userIdToken, set<shared_ptr<ServiceToken>>(), shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), set<shared_ptr<ServiceToken>>(), shared_ptr<KeyExchangeData>());
}

void MessageBuilder::initializeMessageBuilder(
        int64_t messageId,
        shared_ptr<MessageCapabilities> capabilities,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken,
        set<shared_ptr<ServiceToken>> serviceTokens,
        shared_ptr<MasterToken> peerMasterToken,
        shared_ptr<UserIdToken> peerUserIdToken,
        set<shared_ptr<ServiceToken>> peerServiceTokens,
        shared_ptr<KeyExchangeData> keyExchangeData)
{
    masterToken_ = masterToken;
    messageId_ = messageId;
    keyExchangeData_ = keyExchangeData;
    capabilities_ = capabilities;
    userIdToken_ = userIdToken;

	// Primary and peer token combinations will be verified when the
	// message header is constructed. So delay those checks in favor of
	// avoiding duplicate code.
	if (!ctx_->isPeerToPeer() && (peerMasterToken || peerUserIdToken))
		throw MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");

	// If key exchange data is provided and we are not in peer-to-peer mode
	// then its master token should be used for querying service tokens.
	shared_ptr<MasterToken> serviceMasterToken;
	if (keyExchangeData && !ctx_->isPeerToPeer()) {
		serviceMasterToken = keyExchangeData->keyResponseData->getMasterToken();
	} else {
		serviceMasterToken = masterToken;
	}

	// Set the initial service tokens based on the MSL store and provided
	// service tokens.
	set<shared_ptr<ServiceToken>> tokens = ctx_->getMslStore()->getServiceTokens(serviceMasterToken, userIdToken);
	serviceTokens_.insert(tokens.begin(), tokens.end());
	for (set<shared_ptr<ServiceToken>>::iterator token = serviceTokens.begin();
		 token != serviceTokens.end();
		 ++token)
	{
        // Make sure the service token is properly bound.
        if ((*token)->isMasterTokenBound() && !(*token)->isBoundTo(serviceMasterToken)) {
            stringstream ss;
            ss << "st " << *token << "; mt " << serviceMasterToken;
            throw MslMessageException(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(serviceMasterToken);
        }
        if ((*token)->isUserIdTokenBound() && !(*token)->isBoundTo(userIdToken)) {
            stringstream ss;
            ss << "st " << *token << "; uit " << userIdToken;
            throw MslMessageException(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, ss.str()).setMasterToken(serviceMasterToken).setUserIdToken(userIdToken);
        }

		// Add the service token.
        serviceTokens_.erase(*token);
		serviceTokens_.insert(*token);
	}

	// Set the peer-to-peer data.
	if (ctx_->isPeerToPeer()) {
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
		set<shared_ptr<ServiceToken>> peerTokens = ctx_->getMslStore()->getServiceTokens(peerServiceMasterToken, peerUserIdToken);
		peerServiceTokens_.insert(peerTokens.begin(), peerTokens.end());
		for (set<shared_ptr<ServiceToken>>::iterator peerToken = peerServiceTokens.begin();
			 peerToken != peerServiceTokens.end();
			 ++peerToken)
		{
            // Make sure the service token is properly bound.
            if ((*peerToken)->isMasterTokenBound() && !(*peerToken)->isBoundTo(peerMasterToken)) {
                stringstream ss;
                ss << "st " << *peerToken << "; mt " << peerMasterToken;
                throw MslMessageException(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, ss.str()).setMasterToken(peerMasterToken);
            }
            if ((*peerToken)->isUserIdTokenBound() && !(*peerToken)->isBoundTo(peerUserIdToken)) {
                stringstream ss;
                ss << "st " << *peerToken << "; uit " << peerUserIdToken;
                throw MslMessageException(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, ss.str()).setMasterToken(peerMasterToken).setUserIdToken(peerUserIdToken);
            }

            // Add the peer service token.
            peerServiceTokens_.erase(*peerToken);
			peerServiceTokens_.insert(*peerToken);
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
	int64_t nonReplayableId;
	if (nonReplayable_) {
		if (!masterToken_)
			throw MslMessageException(MslError::NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN);
		nonReplayableId = ctx_->getMslStore()->getNonReplayableId(masterToken_);
	} else {
		nonReplayableId = -1;
	}
	shared_ptr<HeaderData> headerData = make_shared<HeaderData>( messageId_, nonReplayableId, renewable_, handshake_, capabilities_, keyRequestData_, response, userAuthData_, userIdToken_, serviceTokens_);
	shared_ptr<HeaderPeerData> peerData = make_shared<HeaderPeerData>(peerMasterToken_, peerUserIdToken_, peerServiceTokens_);

	return createMessageHeader(ctx_, ctx_->getEntityAuthenticationData(), masterToken_, headerData, peerData);
}

shared_ptr<MessageHeader> MessageBuilder::createMessageHeader(
        std::shared_ptr<util::MslContext> ctx,
        std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
        std::shared_ptr<tokens::MasterToken> masterToken,
        std::shared_ptr<HeaderData> headerData,
        std::shared_ptr<HeaderPeerData> peerData)
{
	return make_shared<MessageHeader>(ctx, entityAuthData, masterToken, headerData, peerData);
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
	set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens_.begin();
	while (tokens != serviceTokens_.end()) {
		shared_ptr<ServiceToken> token = *tokens;
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
	    excludeServiceToken((*token)->getName(), (*token)->isMasterTokenBound(), (*token)->isUserIdTokenBound());
		serviceTokens_.insert(*token);
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

    // Remove any existing service token with the same name and bound state.
    excludeServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());

	// Add the service token.
	serviceTokens_.insert(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::addServiceTokenIfAbsent(shared_ptr<ServiceToken> serviceToken)
{
    for (set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens_.begin();
         tokens != serviceTokens_.end();
         ++tokens)
    {
        shared_ptr<ServiceToken> token = (*tokens);
        if (token->getName() == serviceToken->getName() &&
            token->isMasterTokenBound() == serviceToken->isMasterTokenBound() &&
            token->isUserIdTokenBound() == serviceToken->isUserIdTokenBound())
        {
            return shared_from_this();
        }
    }
    addServiceToken(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::excludeServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return excludeServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

shared_ptr<MessageBuilder> MessageBuilder::excludeServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
    set<shared_ptr<ServiceToken>>::iterator tokens = serviceTokens_.begin();
    while (tokens != serviceTokens_.end()) {
        shared_ptr<ServiceToken> token = (*tokens);
        if (token->getName() == name &&
            token->isMasterTokenBound() == masterTokenBound &&
            token->isUserIdTokenBound() == userIdTokenBound)
        {
            serviceTokens_.erase(tokens++);
        } else {
            ++tokens;
        }
    }
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::deleteServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return deleteServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

shared_ptr<MessageBuilder> MessageBuilder::deleteServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
	// Rebuild the original token with empty service data.
	shared_ptr<MasterToken> masterToken;
	if (masterTokenBound) masterToken = masterToken_;
	shared_ptr<UserIdToken> userIdToken;
	if (userIdTokenBound) userIdToken = userIdToken_;
	try {
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx_, name, EMPTY_DATA, masterToken, userIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
		return addServiceToken(token);
	} catch (const MslException& e) {
		throw MslInternalException("Failed to create and add empty service token to message.", e);
	}
}

set<shared_ptr<ServiceToken>> MessageBuilder::getServiceTokens() {
	set<shared_ptr<ServiceToken>> tokens(serviceTokens_);
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
	set<shared_ptr<ServiceToken>>::iterator tokens = peerServiceTokens_.begin();
	while(tokens != peerServiceTokens_.end()) {
	    shared_ptr<ServiceToken> token = *tokens;
	    if ((token->isUserIdTokenBound() && !token->isBoundTo(userIdToken)) ||
	        (token->isMasterTokenBound() && !token->isBoundTo(masterToken)))
	    {
	        peerServiceTokens_.erase(tokens++);
	    } else {
	        ++tokens;
	    }
	}

	// Add any peer service tokens based on the MSL store if they are not
	// already set (as a set one may be newer than the stored one).
	for (set<shared_ptr<ServiceToken>>::iterator token = storedTokens.begin();
		 token != storedTokens.end();
		 ++token)
	{
	    excludePeerServiceToken((*token)->getName(), (*token)->isMasterTokenBound(), (*token)->isUserIdTokenBound());
	    peerServiceTokens_.insert(*token);
	}

	// Set the new peer authentication tokens.
	peerUserIdToken_ = userIdToken;
	peerMasterToken_ = masterToken;
}

shared_ptr<MessageBuilder> MessageBuilder::addPeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    // If we are not in peer-to-peer mode then peer service tokens cannot
    // be set.
	if (!ctx_->isPeerToPeer())
		throw MslInternalException("Cannot set peer service tokens when not in peer-to-peer mode.");

    // Make sure the service token is properly bound.
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

    // Remove any existing service token with the same name and bound state.
    excludePeerServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());

	// Add the peer service token.
	peerServiceTokens_.insert(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::addPeerServiceTokenIfAbsent(shared_ptr<ServiceToken> serviceToken)
{
	set<shared_ptr<ServiceToken>>::iterator tokens = peerServiceTokens_.begin();
	while (tokens != peerServiceTokens_.end()) {
	    shared_ptr<ServiceToken> token = *tokens;
	    if (token->getName() == serviceToken->getName() &&
	        token->isMasterTokenBound() == serviceToken->isMasterTokenBound() &&
	        token->isUserIdTokenBound() == serviceToken->isUserIdTokenBound())
	    {
	        return shared_from_this();
	    }
	}
	addPeerServiceToken(serviceToken);
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::excludePeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return excludePeerServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

shared_ptr<MessageBuilder> MessageBuilder::excludePeerServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
    set<shared_ptr<ServiceToken>>::iterator tokens = peerServiceTokens_.begin();
    while (tokens != peerServiceTokens_.end()) {
        shared_ptr<ServiceToken> token = *tokens;
        if (token->getName() == name &&
            token->isMasterTokenBound() == masterTokenBound &&
            token->isUserIdTokenBound() == userIdTokenBound)
        {
            peerServiceTokens_.erase(tokens++);
        } else {
            ++tokens;
        }
    }
	return shared_from_this();
}

shared_ptr<MessageBuilder> MessageBuilder::deletePeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return deletePeerServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

shared_ptr<MessageBuilder> MessageBuilder::deletePeerServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
	// Rebuild the original token with empty service data.
	shared_ptr<MasterToken> peerMasterToken;
	if (masterTokenBound) peerMasterToken = peerMasterToken_;
	shared_ptr<UserIdToken> peerUserIdToken;
	if (userIdTokenBound) peerUserIdToken = peerUserIdToken_;
	try {
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx_, name, EMPTY_DATA, peerMasterToken, peerUserIdToken, false, CompressionAlgorithm::NOCOMPRESSION, make_shared<NullCryptoContext>());
		return addPeerServiceToken(token);
	} catch (const MslException& e) {
		throw MslInternalException("Failed to create and add empty peer service token to message.", e);
	}
}

set<shared_ptr<ServiceToken>> MessageBuilder::getPeerServiceTokens()
{
	set<shared_ptr<ServiceToken>> tokens(peerServiceTokens_);
	return tokens;
}

}}} // namespace netflix::msl::msg
