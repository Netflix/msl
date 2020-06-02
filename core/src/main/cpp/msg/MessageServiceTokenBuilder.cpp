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

#include <msg/MessageServiceTokenBuilder.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <crypto/ICryptoContext.h>
#include <keyx/KeyExchangeFactory.h>
#include <msg/MessageBuilder.h>
#include <msg/MessageContext.h>
#include <tokens/MasterToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslContext.h>
#include <MslConstants.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;
using namespace netflix::msl::MslConstants;
using KeyExchangeData = netflix::msl::keyx::KeyExchangeFactory::KeyExchangeData;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/**
 * <p>Select the appropriate crypto context for the named service token.</p>
 *
 * <p>If the service token name exists as a key in the map of crypto
 * contexts, the mapped crypto context will be returned. Otherwise the
 * default crypto context mapped from the empty string key will be returned.
 * If no explicit or default crypto context exists null will be
 * returned.</p>
 *
 * @param name service token name.
 * @param cryptoContexts the map of service token names onto crypto
 *        contexts used to decrypt and verify service tokens.
 * @return the correct crypto context for the service token or null.
 */
shared_ptr<ICryptoContext> selectCryptoContext(const string& name, map<string,shared_ptr<ICryptoContext>> cryptoContexts)
{
	map<string,shared_ptr<ICryptoContext>>::const_iterator it = cryptoContexts.find(name);
	if (it != cryptoContexts.end())
		return it->second;
	it = cryptoContexts.find("");
	if (it != cryptoContexts.end())
		return it->second;
	return shared_ptr<ICryptoContext>();
}

shared_ptr<MasterToken> NULL_MASTER_TOKEN;
shared_ptr<UserIdToken> NULL_USER_ID_TOKEN;
} // namespace anonymous

MessageServiceTokenBuilder::MessageServiceTokenBuilder(shared_ptr<MslContext> ctx,
		shared_ptr<MessageContext> msgCtx,
		shared_ptr<MessageBuilder> builder)
	: ctx_(ctx)
	, cryptoContexts_(msgCtx->getCryptoContexts())
	, builder_(builder)
{
}

shared_ptr<MasterToken> MessageServiceTokenBuilder::getPrimaryMasterToken()
{
    // If key exchange data is provided and we are not in peer-to-peer mode
    // then its master token will be used for creating service tokens.
    shared_ptr<KeyExchangeData> keyExchangeData = builder_->getKeyExchangeData();
    if (keyExchangeData && !ctx_->isPeerToPeer()) {
        return keyExchangeData->keyResponseData->getMasterToken();
    } else {
        return builder_->getMasterToken();
    }
}

bool MessageServiceTokenBuilder::isPrimaryMasterTokenAvailable()
{
	return getPrimaryMasterToken().get() != 0;
}

bool MessageServiceTokenBuilder::isPrimaryUserIdTokenAvailable()
{
	return builder_->getUserIdToken().get() != 0;
}

bool MessageServiceTokenBuilder::isPeerMasterTokenAvailable()
{
	return builder_->getPeerMasterToken() != 0;
}

bool MessageServiceTokenBuilder::isPeerUserIdTokenAvailable()
{
	return builder_->getPeerUserIdToken() != 0;
}

set<shared_ptr<tokens::ServiceToken>> MessageServiceTokenBuilder::getPrimaryServiceTokens()
{
	return builder_->getServiceTokens();
}

set<shared_ptr<ServiceToken>> MessageServiceTokenBuilder::getPeerServiceTokens()
{
	return builder_->getPeerServiceTokens();
}

bool MessageServiceTokenBuilder::addPrimaryServiceToken(shared_ptr<ServiceToken> serviceToken)
{
	try {
		builder_->addServiceToken(serviceToken);
		return true;
	} catch (const MslMessageException& e) {
		return false;
	}
}

bool MessageServiceTokenBuilder::addPeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
	try {
		builder_->addPeerServiceToken(serviceToken);
		return true;
	} catch (const MslMessageException& e) {
		return false;
	}
}

bool MessageServiceTokenBuilder::addUnboundPrimaryServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::addUnboundPeerServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addPeerServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::addMasterBoundPrimaryServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no master token.
	shared_ptr<MasterToken> masterToken = getPrimaryMasterToken();
	if (!masterToken)
		return false;

	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, masterToken, NULL_USER_ID_TOKEN, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::addMasterBoundPeerServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no master token.
	shared_ptr<MasterToken> masterToken = builder_->getPeerMasterToken();
	if (!masterToken)
		return false;

	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, masterToken, NULL_USER_ID_TOKEN, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addPeerServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::addUserBoundPrimaryServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no master token.
	shared_ptr<MasterToken> masterToken = getPrimaryMasterToken();
	if (!masterToken)
		return false;

	// Fail if there is no user ID token.
	shared_ptr<UserIdToken> userIdToken = builder_->getUserIdToken();
	if (!userIdToken)
		return false;

	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::addUserBoundPeerServiceToken(const string& name, shared_ptr<ByteArray> data, bool encrypt, MslConstants::CompressionAlgorithm compressionAlgo)
{
	// Fail if there is no master token.
	shared_ptr<MasterToken> masterToken = builder_->getPeerMasterToken();
	if (!masterToken)
		return false;

	// Fail if there is no user ID token.
	shared_ptr<UserIdToken> userIdToken = builder_->getPeerUserIdToken();
	if (!userIdToken)
		return false;

	// Fail if there is no crypto context.
	shared_ptr<ICryptoContext> cryptoContext = selectCryptoContext(name, cryptoContexts_);
	if (!cryptoContext)
		return false;

	// Add the service token.
	shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx_, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext);
	try {
		builder_->addPeerServiceToken(serviceToken);
	} catch (const MslMessageException& e) {
		throw MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
	}
	return true;
}

bool MessageServiceTokenBuilder::excludePrimaryServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return excludePrimaryServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

bool MessageServiceTokenBuilder::excludePrimaryServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
	// Exclude the service token if found.
	set<shared_ptr<ServiceToken>> serviceTokens = builder_->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		if ((*serviceToken)->getName() == name &&
		    (*serviceToken)->isMasterTokenBound() == masterTokenBound &&
		    (*serviceToken)->isUserIdTokenBound() == userIdTokenBound)
		{
			builder_->excludeServiceToken(name, masterTokenBound, userIdTokenBound);
			return true;
		}
	}

	// Not found.
	return false;
}

bool MessageServiceTokenBuilder::excludePeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return excludePeerServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

bool MessageServiceTokenBuilder::excludePeerServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
	// Exclude the service token if found.
	set<shared_ptr<ServiceToken>> serviceTokens = builder_->getPeerServiceTokens();
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		if ((*serviceToken)->getName() == name &&
	        (*serviceToken)->isMasterTokenBound() == masterTokenBound &&
	        (*serviceToken)->isUserIdTokenBound() == userIdTokenBound)
		{
			builder_->excludePeerServiceToken(name, masterTokenBound, userIdTokenBound);
			return true;
		}
	}

	// Not found.
	return false;
}

bool MessageServiceTokenBuilder::deletePrimaryServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return deletePrimaryServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

bool MessageServiceTokenBuilder::deletePrimaryServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
    // Mark the service token for deletion if found.
	set<shared_ptr<ServiceToken>> serviceTokens = builder_->getServiceTokens();
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		if ((*serviceToken)->getName() == name &&
	        (*serviceToken)->isMasterTokenBound() == masterTokenBound &&
	        (*serviceToken)->isUserIdTokenBound() == userIdTokenBound)
		{
			builder_->deleteServiceToken(name, masterTokenBound, userIdTokenBound);
			return true;
		}
	}

	// Not found.
	return false;
}

bool MessageServiceTokenBuilder::deletePeerServiceToken(shared_ptr<ServiceToken> serviceToken)
{
    return deletePeerServiceToken(serviceToken->getName(), serviceToken->isMasterTokenBound(), serviceToken->isUserIdTokenBound());
}

bool MessageServiceTokenBuilder::deletePeerServiceToken(const string& name, const bool masterTokenBound, const bool userIdTokenBound)
{
    // Mark the service token for deletion if found.
	set<shared_ptr<ServiceToken>> serviceTokens = builder_->getPeerServiceTokens();
	for (set<shared_ptr<ServiceToken>>::const_iterator serviceToken = serviceTokens.begin();
		 serviceToken != serviceTokens.end();
		 ++serviceToken)
	{
		if ((*serviceToken)->getName() == name &&
	        (*serviceToken)->isMasterTokenBound() == masterTokenBound &&
	        (*serviceToken)->isUserIdTokenBound() == userIdTokenBound)
		{
			builder_->deletePeerServiceToken(name, masterTokenBound, userIdTokenBound);
			return true;
		}
	}

	// Not found.
	return false;
}

}}} // namespace netflix::msl::msg
