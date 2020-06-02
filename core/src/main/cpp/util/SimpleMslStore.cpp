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

#include <util/SimpleMslStore.h>
#include <MslConstants.h>
#include <MslError.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <crypto/ICryptoContext.h>
#include <tokens/MasterToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslUtils.h>
#include <util/Mutex.h>
#include <algorithm>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace util {

namespace {
/**
 * Increments the provided non-replayable ID by 1, wrapping around to zero
 * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
 *
 * @param id the non-replayable ID to increment.
 * @return the non-replayable ID + 1.
 * @throws MslInternalException if the provided non-replayable ID is out of
 *         range.
 */
int64_t incrementNonReplayableId(int64_t id) {
    if (id < 0 || id > MslConstants::MAX_LONG_VALUE) {
    	stringstream ss;
    	ss << "Non-replayable ID " << id << " is outside the valid range.";
        throw MslInternalException(ss.str());
    }
    return (id == MslConstants::MAX_LONG_VALUE) ? 0 : id + 1;
}

} // namespace anonymous

void SimpleMslStore::setCryptoContext(shared_ptr<MasterToken> masterToken, shared_ptr<ICryptoContext> cryptoContext) {
	if (!cryptoContext) {
		removeCryptoContext(masterToken);
	} else {
		CryptoContextMap::iterator it = find_if(cryptoContexts_.begin(), cryptoContexts_.end(), MslUtils::sharedPtrKeyEqual<CryptoContextMap>(masterToken));
		if (it != cryptoContexts_.end())
			cryptoContexts_.erase(it);
		cryptoContexts_.insert(make_pair(masterToken, cryptoContext));
	}
}

shared_ptr<MasterToken> SimpleMslStore::getMasterToken() {
	LockGuard lg(mutex_);

	shared_ptr<MasterToken> masterToken;
	for (CryptoContextMap::const_iterator masterTokens = cryptoContexts_.begin();
		 masterTokens != cryptoContexts_.end();
		 ++masterTokens)
	{
		const shared_ptr<MasterToken> storedMasterToken = masterTokens->first;
		if (!masterToken || storedMasterToken->isNewerThan(masterToken))
			masterToken = storedMasterToken;
	}
	return masterToken;
}

int64_t SimpleMslStore::getNonReplayableId(shared_ptr<MasterToken> masterToken) {
	LockGuard lg(mutex_);

	// Return the next largest non-replayable ID, or 1 if there is none.
	const int64_t serialNumber = masterToken->getSerialNumber();
	NonReplayableIdMap::const_iterator ids = nonReplayableIds_.find(serialNumber);
	const int64_t currentId = (ids != nonReplayableIds_.end())
			? ids->second
			: 0;
	const int64_t nextId = incrementNonReplayableId(currentId);
	nonReplayableIds_.erase(serialNumber);
	nonReplayableIds_.insert(make_pair(serialNumber, nextId));
	return nextId;
}

shared_ptr<ICryptoContext> SimpleMslStore::getCryptoContext(shared_ptr<MasterToken> masterToken) {
	LockGuard lg(mutex_);

	CryptoContextMap::iterator it = find_if(cryptoContexts_.begin(), cryptoContexts_.end(), MslUtils::sharedPtrKeyEqual<CryptoContextMap>(masterToken));
	return (it != cryptoContexts_.end()) ? it->second : shared_ptr<ICryptoContext>();
}

void SimpleMslStore::removeCryptoContext(shared_ptr<MasterToken> masterToken) {
	LockGuard lg(mutex_);

    // We must perform the removal operations in reverse-dependency order.
    // This ensures the store is in the correct state, allowing all logical
    // and safety checks to pass.
    //
    // First any bound user ID tokens are removed (which first removes any
    // service tokens bound to those user ID tokens), then bound service
    // tokens, and finally the non-replayable ID and crypto context and
    // master token pair.
	CryptoContextMap::iterator it = find_if(cryptoContexts_.begin(), cryptoContexts_.end(), MslUtils::sharedPtrKeyEqual<CryptoContextMap>(masterToken));
	if (it != cryptoContexts_.end()) {
        // Look for a second master token with the same serial number. If
        // there is one, then just remove this master token and its crypto
        // context but do not remove any bound user ID tokens, service
        // tokens, or the non-replayable ID as those are still associated
        // with the master token that remains.
		const int64_t serialNumber = masterToken->getSerialNumber();
		for (CryptoContextMap::const_iterator tokens = cryptoContexts_.begin();
			 tokens != cryptoContexts_.end();
			 ++tokens)
		{
			const shared_ptr<MasterToken> token = tokens->first;
			if (token != masterToken && token->getSerialNumber() == serialNumber) {
		        cryptoContexts_.erase(it);
				return;
			}
		}

		// Remove bound user ID tokens and service tokens.
		UserIdTokenMap::iterator userIdTokens = userIdTokens_.begin();
		while (userIdTokens != userIdTokens_.end()) {
			 // Incremented early to allow modification of the user ID
			 // token map from ::removeUserIdToken().
			shared_ptr<UserIdToken>& userIdToken = userIdTokens->second;
			++userIdTokens;
			if (userIdToken->isBoundTo(masterToken))
				removeUserIdToken(userIdToken);
		}
		try {
			removeServiceTokens(shared_ptr<std::string>(), masterToken, shared_ptr<UserIdToken>());
		} catch (const MslException& e) {
			// This should not happen since we are only providing a master
			// token.
			//
			// FIXME Have to recast the exception otherwise the type is lost.
			throw MslInternalException("Unexpected exception while removing master token bound service tokens.", e);
		}

        // Remove the non-replayable ID.
        nonReplayableIds_.erase(serialNumber);

		// Finally remove the crypto context.
        cryptoContexts_.erase(it);
	}
}

void SimpleMslStore::clearCryptoContexts() {
	LockGuard lg(mutex_);

	cryptoContexts_.clear();
	nonReplayableIds_.clear();
	userIdTokens_.clear();
	uitServiceTokens_.clear();
	mtServiceTokens_.clear();
}

void SimpleMslStore::addUserIdToken(const std::string& userId, shared_ptr<UserIdToken> userIdToken) {
	LockGuard lg(mutex_);

	bool foundMasterToken = false;
	for (CryptoContextMap::const_iterator masterTokens = cryptoContexts_.begin();
		 masterTokens != cryptoContexts_.end();
		 ++masterTokens)
	{
		const shared_ptr<MasterToken> masterToken = masterTokens->first;
		if (userIdToken->isBoundTo(masterToken)) {
			foundMasterToken = true;
			break;
		}
	}
	if (!foundMasterToken) {
		stringstream ss;
		ss << "uit mtserialnumber " << userIdToken->getMasterTokenSerialNumber();
		throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_NOT_FOUND, ss.str());
	}
	userIdTokens_.erase(userId);
	userIdTokens_.insert(make_pair(userId, userIdToken));
}

shared_ptr<UserIdToken> SimpleMslStore::getUserIdToken(const std::string& userId) {
	LockGuard lg(mutex_);

	UserIdTokenMap::const_iterator tokens = userIdTokens_.find(userId);
	return (tokens != userIdTokens_.end()) ? tokens->second : shared_ptr<UserIdToken>();
}

void SimpleMslStore::removeUserIdToken(shared_ptr<UserIdToken> userIdToken) {
	LockGuard lg(mutex_);

	// Find the master token this user ID token is bound to.
	shared_ptr<MasterToken> masterToken;
	for (CryptoContextMap::const_iterator tokens = cryptoContexts_.begin();
		 tokens != cryptoContexts_.end();
		 ++tokens)
	{
		const shared_ptr<MasterToken> token = tokens->first;
		if (userIdToken->isBoundTo(token)) {
			masterToken = token;
			break;
		}
	}

	// If we didn't find a master token we shouldn't be able to find a user
	// ID token, but it doesn't hurt to try anyway and clean things up.
	UserIdTokenMap::iterator entry = userIdTokens_.begin();
	while(entry != userIdTokens_.end()) {
		if (entry->second == userIdToken) {
			try {
				removeServiceTokens(shared_ptr<std::string>(), masterToken, userIdToken);
			} catch (const MslException& e) {
				// This should not happen since we have already confirmed
				// that the user ID token is bound to the master token.
				//
				// FIXME Have to recast the exception otherwise the type is lost.
				throw MslInternalException("Unexpected exception while removing user ID token bound service tokens.", e);
			}
            userIdTokens_.erase(entry++);
			break;
		} else {
			++entry;
		}
	}
}

void SimpleMslStore::clearUserIdTokens() {
	LockGuard lg(mutex_);

	set<shared_ptr<UserIdToken>> tokens;
	for (UserIdTokenMap::const_iterator userIdTokens = userIdTokens_.begin();
		 userIdTokens != userIdTokens_.end();
		 ++userIdTokens
	)
	{
	    tokens.insert(userIdTokens->second);
	}
	for (set<shared_ptr<UserIdToken>>::iterator token = tokens.begin();
	     token != tokens.end();
	     ++token)
	{
	    removeUserIdToken(*token);
	}
}

void SimpleMslStore::addServiceTokens(set<shared_ptr<ServiceToken>> tokens) {
	LockGuard lg(mutex_);

	// Verify we recognize the bound service tokens.
	for (set<shared_ptr<ServiceToken>>::const_iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		const shared_ptr<ServiceToken>& token = *it;

		// Verify master token bound.
		if (token->isMasterTokenBound()) {
			bool foundMasterToken = false;
			for (CryptoContextMap::const_iterator masterTokens = cryptoContexts_.begin();
				 masterTokens != cryptoContexts_.end();
				 ++masterTokens)
			{
				const shared_ptr<MasterToken> masterToken = masterTokens->first;
				if (token->isBoundTo(masterToken)) {
					foundMasterToken = true;
					break;
				}
			}
			if (!foundMasterToken) {
				stringstream ss;
				ss << "st mtserialnumber " << token->getMasterTokenSerialNumber();
				throw MslException(MslError::SERVICETOKEN_MASTERTOKEN_NOT_FOUND, ss.str());
			}
		}

		// Verify user token bound.
		if (token->isUserIdTokenBound()) {
			bool foundUserIdToken = false;
			for (UserIdTokenMap::const_iterator userIdTokens = userIdTokens_.begin();
				 userIdTokens != userIdTokens_.end();
				 ++userIdTokens)
			{
				const shared_ptr<UserIdToken>& userIdToken = userIdTokens->second;
				if (token->isBoundTo(userIdToken)) {
					foundUserIdToken = true;
					break;
				}
			}
			if (!foundUserIdToken) {
				stringstream ss;
				ss << "st uitserialnumber " << token->getUserIdTokenSerialNumber();
				throw MslException(MslError::SERVICETOKEN_USERIDTOKEN_NOT_FOUND, ss.str());
			}
		}
	}

	// Add service tokens.
	for (set<shared_ptr<ServiceToken>>::const_iterator it = tokens.begin();
		 it != tokens.end();
		 ++it)
	{
		const shared_ptr<ServiceToken>& token = *it;

		// Unbound?
		if (token->isUnbound()) {
			UnboundServiceTokensSet::iterator it = find_if(unboundServiceTokens_.begin(), unboundServiceTokens_.end(), MslUtils::sharedPtrEqual<UnboundServiceTokensSet>(token));
			if (it != unboundServiceTokens_.end())
				unboundServiceTokens_.erase(it);
			unboundServiceTokens_.insert(token);
			continue;
		}

		// Master token bound?
		if (token->isMasterTokenBound()) {
			MasterTokenServiceTokensMap::const_iterator sets = mtServiceTokens_.find(token->getMasterTokenSerialNumber());
			set<shared_ptr<ServiceToken>> tokenSet;
			if (sets != mtServiceTokens_.end())
				tokenSet = sets->second;
			tokenSet.insert(token);
			mtServiceTokens_.erase(token->getMasterTokenSerialNumber());
			mtServiceTokens_.insert(make_pair(token->getMasterTokenSerialNumber(), tokenSet));
		}

		// User ID token bound?
		if (token->isUserIdTokenBound()) {
			UserIdTokenServiceTokensMap::const_iterator sets = uitServiceTokens_.find(token->getUserIdTokenSerialNumber());
			set<shared_ptr<ServiceToken>> tokenSet;
			if (sets != uitServiceTokens_.end())
				tokenSet = sets->second;
			tokenSet.insert(token);
			uitServiceTokens_.erase(token->getUserIdTokenSerialNumber());
			uitServiceTokens_.insert(make_pair(token->getUserIdTokenSerialNumber(), tokenSet));
		}
	}
}

set<shared_ptr<ServiceToken>> SimpleMslStore::getServiceTokens(shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken) {
	LockGuard lg(mutex_);

	// Validate arguments.
	if (userIdToken.get()) {
		if (!masterToken.get())
			throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_NULL);
		if (!userIdToken->isBoundTo(masterToken)) {
			stringstream ss;
			ss << "uit mtserialnumber " << userIdToken->getMasterTokenSerialNumber() << "; mt " << masterToken->getSerialNumber();
			throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str());
		}
	}

	// Grab service tokens. We start with the set of unbound service
	// tokens.
	set<shared_ptr<ServiceToken>> serviceTokens;
	serviceTokens.insert(unboundServiceTokens_.begin(), unboundServiceTokens_.end());
	// If we have a master token add the set of master token bound service
	// tokens that are not bound to any user ID tokens.
	if (masterToken.get()) {
		MasterTokenServiceTokensMap::const_iterator mtTokenSets = mtServiceTokens_.find(masterToken->getSerialNumber());
		if (mtTokenSets != mtServiceTokens_.end()) {
			const set<shared_ptr<ServiceToken>>& mtTokenSet = mtTokenSets->second;
			for (set<shared_ptr<ServiceToken>>::const_iterator mtTokens = mtTokenSet.begin();
				 mtTokens != mtTokenSet.end();
				 ++mtTokens)
			{
				const shared_ptr<ServiceToken>& mtToken = *mtTokens;
				if (!mtToken->isUserIdTokenBound())
					serviceTokens.insert(mtToken);
			}
		}
	}
	// If we have a user ID token (and because of the check above a master
	// token) add the set of user ID token bound service tokens that are
	// also bound to the same master token.
	if (userIdToken.get()) {
		UserIdTokenServiceTokensMap::const_iterator uitTokenSets = uitServiceTokens_.find(userIdToken->getSerialNumber());
		if (uitTokenSets != uitServiceTokens_.end()) {
			const set<shared_ptr<ServiceToken>>& uitTokenSet = uitTokenSets->second;
			for (set<shared_ptr<ServiceToken>>::const_iterator uitTokens = uitTokenSet.begin();
				 uitTokens != uitTokenSet.end();
				 ++uitTokens)
			{
				const shared_ptr<ServiceToken>& uitToken = *uitTokens;
				if (uitToken->isBoundTo(masterToken))
					serviceTokens.insert(uitToken);
			}
		}
	}

	return serviceTokens;
}

void SimpleMslStore::removeServiceTokens(shared_ptr<string> name, shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken) {
	LockGuard lg(mutex_);

	// Validate arguments.
	if (userIdToken && masterToken &&
		!userIdToken->isBoundTo(masterToken))
	{
		stringstream ss;
		ss << "uit mtserialnumber " << userIdToken->getMasterTokenSerialNumber() << "; mt " << masterToken->getSerialNumber();
		throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str());
	}

	// If only a name was provided remove all unbound tokens with that
	// name.
	if (name && !masterToken && !userIdToken) {
		// Remove all unbound tokens with the specified name.
		UnboundServiceTokensSet::iterator unboundTokens = unboundServiceTokens_.begin();
		while (unboundTokens != unboundServiceTokens_.end()) {
			const shared_ptr<ServiceToken>& unboundToken = *unboundTokens;
			if (unboundToken->getName() == *name)
				unboundServiceTokens_.erase(unboundTokens++);
			else
				++unboundTokens;
		}
	}

	// If a master token was provided but no user ID token was provided,
	// remove all tokens bound to the master token. If a name was also
	// provided then limit removal to tokens with the specified name.
	if (masterToken && !userIdToken) {
		const int64_t mtSerialNumber = masterToken->getSerialNumber();
		MasterTokenServiceTokensMap::iterator mtTokenEntries = mtServiceTokens_.find(mtSerialNumber);
		if (mtTokenEntries != mtServiceTokens_.end()) {
			set<shared_ptr<ServiceToken>> tokenSet = mtTokenEntries->second;
			set<shared_ptr<ServiceToken>>::iterator tokens = tokenSet.begin();
			while (tokens != tokenSet.end()) {
				const shared_ptr<ServiceToken>& token = *tokens;

				// Skip if the name was provided and it does not match.
				if (name && token->getName() != *name) {
					++tokens;
					continue;
				}

				// Remove the token.
				tokenSet.erase(tokens++);
			}
			mtServiceTokens_.erase(mtSerialNumber);
			mtServiceTokens_.insert(make_pair(mtSerialNumber, tokenSet));
		}
	}

    // If a user ID token was provided remove all tokens bound to the user
    // ID token. If a name was also provided then limit removal to tokens
    // with the specified name.
	if (userIdToken) {
		const int64_t uitSerialNumber = userIdToken->getSerialNumber();
		UserIdTokenServiceTokensMap::iterator sets = uitServiceTokens_.find(uitSerialNumber);
		if (sets != uitServiceTokens_.end()) {
			set<shared_ptr<ServiceToken>>& tokenSet = sets->second;
			set<shared_ptr<ServiceToken>>::iterator tokens = tokenSet.begin();
			while (tokens != tokenSet.end()) {
				const shared_ptr<ServiceToken>& token = *tokens;

				// Skip if the name was provided and it does not match.
				if (name && token->getName() != *name) {
					++tokens;
					continue;
				}

				// Remove the token.
				tokenSet.erase(tokens++);
			}
			uitServiceTokens_.insert(make_pair(uitSerialNumber, tokenSet));
		}
	}
}

void SimpleMslStore::clearServiceTokens() {
	LockGuard lg(mutex_);

	unboundServiceTokens_.clear();
	mtServiceTokens_.clear();
	uitServiceTokens_.clear();
}

}}} // namespace netflix::msl::util
