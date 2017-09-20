/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

#include <MslError.h>
#include <MslException.h>
#include <crypto/ICryptoContext.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <util/NullMslStore.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::tokens;

namespace netflix {
namespace msl {
namespace util {

shared_ptr<MasterToken> getMasterToken() {
    return shared_ptr<MasterToken>();
}

shared_ptr<ICryptoContext> NullMslStore::getCryptoContext(shared_ptr<MasterToken> /*masterToken*/) {
    return shared_ptr<ICryptoContext>();
}

shared_ptr<UserIdToken> NullMslStore::getUserIdToken(const string& /*userId*/) {
    return shared_ptr<UserIdToken>();
}

set<shared_ptr<ServiceToken>> NullMslStore::getServiceTokens(shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken) {
	// Validate arguments.
	if (userIdToken) {
		if (!masterToken)
			throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_NULL);
		if (!userIdToken->isBoundTo(masterToken)) {
			stringstream ss;
			ss << "uit mtserialnumber " << userIdToken->getMasterTokenSerialNumber() << "; mt " << masterToken->getSerialNumber();
			throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str());
		}
	}

	return set<shared_ptr<ServiceToken> >();
}

void NullMslStore::removeServiceTokens(shared_ptr<string> /*name*/, shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken) {
	// Validate arguments.
	if (userIdToken && masterToken &&
		!userIdToken->isBoundTo(masterToken))
	{
		stringstream ss;
		ss << "uit mtserialnumber " << userIdToken->getMasterTokenSerialNumber() << "; mt " << masterToken->getSerialNumber();
		throw MslException(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, ss.str());
	}
}

}}} // namespace netflix::msl::util
