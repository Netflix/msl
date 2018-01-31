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

#include <tokens/ClientTokenFactory.h>
#include <crypto/Key.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslObject.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/UserIdToken.h>
#include <util/MslContext.h>
#include <memory>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

MslError ClientTokenFactory::isMasterTokenRevoked(shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MasterToken> /*masterToken*/)
{
    return MslError::NONE; // Note: java code returns java null here;
}

MslError ClientTokenFactory::acceptNonReplayableId(shared_ptr<MslContext> /*ctx*/,
         shared_ptr<MasterToken> /*masterToken*/, int64_t /*nonReplayableId*/)
{
    return MslError::NONE; // Note: java code returns java null here;
}

shared_ptr<MasterToken> ClientTokenFactory::createMasterToken(
        shared_ptr<MslContext> /*ctx*/,
        shared_ptr<EntityAuthenticationData> /*entityAuthData*/,
        const SecretKey& /*encryptionKey*/, const SecretKey& /*hmacKey*/,
        shared_ptr<MslObject> /*issuerData*/)
{
    throw MslInternalException("Creating master tokens is unsupported by the token factory.");
}

MslError ClientTokenFactory::isMasterTokenRenewable(shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MasterToken> /*masterToken*/)
{
    return MslError::NONE; // Note: java code returns java null here;
}

shared_ptr<MasterToken> ClientTokenFactory::renewMasterToken(
        shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MasterToken> /*masterToken*/,
        const SecretKey& /*encryptionKey*/,
        const SecretKey& /*hmacKey*/,
        shared_ptr<MslObject> /*issuerData*/)
{
    throw MslInternalException("Renewing master tokens is unsupported by the token factory.");
}

MslError ClientTokenFactory::isUserIdTokenRevoked(
        shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MasterToken> /*masterToken*/,
        shared_ptr<UserIdToken> /*userIdToken*/)
{
    return MslError::NONE; // Note: java code returns java null here;
}

shared_ptr<UserIdToken> ClientTokenFactory::createUserIdToken(shared_ptr<MslContext> /*ctx*/,
        shared_ptr<MslUser> /*user*/, shared_ptr<MasterToken> /*masterToken*/)
{
    throw MslInternalException("Creating user ID tokens is unsupported by the token factory.");
}

shared_ptr<UserIdToken> ClientTokenFactory::renewUserIdToken(shared_ptr<MslContext> /*ctx*/,
        shared_ptr<UserIdToken> /*userIdToken*/, shared_ptr<MasterToken> /*masterToken*/)
{
    throw MslInternalException("Renewing master tokens is unsupported by the token factory.");
}

shared_ptr<MslUser> ClientTokenFactory::createUser(shared_ptr<MslContext> /*ctx*/,
        const string& /*userdata*/)
{
    throw MslInternalException("Creating users is unsupported by the token factory.");
}

}}} // namespace netflix::msl::tokens
