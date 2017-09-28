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

#include "MockTokenFactory.h"

#include <MslError.h>
#include <MslMasterTokenException.h>
#include <crypto/IRandom.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslEncoderUtils.h>
#include <MslEncodingException.h>
#include <MslUserIdTokenException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>

#include <gtest/gtest.h>
#include <tokens/MockMslUser.h>

using netflix::msl::tokens::UserIdToken;

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

namespace {
/** Renewal window start offset in milliseconds. */
const int RENEWAL_OFFSET = 60000;
/** Expiration offset in milliseconds. */
const int EXPIRATION_OFFSET = 120000;
/** Non-replayable ID acceptance window. */
const int64_t NON_REPLAYABLE_ID_WINDOW = 65536;
} // namespace anonymous

MockTokenFactory::MockTokenFactory() : sequenceNumber(-1), largestNonReplayableId(0)
{
}

MslError MockTokenFactory::isMasterTokenRevoked(shared_ptr<MslContext>,
        shared_ptr<MasterToken> masterToken)
{
    if (!masterToken->isDecrypted())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);

    if (revokedMasterToken && revokedMasterToken->getIdentity() == masterToken->getIdentity())
        return MslError::MASTERTOKEN_IDENTITY_REVOKED;
    return MslError::OK;
}

MslError MockTokenFactory::acceptNonReplayableId(shared_ptr<MslContext>,
        shared_ptr<MasterToken> masterToken, int64_t nonReplayableId)
{
    if (!masterToken->isDecrypted())
         throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);
     if (nonReplayableId < 0 || nonReplayableId > MslConstants::MAX_LONG_VALUE)
         throw MslException(MslError::NONREPLAYABLE_ID_OUT_OF_RANGE, "nonReplayableId " + to_string(nonReplayableId));

     // Reject if the non-replayable ID is equal or just a few messages
     // behind. The sender can recover by incrementing.
     const int64_t catchupWindow = MslConstants::MAX_MESSAGES / 2;
     if (nonReplayableId <= largestNonReplayableId &&
         nonReplayableId > largestNonReplayableId - catchupWindow)
     {
         return MslError::MESSAGE_REPLAYED;
     }

     // Reject if the non-replayable ID is larger by more than the
     // acceptance window. The sender cannot recover quickly.
     if (nonReplayableId - NON_REPLAYABLE_ID_WINDOW > largestNonReplayableId)
         return MslError::MESSAGE_REPLAYED_UNRECOVERABLE;

     // If the non-replayable ID is smaller reject it if it is outside the
     // wrap-around window. The sender cannot recover quickly.
     if (nonReplayableId < largestNonReplayableId) {
         const int64_t cutoff = largestNonReplayableId - MslConstants::MAX_LONG_VALUE + NON_REPLAYABLE_ID_WINDOW;
         if (nonReplayableId >= cutoff)
             return MslError::MESSAGE_REPLAYED_UNRECOVERABLE;
     }

     // Accept the non-replayable ID.
     largestNonReplayableId = nonReplayableId;
     return MslError::OK;
}


shared_ptr<MasterToken> MockTokenFactory::createMasterToken(
        shared_ptr<MslContext> ctx,
        shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
        const SecretKey& encryptionKey, const SecretKey& hmacKey,
        shared_ptr<MslObject> issuerData)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(ctx->getTime() + RENEWAL_OFFSET);
    shared_ptr<Date> expiration = make_shared<Date>(ctx->getTime() + EXPIRATION_OFFSET);
    const int64_t sequenceNumber = 0;
    const int64_t serialNumber = MslUtils::getRandomLong(ctx);
    const string identity = entityAuthData->getIdentity();
    return make_shared<MasterToken>(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, issuerData, identity, encryptionKey, hmacKey);
}


MslError MockTokenFactory::isMasterTokenRenewable(shared_ptr<MslContext>,
        shared_ptr<MasterToken> masterToken)
{
    if (!masterToken->isDecrypted())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);

    // Always succeed.
    return MslError::OK;
}


shared_ptr<MasterToken> MockTokenFactory::renewMasterToken(
        shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken,
        const SecretKey& encryptionKey,
        const SecretKey& hmacKey,
        shared_ptr<MslObject> issuerData)
{
    if (!masterToken->isDecrypted())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);

    shared_ptr<Date> renewalWindow = make_shared<Date>(ctx->getTime() + RENEWAL_OFFSET);
    shared_ptr<Date> expiration = make_shared<Date>(ctx->getTime() + EXPIRATION_OFFSET);
    const int64_t oldSequenceNumber = masterToken->getSequenceNumber();
    int64_t sequenceNumber;
    if (this->sequenceNumber == -1) {
        sequenceNumber = (oldSequenceNumber == MslConstants::MAX_LONG_VALUE) ? 0 : oldSequenceNumber + 1;
    } else {
        this->sequenceNumber = (this->sequenceNumber == MslConstants::MAX_LONG_VALUE) ? 0 : this->sequenceNumber + 1;
        sequenceNumber = this->sequenceNumber;
    }
    const int64_t serialNumber = masterToken->getSerialNumber();
    shared_ptr<MslObject> mtIssuerData = masterToken->getIssuerData();
    shared_ptr<MslObject> mergedIssuerData;
    try {
        mergedIssuerData = MslEncoderUtils::merge(mtIssuerData, issuerData);
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MASTERTOKEN_ISSUERDATA_ENCODE_ERROR, "mt issuerdata " + mtIssuerData->toString() + "; issuerdata " + issuerData->toString(), e);
    }
    const string identity = masterToken->getIdentity();
    return make_shared<MasterToken>(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, mergedIssuerData, identity, encryptionKey, hmacKey);
}


MslError MockTokenFactory::isUserIdTokenRevoked(shared_ptr<MslContext>,
        shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken)
{
    if (!masterToken->isDecrypted())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);
    if (!userIdToken->isDecrypted())
        throw MslUserIdTokenException(MslError::USERIDTOKEN_NOT_DECRYPTED, userIdToken);

    if (revokedUserIdToken && *userIdToken == *revokedUserIdToken)
        return MslError::USERIDTOKEN_REVOKED;
    return MslError::OK;
}

shared_ptr<UserIdToken> MockTokenFactory::createUserIdToken(shared_ptr<MslContext> ctx,
        shared_ptr<MslUser> user, shared_ptr<MasterToken> masterToken)
{
    shared_ptr<MslObject> issuerData;
    shared_ptr<Date> renewalWindow = make_shared<Date>(ctx->getTime() + RENEWAL_OFFSET);
    shared_ptr<Date> expiration = make_shared<Date>(ctx->getTime() + EXPIRATION_OFFSET);
    const int64_t serialNumber = MslUtils::getRandomLong(ctx);
    return make_shared<UserIdToken>(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user);
}

shared_ptr<UserIdToken> MockTokenFactory::renewUserIdToken(shared_ptr<MslContext> ctx,
        shared_ptr<UserIdToken> userIdToken, shared_ptr<MasterToken> masterToken)
{
    if (!userIdToken->isDecrypted())
        throw MslUserIdTokenException(MslError::USERIDTOKEN_NOT_DECRYPTED, userIdToken).setMasterToken(masterToken);

    shared_ptr<MslObject> issuerData ;
    shared_ptr<Date> renewalWindow = make_shared<Date>(ctx->getTime() + RENEWAL_OFFSET);
    shared_ptr<Date> expiration = make_shared<Date>(ctx->getTime() + EXPIRATION_OFFSET);
    const int64_t serialNumber = userIdToken->getSerialNumber();
    shared_ptr<MslUser> user = userIdToken->getUser();
    return make_shared<UserIdToken>(ctx, renewalWindow, expiration, masterToken, serialNumber, issuerData, user);
}


shared_ptr<MslUser> MockTokenFactory::createUser(shared_ptr<MslContext>,
        const string& userdata)
{
    try {
        return make_shared<MockMslUser>(userdata);
    } catch (const IllegalArgumentException& e) {
        throw MslException(MslError::USERIDTOKEN_IDENTITY_INVALID, userdata, e);
    }
}

}}} // namespace netflix::msl::tokens
