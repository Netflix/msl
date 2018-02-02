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

#ifndef TEST_TOKENS_MOCKTOKENFACTORY_H_
#define TEST_TOKENS_MOCKTOKENFACTORY_H_

#include <tokens/TokenFactory.h>
#include <memory>

namespace netflix {
namespace msl {
namespace tokens {

/**
 * Token factory for unit tests.
 */
class MockTokenFactory : public TokenFactory
{
public:
	virtual ~MockTokenFactory() {};

	MockTokenFactory();

	/**
	 * @param sequenceNumber the newest master token sequence number, or -1 to
	 *        accept all master tokens as the newest.
	 */
	void setNewestMasterToken(int64_t sequenceNumber) {
	    this->sequenceNumber = sequenceNumber;
	}

	/**
	 * @param masterToken the master token to consider revoked or {@code null}
	 *        to unset.
	 */
	void setRevokedMasterToken(std::shared_ptr<MasterToken> masterToken) {
	    revokedMasterToken = masterToken;
	}

	/** @inheritDoc */
	virtual MslError isMasterTokenRevoked(std::shared_ptr<util::MslContext> ctx,
	        std::shared_ptr<MasterToken> masterToken);

	/**
	 * @param nonReplayableId the largest non-replayable ID, or -1 to accept
	 *        all non-replayable IDs.
	 */
	void setLargestNonReplayableId(int64_t nonReplayableId) {
	    largestNonReplayableId = nonReplayableId;
	}

	/** @inheritDoc */
	virtual MslError acceptNonReplayableId(std::shared_ptr<util::MslContext> ctx,
	        std::shared_ptr<MasterToken> masterToken, int64_t nonReplayableId);

	/** @inheritDoc */
	virtual std::shared_ptr<MasterToken> createMasterToken(
	        std::shared_ptr<util::MslContext> ctx,
	        std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
	        const crypto::SecretKey& encryptionKey, const crypto::SecretKey& hmacKey,
	        std::shared_ptr<io::MslObject> issuerData);

    /** @inheritDoc */
    virtual MslError isMasterTokenRenewable(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<MasterToken> renewMasterToken(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            const crypto::SecretKey& encryptionKey,
            const crypto::SecretKey& hmacKey,
            std::shared_ptr<io::MslObject> issuerData);

    /**
     * @param userIdToken the user ID token to consider revoked or {@code null}
     *        to unset.
     */
    void setRevokedUserIdToken(std::shared_ptr<UserIdToken> userIdToken) {
        revokedUserIdToken = userIdToken;
    }

    /** @inheritDoc */
    virtual MslError isUserIdTokenRevoked(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            std::shared_ptr<UserIdToken> userIdToken);

    /** @inheritDoc */
    virtual std::shared_ptr<UserIdToken> createUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MslUser> user, std::shared_ptr<MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<UserIdToken> renewUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<UserIdToken> userIdToken, std::shared_ptr<MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<MslUser> createUser(std::shared_ptr<util::MslContext> ctx,
            const std::string& userdata);

    /**
     * Reset the token factory state.
     */
    void reset() {
        sequenceNumber = -1;
        revokedMasterToken.reset();
        largestNonReplayableId = 0;
        revokedUserIdToken.reset();
    }

protected:
    /** Newest master token sequence number. (-1 accepts all master tokens.) */
    int64_t sequenceNumber = -1;
    /** Revoked master token. (null accepts all master tokens.) */
    std::shared_ptr<MasterToken> revokedMasterToken;
    /** Current largest non-replayable ID. */
    int64_t largestNonReplayableId = 0;
    /** Revoked user ID token. (null accepts all user ID tokens.) */
    std::shared_ptr<UserIdToken> revokedUserIdToken;
};

}}} // namespace netflix::msl::tokens

#endif /* TEST_TOKENS_MOCKTOKENFACTORY_H_ */
