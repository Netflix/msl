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

#ifndef SRC_TOKENS_TOKENFACTORY_H_
#define SRC_TOKENS_TOKENFACTORY_H_

#include <MslError.h>
#include <memory>

namespace netflix {
namespace msl {
namespace crypto { class SecretKey; }
namespace entityauth { class EntityAuthenticationData; }
namespace io { class MslObject; }
namespace util { class MslContext; }
namespace tokens {

class MasterToken;
class UserIdToken;
class MslUser;

/**
 * The token factory creates and renews master tokens and user ID tokens.
 */
class TokenFactory
{
public:
    virtual ~TokenFactory() {}

    /**
     * <p>Return false if the master token has been revoked.</p>
     *
     * <p>A master token may be revoked at any time after creation and before
     * renewal for various reasons, including but not limited to entity
     * revocation or knowledge that a master token or its session keys has been
     * compromised. The entity will be forced to re-authenticate if its master
     * token is rejected.</p>
     *
     * <p>This method is slightly different than
     * {@link #isMasterTokenRenewable(MslContext, MasterToken)} because it
     * will be called for every received message and should not check the
     * renewability of the master token.</p>
     *
     * <p>This method should return the exact {@link MslError} identifying the
     * reason the master token has been revoked. The response code associated
     * with the error will be honored.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token to check.
     * @return {@code null} if the master token has not been revoked. Otherwise
     *         return a MSL error.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslException if there is an error performing the revocation
     *         check.
     */
    virtual MslError isMasterTokenRevoked(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken)  = 0;

    /**
     * <p>Return true if the non-replayable ID is larger by no more than 65536
     * than the largest non-replayable ID accepted so far for the provided
     * master token.</p>
     *
     * <p>Non-replayable IDs should be tracked by the master token entity
     * identity and serial number. Before accepting any non-replayable IDs the
     * largest value accepted so far shall be considered zero. The maximum non-
     * replayable ID is equal to
     * {@link com.netflix.msl.MslConstants#MAX_LONG_VALUE} which the IDs wrap
     * around to zero. The wrap around must be considered when comparing the
     * non-replayable ID to the largest non-replayable ID accepted so far.</p>
     *
     * <p>It is also permitted to accept non-replayable IDs less than the
     * largest non-replayable ID accepted so far if those non-replayable IDs
     * have not been seen. The set of smaller non-replayable IDs accepted
     * should be limited in size based on a reasonable expectation for the the
     * number of concurrent non-replayable messages the entity may create.</p>
     *
     * <p>This method should return the exact {@link MslError} identifying the
     * reason the non-replayable ID was rejected. The response code associated
     * with the error will be honored. If the master token entity cannot be
     * expected to recover if the message is sent with a new non-replayable ID
     * then the response code {@link ResponseCode#ENTITYDATA_REAUTH} should be
     * used.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token.
     * @param nonReplayableId non-replayable ID.
     * @return {@code null} if the non-replayable ID has been accepted.
     *         Otherwise return a MSL error.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslException if there is an error comparing or updating the non-
     *         replayable ID associated with this master token.
     * @see #createMasterToken(MslContext, EntityAuthenticationData, SecretKey, SecretKey, MslObject)
     * @see MslError#MESSAGE_REPLAYED
     * @see MslError#MESSAGE_REPLAYED_UNRECOVERABLE
     */
    virtual MslError acceptNonReplayableId(std::shared_ptr<util::MslContext> ctx,
             std::shared_ptr<MasterToken> masterToken, int64_t nonReplayableId) = 0;

    /**
     * <p>Create a new master token with the specified identity and session
     * keys.</p>
     *
     * <p>Creating a new master token implies all previous master tokens issued
     * to the specified entity are no longer valid and therefore all state data
     * for the non-replayable IDs associated with the entity identity may be
     * discarded.</p>
     *
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data.
     * @param encryptionKey the session encryption key.
     * @param hmacKey the session HMAC key.
     * @param issuerData optional master token issuer data that should be
     *        included in the master token. May be {@code null}.
     * @return the new master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if there is an error creating the master token.
     * @see #acceptNonReplayableId(MslContext, MasterToken, long)
     */
    virtual std::shared_ptr<MasterToken> createMasterToken(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
            const crypto::SecretKey& encryptionKey, const crypto::SecretKey& hmacKey,
            std::shared_ptr<io::MslObject> issuerData) = 0;

    /**
     * <p>Check if the master token would be renewed by a call to
     * {@link #renewMasterToken(MslContext, MasterToken, SecretKey, SecretKey, MslObject)}.</p>
     *
     * <p>This method should return the exact {@link MslError} identifying the
     * reason the master token will not be renewed.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token to check.
     * @return {@code null} if the master token would be renewed. Otherwise
     *         return a MSL error.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslException if there is an error checking the master token
     *         renewability.
     * @see #renewMasterToken(MslContext, MasterToken, SecretKey, SecretKey, MslObject)
     */
    virtual MslError isMasterTokenRenewable(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken) = 0;

    /**
     * <p>Renew a master token assigning it the new session keys.</p>
     *
     * <p>This method should also perform any additional entity checks such as
     * if the entity has been revoked.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token to renew.
     * @param encryptionKey the session encryption key.
     * @param hmacKey the session HMAC key.
     * @param issuerData optional master token issuer data that should be
     *        merged into or overwrite any existing issuer data. May be
     *        {@code null}.
     * @return the new master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslMasterTokenException if the master token is not trusted or
     *         the factory does not wish to renew it.
     * @throws MslException if there is an error renewing the master token.
     * @see #isMasterTokenRenewable(MslContext, MasterToken)
     */
    virtual std::shared_ptr<MasterToken> renewMasterToken(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            const crypto::SecretKey& encryptionKey,
            const crypto::SecretKey& hmacKey,
            std::shared_ptr<io::MslObject> issuerData) = 0;

    /**
     * <p>Return false if the user ID token has been revoked.</p>
     *
     * <p>A user ID token may be revoked at any time after creation and before
     * renewal for various reasons, including but not limited to user deletion.
     * The user will be forced to re-authenticate if its user ID token is
     * rejected.</p>
     *
     * <p>This method should return the exact {@link MslError} identifying the
     * reason the user ID token has been revoked.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the associated master token.
     * @param userIdToken the user ID token to check.
     * @return MslError::OK if the user ID token has not been revoked.
     *         Otherwise return a MSL error.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslUserIdTokenException if the user ID token is not trusted.
     * @throws MslException if there is an error performing the revocation
     *         check.
     */
    virtual MslError isUserIdTokenRevoked(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            std::shared_ptr<UserIdToken> userIdToken) = 0;

    /**
     * Create a new user ID token bound to the provided master token.
     *
     * @param ctx MSL context.
     * @param user MSL user.
     * @param masterToken the master token to bind the user token against.
     * @return the new user ID token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslException if there is an error creating the user ID token.
     */
    virtual std::shared_ptr<UserIdToken> createUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MslUser> user, std::shared_ptr<MasterToken> masterToken) = 0;

    /**
     * <p>Renew a user ID token and bind it to the provided master token.</p>
     *
     * <p>This method should also perform any additional user checks such as if
     * the user no longer exists or must re-login.</p>
     *
     * @param ctx MSL context.
     * @param userIdToken the user ID token to renew.
     * @param masterToken the master token to bind the user token against.
     * @return the new user ID token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslUserIdTokenException if the user ID token is not decrypted or
     *         the factory does not wish to renew it.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslException if there is an error renewing the user ID token.
     */
    virtual std::shared_ptr<UserIdToken> renewUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<UserIdToken> userIdToken, std::shared_ptr<MasterToken> masterToken) = 0;

    /**
     * <p>Create a new MSL user instance from the serialized user data.</p>
     *
     * <p>This method is called when reconstructing a user ID token. Thrown
     * {@link MslException}s should keep that in mind when deciding upon the
     * {@link MslError} to reference.</p>
     *
     * @param ctx MSL context.
     * @param userdata serialized user data.
     * @return the MSL user.
     * @throws MslEncodingException if there is an error parsing the user data.
     * @throws MslException if there is an error creating the MSL user.
     */
    virtual std::shared_ptr<MslUser> createUser(std::shared_ptr<util::MslContext> ctx,
            const std::string& userdata) = 0;
};

}}} // namespace netflix::msl::tokens

#endif /* SRC_TOKENS_TOKENFACTORY_H_ */
