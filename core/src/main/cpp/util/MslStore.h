/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_UTIL_MSLSTORE_H_
#define SRC_UTIL_MSLSTORE_H_

#include <map>
#include <memory>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace tokens { class MasterToken; class ServiceToken; class UserIdToken; }
namespace util {

/**
 * <p>The Message Security Layer store manages the local store of master tokens
 * identifying the local entity, user ID tokens identifying local users, and
 * all service tokens issued by the local entity or remote entities. It also
 * provides methods for identifying the tokens that should be included in a
 * message and accessing crypto contexts associated with master tokens.<p>
 *
 * <p>Applications may wish to ensure the store contains only the newest master
 * token and user ID tokens for the known users at application startup and
 * shutdown.</p>
 *
 * <p>Implementations must be thread-safe.</p>
 *
 * @see MslContext
 * @author Wesley Miaw <wmiaw@netflix.com>
*/
class MslStore
{
public:
	virtual ~MslStore() {}

    /**
     * Save a master token and its associated crypto context. This replaces any
     * existing association. Passing in a null crypto context is the same as
     * calling {@link #removeCryptoContext(MasterToken)}.
     *
     * @param masterToken the master token.
     * @param cryptoContext the crypto context. May be null.
     */
    virtual void setCryptoContext(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<crypto::ICryptoContext> cryptoContext) = 0;

    /**
     * Return the newest saved master token in this store.
     *
     * @return the newest saved master token or null.
     */
    virtual std::shared_ptr<tokens::MasterToken> getMasterToken() = 0;

    /**
     * Return the next non-replayable ID of the provided master token.
     *
     * The initial number is one (1). Each call to this function should return
     * the next largest number. The next largest number after
     * {@link com.netflix.msl.MslConstants#MAX_LONG_VALUE} is zero (0).
     *
     * @return the next non-replayable ID.
     */
    virtual int64_t getNonReplayableId(std::shared_ptr<tokens::MasterToken> masterToken) = 0;

    /**
     * Return the crypto context associated with the provided master token.
     *
     * @param masterToken the master token.
     * @return the crypto context for the master token or null if not found.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(std::shared_ptr<tokens::MasterToken> masterToken) = 0;

    /**
     * Remove a master token and its associated crypto context. This also
     * removes any stored user ID tokens and service tokens that are no longer
     * bound to a known master token.
     *
     * @param masterToken the master token.
     */
    virtual void removeCryptoContext(std::shared_ptr<tokens::MasterToken> masterToken) = 0;

    /**
     * Removes all master tokens and crypto contexts and bound user ID tokens
     * and their bound service tokens.
     */
    virtual void clearCryptoContexts() = 0;

    /**
     * Add a user ID token to the store, replacing any existing user ID token
     * of the same user. The local user ID has no meeting external to the
     * store.
     *
     * @param userId local user ID.
     * @param userIdToken the user ID token.
     * @throws MslException if the user ID token is not bound to any stored
     *         master token.
     */
    virtual void addUserIdToken(const std::string& userId, std::shared_ptr<tokens::UserIdToken> userIdToken) = 0;

    /**
     * Returns the user ID token, if any, for the specified local user ID.
     *
     * @param userId local user ID.
     * @return the user ID token for the local user ID or null.
     */
    virtual std::shared_ptr<tokens::UserIdToken> getUserIdToken(const std::string& userId) = 0;

    /**
     * Remove a user ID token. This also removes any service tokens no longer
     * bound to a known user ID token.
     *
     * @param userIdToken the user ID token.
     */
    virtual void removeUserIdToken(std::shared_ptr<tokens::UserIdToken> userIdToken) = 0;

    /**
     * Removes all user ID tokens and user ID token bound service tokens.
     */
    virtual void clearUserIdTokens() = 0;

    /**
     * <p>Add a set of service tokens to the store.</p>
     *
     * <p>Either all or none of the provided service tokens will be added.</p>
     *
     * @param tokens the service tokens.
     * @throws MslException if a service token is master token bound to a
     *         master token not found in the store or if a service token is
     *         user ID token bound to a user ID token not found in the store.
     */
    virtual void addServiceTokens(const std::set<std::shared_ptr<tokens::ServiceToken>> tokens) = 0;

    /**
     * <p>Return the set of service tokens that are applicable to the provided
     * pair of master token and user ID token. The base set consists of the
     * service tokens that are not bound to any master token or user ID
     * token.</p>
     *
     * <p>If a master token is provided, the service tokens that are bound to
     * the master token and not bound to any user ID token are also
     * provided.</p>
     *
     * <p>If a master token and user ID token is provided, the service tokens
     * that are bound to both the master token and user ID token are also
     * provided.</p>
     *
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @return the set of service tokens applicable to the message.
     * @throws MslException if the user ID token is not bound to the master
     *         token or a user ID token is provided without also providing a
     *         master token.
     */
    virtual std::set<std::shared_ptr<tokens::ServiceToken>> getServiceTokens(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken) = 0;

    /**
     * <p>Remove all service tokens matching all the specified parameters. A
     * null value for the master token or user ID token restricts removal to
     * tokens that are not bound to a master token or not bound to a user ID
     * token respectively.</p>
     *
     * <p>For example, if a name and master token is provided, only tokens with
     * that name, bound to that master token, and not bound to a user ID token
     * are removed. If only a user ID token is provided, all tokens bound to
     * that user ID token are removed.</p>
     *
     * <p>If no parameters are provided, no tokens are removed.</p>
     *
     * @param name service token name. May be null.
     * @param masterToken master token. May be null.
     * @param userIdToken user ID token. May be null.
     * @throws MslException if the user ID token is not bound to the master
     *         token.
     */
    virtual void removeServiceTokens(std::shared_ptr<std::string> name, std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken) = 0;

    /**
     * Removes all service tokens.
     */
    virtual void clearServiceTokens() = 0;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_MSLSTORE_H_ */
