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

#ifndef SRC_USERAUTH_USERAUTHENTICATIONFACTORY_H_
#define SRC_USERAUTH_USERAUTHENTICATIONFACTORY_H_

#include <userauth/UserAuthenticationScheme.h>
#include <userauth/UserAuthenticationData.h>
#include <memory>

namespace netflix {
namespace msl {
namespace io { class MslObject; }
namespace tokens { class MasterToken; class UserIdToken; class MslUser;}
namespace util { class MslContext; }
namespace userauth {

/**
 * A user authentication factory creates authentication data instances and
 * performs authentication for a specific user authentication scheme.
 */
class UserAuthenticationFactory
{
public:
    virtual ~UserAuthenticationFactory() {}

    /**
     * @return the user authentication scheme this factory is for.
     */
    UserAuthenticationScheme getScheme() const { return scheme_; }

    /**
     * <p>Construct a new user authentication data instance from the provided
     * MSL object.</p>
     *
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the entity master token. May be {@code null}.
     * @param userAuthMo the MSL object.
     * @return the user authentication data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if there is an error creating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the user
     *         authentication data cryptography.
     */
    virtual std::shared_ptr<UserAuthenticationData> createData(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<io::MslObject> userAuthMo) = 0;

    /**
     * <p>Authenticate the user using the provided authentication data.</p>
     *
     * <p>If a user ID token is provided then also validate the authenticated
     * user against the provided user ID token. This is typically a check to
     * ensure the user identities are equal but not always. The returned user
     * must be the user identified by the user ID token.</p>
     *
     * @param ctx MSL context.
     * @param identity the entity identity.
     * @param data user authentication data.
     * @param userIdToken user ID token. May be {@code null}.
     * @return the MSL user.
     * @throws MslUserAuthException if there is an error authenticating the
     *         user or if the user authentication data and user ID token
     *         identities do not match.
     * @throws MslUserIdTokenException if there is a problem with the user ID
     *         token.
     */
    virtual std::shared_ptr<tokens::MslUser> authenticate(std::shared_ptr<util::MslContext> ctx,
            const std::string& identity, std::shared_ptr<UserAuthenticationData> data,
            std::shared_ptr<tokens::UserIdToken> userIdToken) = 0;

protected:
    /**
     * Create a new user authentication factory for the specified scheme.
     *
     * @param scheme the user authentication scheme.
     */
    UserAuthenticationFactory(const UserAuthenticationScheme& scheme) : scheme_(scheme) {}

private:
    /** The factory's user authentication scheme. */
    const UserAuthenticationScheme scheme_;

    UserAuthenticationFactory(); // not implemented
};

}}} // namespace netflix::msl::userauth

#endif /* SRC_USERAUTH_USERAUTHENTICATIONFACTORY_H_ */
