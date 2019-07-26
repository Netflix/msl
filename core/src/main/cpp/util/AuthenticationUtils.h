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

#ifndef SRC_UTIL_AUTHENTICATIONUTILS_H_
#define SRC_UTIL_AUTHENTICATIONUTILS_H_

#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace entityauth { class EntityAuthenticationScheme; }
namespace tokens { class MslUser; }
namespace userauth { class UserAuthenticationScheme; }
namespace keyx { class KeyExchangeScheme; }
namespace util {

class AuthenticationUtils
{
public:
    virtual ~AuthenticationUtils() {}

    /**
     * Returns true if the entity identity has been revoked.
     *
     * @param identity the entity identity.
     * @return true if the entity identity has been revoked.
     */
    virtual bool isEntityRevoked(const std::string& identity) = 0;

    /**
     * Returns true if the identified entity is permitted to use the specified
     * entity authentication scheme.
     *
     * @param identity the entity identity.
     * @param scheme the entity authentication scheme.
     * @return true if the entity is permitted to use the scheme.
     */
    virtual bool isSchemePermitted(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme) = 0;

    /**
     * Returns true if the identified entity is permitted to use the specified
     * user authentication scheme.
     *
     * @param identity the entity identity.
     * @param scheme the user authentication scheme.
     * @return true if the entity is permitted to use the scheme.
     */
    virtual bool isSchemePermitted(const std::string& identity, const userauth::UserAuthenticationScheme& scheme) = 0;

    /**
     * Returns true if the identified entity and user combination is permitted
     * to use the specified user authentication scheme.
     *
     * @param identity the entity identity.
     * @param user the user.
     * @param scheme the user authentication scheme.
     * @return true if the entity and user are permitted to use the scheme.
     */
    virtual bool isSchemePermitted(const std::string& identity, std::shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme) = 0;

    /**
     * Returns true if the identified entity is permitted to use the specified
     * key exchange scheme.
     *
     * @param identity the entity identity.
     * @param scheme the key exchange scheme.
     * @return true if the entity is permitted to use the scheme.
     */
    virtual bool isSchemePermitted(const std::string& identity, const keyx::KeyExchangeScheme& scheme) = 0;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_AUTHENTICATIONUTILS_H_ */
