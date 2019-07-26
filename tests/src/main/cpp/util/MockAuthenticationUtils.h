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

#ifndef TEST_UTIL_MOCKAUTHENTICATIONUTILS_H_
#define TEST_UTIL_MOCKAUTHENTICATIONUTILS_H_

#include <util/AuthenticationUtils.h>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace entityauth { class EntityAuthenticationScheme; }
namespace userauth { class UserAuthenticationScheme; }
namespace keyx { class KeyExchangeScheme; }
namespace tokens { class MslUser; }
namespace util {

/**
 * Test authentication utilities.
 */
class MockAuthenticationUtils : public AuthenticationUtils
{
public:
    virtual ~MockAuthenticationUtils() {}

    /**
     * Reset the entity revocation state.
     */
    void reset();

    /**
     * @param identity the entity identity to revoke.
     */
    void revokeEntity(const std::string& identity);

    /**
     * @param identity the entity to accept.
     */
    void accept(std::string identity);

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthUtils#isRevoked(java.lang.std::string)
     */
    virtual bool isEntityRevoked(const std::string& identity);

    /**
      * @param identity the entity identity.
      * @param scheme the scheme to permit.
      */
     void permitScheme(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme);

     /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    void disallowScheme(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme);

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.std::string, com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, const entityauth::EntityAuthenticationScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to permit.
     */
    void permitScheme(const std::string& identity, const userauth::UserAuthenticationScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    void disallowScheme(const std::string& identity, const userauth::UserAuthenticationScheme& scheme);

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.std::string, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, const userauth::UserAuthenticationScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param user the MSL user.
     * @param scheme the scheme to permit.
     */
    void permitScheme(const std::string& identity, std::shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param user the MSL user.
     * @param scheme the scheme to disallow.
     */
    void disallowScheme(const std::string& identity, std::shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme);

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.std::string, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    virtual bool isSchemePermitted(const std::string& identity, std::shared_ptr<tokens::MslUser> user, const userauth::UserAuthenticationScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to permit.
     */
    void permitScheme(const std::string& identity, const keyx::KeyExchangeScheme& scheme);

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    void disallowScheme(const std::string& identity, const keyx::KeyExchangeScheme& scheme);

    /* (non-Javadoc)
      * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.std::string, com.netflix.msl.keyx.KeyExchangeScheme)
      */
     virtual bool isSchemePermitted(const std::string& identity, const keyx::KeyExchangeScheme& scheme);

private:
    /** Revoked entity identities. */
    std::set<std::string> revokedEntityIdentities;
    /** Revoked entity authentication schemes. */
    std::map<std::string, std::set<entityauth::EntityAuthenticationScheme>> revokedEntityAuthSchemes;
    /** Revoked user authentication schemes. */
    std::map<std::string, std::set<userauth::UserAuthenticationScheme>> revokedUserAuthSchemes;
    /** Revoked entity-user authentication schemes. */
    std::map<std::string, std::map<std::shared_ptr<tokens::MslUser>, std::set<userauth::UserAuthenticationScheme>>> revokedEntityUserAuthSchemes;
    /** Revoked key exchange schemes. */
    std::map<std::string, std::set<keyx::KeyExchangeScheme>> revokedKeyxSchemes;

};

}}} // namespace neetflix::msl::util

#endif /* TEST_UTIL_MOCKAUTHENTICATIONUTILS_H_ */
