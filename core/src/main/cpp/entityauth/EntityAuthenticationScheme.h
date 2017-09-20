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

#ifndef SRC_ENTITYAUTH_ENTITYAUTHENTICATIONSCHEME_H_
#define SRC_ENTITYAUTH_ENTITYAUTHENTICATIONSCHEME_H_

#include <Macros.h>
#include <util/StaticMslMutex.h>
#include <map>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace entityauth {

/**
 * <p>Entity authentication schemes.</p>
 *
 * <p>The scheme name is used to uniquely identify entity authentication
 * schemes.</p>
 */
class EntityAuthenticationScheme
{
public:
    virtual ~EntityAuthenticationScheme() {}

    /** Pre-shared keys. */
    static EntityAuthenticationScheme PSK;
    /** Pre-shared keys with entity profiles. */
    static EntityAuthenticationScheme PSK_PROFILE;
    /** X.509 public/private key pair. */
    static EntityAuthenticationScheme X509;
    /** RSA public/private key pair. */
    static EntityAuthenticationScheme RSA;
    /** ECC public/private key pair. */
    static EntityAuthenticationScheme ECC;
    /** Unauthenticated. */
    static EntityAuthenticationScheme NONE;
    /** Unauthenticated suffixed. */
    static EntityAuthenticationScheme NONE_SUFFIXED;
    /** Master token protected. */
    static EntityAuthenticationScheme MT_PROTECTED;
    /** Provisioned. */
    static EntityAuthenticationScheme PROVISIONED;
    /** Invalid. */
    static EntityAuthenticationScheme INVALID;

    /**
     * @param name the entity authentication scheme name.
     * @return the scheme identified by the specified name or INVALID if
     *         there is none.
     */
    static EntityAuthenticationScheme getScheme(const std::string& name);

    /**
     * @return all known entity authentication schemes.
     */
    static std::vector<EntityAuthenticationScheme> values();

    /**
     * @return the scheme identifier.
     */
    std::string name() const { return name_; }

    /**
     * @return true if the scheme encrypts message data.
     */
    bool encrypts() const { return encrypts_; }

    /**
     * @return true if the scheme protects message integrity.
     */
    bool protectsIntegrity() const { return protects_; }

    std::string toString() const { return name(); }

    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     *
     * @param name the entity authentication scheme name.
     * @param encrypts true if the scheme encrypts message data.
     * @param protects true if the scheme protects message integrity.
     */
    EntityAuthenticationScheme(const std::string& name, bool encrypts, bool protects);

private:
    static util::StaticMslMutex& mutex();
    typedef std::map<std::string, EntityAuthenticationScheme> MapType;
    static MapType& schemes();

    /** Scheme name. */
    std::string name_;
    /** Encrypts message data. */
    bool encrypts_;
    /** Protects message integrity. */
    bool protects_;
};

bool operator==(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b);
bool operator!=(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b);
bool operator<(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b);

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ENTITYAUTHENTICATIONSCHEME_H_ */
