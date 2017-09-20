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

#ifndef SRC_ENTITYAUTH_PRESHAREDPROFILEAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_PRESHAREDPROFILEAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationData.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace io { class MslObject; }
namespace entityauth {

/**
 * <p>Preshared keys profile entity authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "pskid", "profile" ],
 *   "pskid" : "string",
 *   "profile" : "string",
 * }} where:
 * <ul>
 * <li>{@code pskid} is the entity preshared keys identity</li>
 * <li>{@code profile} is the entity profile</li>
 * </ul></p>
 */
class PresharedProfileAuthenticationData: public entityauth::EntityAuthenticationData
{
public:
    virtual ~PresharedProfileAuthenticationData() {}

    /**
     * Construct a new preshared keys authentication data instance from the
     * specified entity preshared keys identity and profile.
     *
     * @param pskid the entity preshared keys identity.
     * @param profile the entity profile.
     */
    PresharedProfileAuthenticationData(const std::string& pskid, const std::string& profile);

    /**
     * Construct a new preshared keys profile authentication data instance from
     * the provided MSL object.
     *
     * @param authMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    PresharedProfileAuthenticationData(std::shared_ptr<io::MslObject> authMo);

    /**
     * <p>Returns the entity identity. This is equal to the preshared keys
     * identity and profile strings joined with a hyphen, e.g.
     * {@code pskid-profile}.</p>
     *
     * @return the entity identity.
     */
    virtual std::string getIdentity() const;

    /**
     * @return the entity preshared keys identity.
     */
    std::string getPresharedKeysId() const { return pskid; }

    /**
     * @return the entity profile.
     */
    std::string getProfile() const { return profile; }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> obj) const;

private:
    PresharedProfileAuthenticationData(); // not implemented
    /** Entity preshared keys identity. */
    std::string pskid;
    /** Entity profile. */
    std::string profile;
};

bool operator==(const PresharedProfileAuthenticationData& a, const PresharedProfileAuthenticationData& b);
inline bool operator!=(const PresharedProfileAuthenticationData& a, const PresharedProfileAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl:entityauth

#endif /* SRC_ENTITYAUTH_PRESHAREDPROFILEAUTHENTICATIONDATA_H_ */
