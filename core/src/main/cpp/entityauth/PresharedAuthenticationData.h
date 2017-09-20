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

#ifndef SRC_ENTITYAUTH_PRESHAREDAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_PRESHAREDAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationData.h>
#include <string>

namespace netflix {
namespace msl {
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace entityauth {

class PresharedAuthenticationData: public EntityAuthenticationData
{
public:
    virtual ~PresharedAuthenticationData() {}

    /**
     * Construct a new preshared keys authentication data instance from the
     * specified entity identity.
     *
     * @param identity the entity identity.
     */
    PresharedAuthenticationData(const std::string identity);

    /**
     * Construct a new preshared keys authentication data instance from the
     * provided MSL object.
     *
     * @param presharedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    PresharedAuthenticationData(std::shared_ptr<io::MslObject> presharedAuthMo);

    /**
     * @return the entity identity.
     */
    virtual std::string getIdentity() const { return identity_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> obj) const;

private:
    /** Entity identity. */
    const std::string identity_;
};

bool operator==(const PresharedAuthenticationData& a, const PresharedAuthenticationData& b);
inline bool operator!=(const PresharedAuthenticationData& a, const PresharedAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_PRESHAREDAUTHENTICATIONDATA_H_ */
