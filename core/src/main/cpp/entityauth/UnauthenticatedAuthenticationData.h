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

#ifndef SRC_ENTITYAUTH_UNAUTHENTICATEDAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_UNAUTHENTICATEDAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationData.h>
#include <string>

namespace netflix {
namespace msl {
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace entityauth {

/**
 * <p>Unauthenticated entity authentication data. This form of authentication
 * is used by entities that cannot provide any form of entity
 * authentication.</p>
 *
 * <p>Unauthenticated entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "identity" ],
 *   "identity" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class UnauthenticatedAuthenticationData: public EntityAuthenticationData
{
public:
    virtual ~UnauthenticatedAuthenticationData() {}

    /**
     * Construct a new unauthenticated entity authentication data instance from
     * the specified entity identity.
     *
     * @param identity the entity identity.
     */
    UnauthenticatedAuthenticationData(const std::string identity);

    /**
     * Construct a new unauthenticated entity authentication data instance from
     * the provided MSL object.
     *
     * @param unauthenticatedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL data.
     */
    UnauthenticatedAuthenticationData(std::shared_ptr<io::MslObject> unauthenticatedAuthMo);

    /**
     * @return the entity identity.
     */
    virtual std::string getIdentity() const { return identity_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> obj) const;

private:
    /** Entity identity. */
    const std::string identity_;
};

bool operator==(const UnauthenticatedAuthenticationData& a, const UnauthenticatedAuthenticationData& b);
inline bool operator!=(const UnauthenticatedAuthenticationData& a, const UnauthenticatedAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_UNAUTHENTICATEDAUTHENTICATIONDATA_H_ */
