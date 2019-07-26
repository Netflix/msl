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

#ifndef SRC_ENTITYAUTH_RSAAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_RSAAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationData.h>
#include <string>

namespace netflix {
namespace msl {
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace entityauth {

/**
 * <p>RSA asymmetric keys entity authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity", "pubkeyid" ],
 *   "identity" : "string",
 *   "pubkeyid" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * <li>{@code pubkeyid} is the identity of the RSA public key associated with this identity</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class RsaAuthenticationData: public EntityAuthenticationData
{
public:
    virtual ~RsaAuthenticationData() {}

    /**
     * Construct a new public key authentication data instance from the
     * specified entity identity and public key ID.
     *
     * @param identity the entity identity.
     * @param pubkeyid the public key ID.
     */
    RsaAuthenticationData(const std::string identity, const std::string pubkeyid);

    /**
     * Construct a new RSA asymmetric keys authentication data instance from
     * the provided MSL object.
     *
     * @param rsaAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL data.
     */
    RsaAuthenticationData(std::shared_ptr<io::MslObject> rsaAuthMo);

    /**
     * @return the entity identity.
     */
    virtual std::string getIdentity() const { return identity_; }

    /**
     * @return the public key ID.
     */
    virtual std::string getPublicKeyId() const { return pubkeyid_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> obj) const;

private:
    /** Entity identity. */
    const std::string identity_;
    /** Public key ID. */
    const std::string pubkeyid_;
};

bool operator==(const RsaAuthenticationData& a, const RsaAuthenticationData& b);
inline bool operator!=(const RsaAuthenticationData& a, const RsaAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_RSAAUTHENTICATIONDATA_H_ */
