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
#ifndef SRC_ENTITYAUTH_ECCAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_ECCAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <string>
#include <memory>

namespace netflix {
namespace msl {
namespace io { class MslEncoderFactory; class MslEncoderFormat; class MslObject; }
namespace entityauth {

class EccAuthenticationData : public EntityAuthenticationData
{
public:
	virtual ~EccAuthenticationData() {}

    /**
     * Construct a new public key authentication data instance from the
     * specified entity identity and public key ID.
     *
     * @param identity the entity identity.
     * @param pubkeyid the public key ID.
     */
	EccAuthenticationData(const std::string identity, const std::string pubkeyid)
		: EntityAuthenticationData(EntityAuthenticationScheme::ECC)
		, identity_(identity)
		, pubkeyid_(pubkeyid)
	{}

    /**
     * Construct a new public key authentication data instance from the
     * specified entity identity and public key ID.
     *
     * @param identity the entity identity.
     * @param pubkeyid the public key ID.
     */
	EccAuthenticationData(std::shared_ptr<io::MslObject> eccAuthMo);

	/** @inheritDoc */
	virtual std::string getIdentity() const {
		return identity_;
	}

	/**
	 * @return the public key ID.
	 */
	const std::string getPublicKeyId() const {
		return pubkeyid_;
	}

	/** @inheritDoc */
	virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

	/** @inheritDoc */
    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> other) const;

private:
    /** Entity identity. */
    std::string identity_;
    /** Public key ID. */
    std::string pubkeyid_;
};

bool operator==(const EccAuthenticationData& a, const EccAuthenticationData& b);
inline bool operator!=(const EccAuthenticationData& a, const EccAuthenticationData& b) { return !(a == b); }


}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ECCAUTHENTICATIONDATA_H_ */
