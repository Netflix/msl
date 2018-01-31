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

#ifndef SRC_ENTITYAUTH_ENTITYAUTHENTICATIONDATA_H_
#define SRC_ENTITYAUTH_ENTITYAUTHENTICATIONDATA_H_

#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncodable.h>
#include <stdint.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; class MslEncoderFormat; }
namespace util { class MslContext; }
namespace entityauth {

/**
 * <p>The entity authentication data provides proof of entity identity.</p>
 *
 * <p>Specific entity authentication mechanisms should define their own entity
 * authentication data types.</p>
 *
 * <p>Entity authentication data is represented as
 * {@code
 * entityauthdata = {
 *   "#mandatory" : [ "scheme", "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the entity authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific entity authentication data</li>
 * </ul></p>
 */
class EntityAuthenticationData: public io::MslEncodable
{
public:
    virtual ~EntityAuthenticationData() {}

    /**
     * Construct a new entity authentication data instance of the correct type
     * from the provided MSL object.
     *
     * @param ctx MSL context.
     * @param entityAuthMo the MSL object.
     * @return the entity authentication data concrete instance.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslCryptoException if there is an error creating the entity
     *         authentication data crypto.
     */
    static std::shared_ptr<EntityAuthenticationData> create(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> entityAuthMo);

    /**
     * <p>Returns the entity identity or the empty string if unknown.</p>
     *
     * @return the entity identity. May be the empty string.
     * @throws MslCryptoException if there is a crypto error accessing the
     *         entity identity.
     */
    virtual std::string getIdentity() const = 0;

    /**
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the authentication data MSL representation.
     * @throws MslEncoderException if there was an error constructing the
     *         MSL object.
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const = 0;

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const EntityAuthenticationData> other) const;

    /**
     * @return the entity authentication scheme.
     */
    EntityAuthenticationScheme getScheme() const { return scheme_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

protected:
    /**
     * Create a new entity authentication data object with the specified entity
     * authentication scheme.
     *
     * @param scheme the entity authentication scheme.
     */
    EntityAuthenticationData(const EntityAuthenticationScheme& scheme) : scheme_(scheme) {}

private:
    /** Entity authentication scheme. */
    const EntityAuthenticationScheme scheme_;
    /** Cached encodings. */
    typedef std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> MapType;
    mutable MapType encodings_;
};

bool operator==(const EntityAuthenticationData& a, const EntityAuthenticationData& b);
inline bool operator!=(const EntityAuthenticationData& a, const EntityAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ENTITYAUTHENTICATIONDATA_H_ */
