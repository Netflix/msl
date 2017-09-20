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

#ifndef SRC_USERAUTH_USERAUTHENTICATIONDATA_H_
#define SRC_USERAUTH_USERAUTHENTICATIONDATA_H_

#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <userauth/UserAuthenticationScheme.h>
#include <vector>
#include <stdint.h>
#include <memory>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslObject; }
namespace tokens { class MasterToken; }
namespace util { class MslContext; }
namespace userauth {

/**
 * <p>The user authentication data provides proof of user identity.</p>
 *
 * <p>Specific user authentication mechanisms should define their own user
 * authentication data types.</p>
 *
 * <p>User authentication data is represented as
 * {@code
 * userauthdata = {
 *   "#mandatory" : [ "scheme"., "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where
 * <ul>
 * <li>{@code scheme} is the user authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific authentication data</li>
 * </ul></p>
 */
class UserAuthenticationData : public io::MslEncodable
{
public:
    virtual ~UserAuthenticationData() {}

    /**
     * <p>Construct a new user authentication data instance of the correct type
     * from the provided MSL object.</p>
     *
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token associated with the user
     *        authentication data. May be {@code null}.
     * @param userAuthMo the MSL object.
     * @return the user authentication data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if there is an error instantiating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     */
    static std::shared_ptr<UserAuthenticationData> create(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<io::MslObject> userAuthMo);

    /**
     * @return the user authentication scheme.
     */
    UserAuthenticationScheme getScheme() const { return scheme_; }

    /**
     * Returns the scheme-specific user authentication data. This method is
     * expected to succeed unless there is an internal error.
     *
     * @param encoder the encoder factory.
     * @param format the encoder format.
     * @return the authentication data MSL object.
     * @throws MslEncoderException if there was an error constructing the
     *         MSL object.
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(
            std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const = 0;


    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

    // FIXME: this should be protected, but a test complains
    /**
      * Create a new user authentication data object with the specified user
      * authentication scheme.
      *
      * @param scheme the user authentication scheme.
      */
    UserAuthenticationData(const UserAuthenticationScheme& scheme) : scheme_(scheme) {}

    virtual bool equals(std::shared_ptr<const UserAuthenticationData> that) const;

protected:
    // FIXME: this should be protected, but a test complains (see above)
//    /**
//      * Create a new user authentication data object with the specified user
//      * authentication scheme.
//      *
//      * @param scheme the user authentication scheme.
//      */
//    UserAuthenticationData(const UserAuthenticationScheme& scheme) : scheme_(scheme) {}

private:
    /** User authentication scheme. */
    const UserAuthenticationScheme scheme_;

    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings_;

};

bool operator==(const UserAuthenticationData& a, const UserAuthenticationData& b);
inline bool operator!=(const UserAuthenticationData& a, const UserAuthenticationData& b) { return !(a == b); }

}}} // namespace netflix::msl::entityauth

#endif /* SRC_USERAUTH_USERAUTHENTICATIONDATA_H_ */
