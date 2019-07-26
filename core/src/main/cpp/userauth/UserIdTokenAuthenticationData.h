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

#ifndef SRC_USERAUTH_USERIDTOKENAUTHENTICATIONDATA_H_
#define SRC_USERAUTH_USERIDTOKENAUTHENTICATIONDATA_H_

#include <userauth/UserAuthenticationData.h>
#include <memory>

namespace netflix {
namespace msl {
namespace io { class MslEncoderFactory; class MslEncoderFormat; class MslObject; }
namespace tokens { class MasterToken; class UserIdToken; }
namespace util { class MslContext; }
namespace userauth {

/**
 * <p>User ID token-based user authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "useridtoken" ],
 *   "mastertoken" : mastertoken,
 *   "useridtoken" : useridtoken,
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * </ul></p>
 */
class UserIdTokenAuthenticationData: public UserAuthenticationData
{
public:
    virtual ~UserIdTokenAuthenticationData() {}

    /**
     * Construct a new user ID token authentication data instance from the
     * provided master token and user ID token.
     *
     * @param masterToken the master token.
     * @param userIdToken the user ID token.
     */
    UserIdTokenAuthenticationData(std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * Construct a new user ID token authentication data instance from the
     * provided MSL object.
     *
     * @param ctx MSl context.
     * @param userIdTokenAuthMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if the token data is invalid or the user ID
     *         token is not bound to the master token.
     */
    UserIdTokenAuthenticationData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> userIdTokenAuthMo);

    /**
     * @return the master token.
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() const { return masterToken_; }

    /**
     * @return the user ID token.
     */
    std::shared_ptr<tokens::UserIdToken> getUserIdToken() const { return userIdToken_; }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual std::shared_ptr<io::MslObject> getAuthData(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

    virtual bool equals(std::shared_ptr<const UserAuthenticationData> that) const;

    std::string toString() const;  // FIXME: debug only

private:
    UserIdTokenAuthenticationData(); // not implemented
private:
    /** Master token. */
    std::shared_ptr<tokens::MasterToken> masterToken_;
    /** User ID token. */
    std::shared_ptr<tokens::UserIdToken> userIdToken_;
};

bool operator==(const UserIdTokenAuthenticationData& a, const UserIdTokenAuthenticationData& b);
inline bool operator!=(const UserIdTokenAuthenticationData& a, const UserIdTokenAuthenticationData& b) { return !(a == b); }

}}} // netflix::msl::userauth

#endif /* SRC_USERAUTH_USERIDTOKENAUTHENTICATIONDATA_H_ */
