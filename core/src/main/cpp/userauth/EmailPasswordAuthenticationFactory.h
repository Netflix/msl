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

#ifndef SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONFACTORY_H_
#define SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONFACTORY_H_

#include <userauth/UserAuthenticationFactory.h>
#include <memory>

namespace netflix {
namespace msl {
namespace util { class AuthenticationUtils; }
namespace userauth {

class EmailPasswordStore;

/**
 * Email/password-based user authentication factory.
 */
class EmailPasswordAuthenticationFactory : public UserAuthenticationFactory
{
public:
    virtual ~EmailPasswordAuthenticationFactory() {}

    /**
     * Construct a new email/password-based user authentication factory.
     *
     * @param store email/password store.
     * @param authutils authentication utilities.
     */
    EmailPasswordAuthenticationFactory(std::shared_ptr<EmailPasswordStore> store,
            std::shared_ptr<util::AuthenticationUtils>);

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    virtual std::shared_ptr<UserAuthenticationData> createData(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<io::MslObject> userAuthMo);

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    virtual std::shared_ptr<tokens::MslUser> authenticate(std::shared_ptr<util::MslContext> ctx,
            const std::string& identity, std::shared_ptr<UserAuthenticationData> data,
            std::shared_ptr<tokens::UserIdToken> userIdToken);

private:
    EmailPasswordAuthenticationFactory(); // not implemented
private:
    /** Email/password store. */
    std::shared_ptr<EmailPasswordStore> store_;
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils_;
};

std::string strTrim(const std::string& str);

}}} // namespace netflix::msl::userauth

#endif /* SRC_USERAUTH_EMAILPASSWORDAUTHENTICATIONFACTORY_H_ */
