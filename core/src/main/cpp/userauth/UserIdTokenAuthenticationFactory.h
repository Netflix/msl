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

#ifndef SRC_USERAUTH_USERIDTOKENAUTHENTICATIONFACTORY_H_
#define SRC_USERAUTH_USERIDTOKENAUTHENTICATIONFACTORY_H_

#include <userauth/UserAuthenticationFactory.h>
#include <memory>

namespace netflix {
namespace msl {
namespace io { class MslObject; }
namespace tokens { class MasterToken; }
namespace util { class AuthenticationUtils; class MslContext; }
namespace userauth {

class UserAuthenticationData;

/**
 * User ID token-based user authentication factory.
 */
class UserIdTokenAuthenticationFactory : public UserAuthenticationFactory
{
public:
    virtual ~UserIdTokenAuthenticationFactory() {}

    /**
     * Construct a new user ID token-based user authentication factory.
     *
     * @param authutils authentication utilities.
     */
    UserIdTokenAuthenticationFactory(std::shared_ptr<util::AuthenticationUtils> authutils);

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
    UserIdTokenAuthenticationFactory(); // not implemented
private:
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils_;

};

}}} // netflix::msl::userauth

#endif /* SRC_USERAUTH_USERIDTOKENAUTHENTICATIONFACTORY_H_ */
