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

#ifndef TEST_USERAUTH_MOCKUSERIDTOKENAUTHENTICATIONFACTORY_H_
#define TEST_USERAUTH_MOCKUSERIDTOKENAUTHENTICATIONFACTORY_H_

#include <userauth/UserAuthenticationFactory.h>
#include <memory>

namespace netflix {
namespace msl {
namespace userauth {

/**
 * Test user ID token authentication factory.
 */
class MockUserIdTokenAuthenticationFactory : public UserAuthenticationFactory
{
public:
    virtual ~MockUserIdTokenAuthenticationFactory() {}

    /**
     * Create a new test user ID token authentication factory. By default no
     * tokens are accepted.
     */
    MockUserIdTokenAuthenticationFactory();

    /**
     * <p>Set the master token and user ID token pair to accept. The user ID
     * token must be bound to the master token.</p>
     *
     * @param masterToken the master token to accept.
     * @param userIdToken the user ID token to accept.
     */
    void setTokens(std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

    /**
     * @return the accepted master token.
     */
    std::shared_ptr<tokens::MasterToken> getMasterToken() { return masterToken_; };

    /**
     * @return the accepted user ID token.
     */
    std::shared_ptr<tokens::UserIdToken> getUserIdToken() { return userIdToken_; }

    virtual std::shared_ptr<UserAuthenticationData> createData(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken,
            std::shared_ptr<io::MslObject> userAuthMo);

    virtual std::shared_ptr<tokens::MslUser> authenticate(std::shared_ptr<util::MslContext> ctx,
            const std::string& identity, std::shared_ptr<UserAuthenticationData> data,
            std::shared_ptr<tokens::UserIdToken> userIdToken);

private:
    /** Master token. */
    std::shared_ptr<tokens::MasterToken> masterToken_;
    /** User ID token. */
    std::shared_ptr<tokens::UserIdToken> userIdToken_;

};

}}} // netflix::msl::userauth

#endif /* TEST_USERAUTH_MOCKUSERIDTOKENAUTHENTICATIONFACTORY_H_ */
