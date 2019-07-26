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

#ifndef TEST_USERAUTH_MOCKEMAILPASSWORDAUTHENTICATIONFACTORY_H_
#define TEST_USERAUTH_MOCKEMAILPASSWORDAUTHENTICATIONFACTORY_H_

#include <userauth/UserAuthenticationFactory.h>
#include <userauth/UserAuthenticationScheme.h>
#include <string>

namespace netflix {
namespace msl {
namespace userauth {

class UserAuthenticationData;

/**
 * Test email/password authentication factory.
 */
class MockEmailPasswordAuthenticationFactory : public UserAuthenticationFactory
{
public:
    virtual ~MockEmailPasswordAuthenticationFactory() {}

    /** Email. */
    static const std::string EMAIL;
    /** Password. */
    static const std::string PASSWORD;
    /** User. */
    static std::shared_ptr<tokens::MslUser> USER();

    /** Email #2. */
    static const std::string EMAIL_2;
    /** Password #2. */
    static const std::string PASSWORD_2;
    /** User #2. */
    static std::shared_ptr<tokens::MslUser> USER_2();

    /**
     * Create a new test email/password authentication factory.
     */
    MockEmailPasswordAuthenticationFactory() : UserAuthenticationFactory(UserAuthenticationScheme::EMAIL_PASSWORD) {}

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    virtual std::shared_ptr<UserAuthenticationData> createData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<io::MslObject> userAuthMo);

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.EmailPasswordAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    virtual std::shared_ptr<tokens::MslUser> authenticate(std::shared_ptr<util::MslContext> ctx,
            const std::string& identity, std::shared_ptr<UserAuthenticationData> data,
            std::shared_ptr<tokens::UserIdToken> userIdToken);
};

std::string strTrim(const std::string& str);

}}} // netflix::msl::userauth

#endif /* TEST_USERAUTH_MOCKEMAILPASSWORDAUTHENTICATIONFACTORY_H_ */
