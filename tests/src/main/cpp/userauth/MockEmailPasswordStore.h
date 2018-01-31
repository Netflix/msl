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

#ifndef TEST_USERAUTH_MOCKEMAILPASSWORDSTORE_H_
#define TEST_USERAUTH_MOCKEMAILPASSWORDSTORE_H_

#include <userauth/EmailPasswordStore.h>
#include <map>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace tokens { class MslUser; }
namespace userauth {

class UserAndPassword;

/**
 * Fake email/password store.
 */
class MockEmailPasswordStore : public EmailPasswordStore
{
public:
    /**
     * Add a user to the store.
     *
     * @param email email address.
     * @param password password.
     * @param user user.
     */
    void addUser(const std::string& email, const std::string& password, std::shared_ptr<tokens::MslUser> user);

    /**
     * Clear all known users.
     */
    void clear();

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.EmailPasswordStore#isUser(java.lang.String, java.lang.String)
     */
    virtual std::shared_ptr<tokens::MslUser> isUser(const std::string& email, const std::string& password);

private:
    /**
     * A user and password pair.
     */
    struct UserAndPassword
    {
        /**
         * Create a new user and password pair.
         *
         * @param user MSL user.
         * @param password user password.
         */
        UserAndPassword(std::shared_ptr<tokens::MslUser> user, const std::string& password)
        : user(user), password(password) {}

        /** User. */
        std::shared_ptr<tokens::MslUser> user;
        /** User password. */
        const std::string password;
    };

    /** Map of email addresses onto user ID and password pairs. */
    std::map<std::string, UserAndPassword> credentials;
};

std::string strTrim(const std::string& str);

}}} // namespace netflix::msl::userauth


#endif /* TEST_USERAUTH_MOCKEMAILPASSWORDSTORE_H_ */
