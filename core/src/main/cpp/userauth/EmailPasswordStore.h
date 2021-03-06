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

#ifndef SRC_USERAUTH_EMAILPASSWORDSTORE_H_
#define SRC_USERAUTH_EMAILPASSWORDSTORE_H_

#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace tokens { class  MslUser; }
namespace userauth {

/**
 * An email/password store contains user credentials.
 */
class EmailPasswordStore
{
public:
    virtual ~EmailPasswordStore() {}

    /**
     * Return the user if the email/password combination is valid.
     *
     * @param email email address.
     * @param password password.
     * @return the MSL user or null if there is no such user.
     */
    virtual std::shared_ptr<tokens::MslUser> isUser(const std::string& email, const std::string& password) = 0;
};

}}} // netflix::msl::userauth

#endif /* SRC_USERAUTH_EMAILPASSWORDSTORE_H_ */
