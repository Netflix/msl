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

#ifndef SRC_USERAUTH_USERAUTHENTICATIONSCHEME_H_
#define SRC_USERAUTH_USERAUTHENTICATIONSCHEME_H_

#include <util/StaticMslMutex.h>
#include <string>
#include <vector>
#include <map>

namespace netflix {
namespace msl {
namespace userauth {

/**
 * <p>User authentication schemes.</p>
 *
 * <p>The scheme name is used to uniquely identify user authentication
 * schemes.</p>
 */
class UserAuthenticationScheme
{
public:
    virtual ~UserAuthenticationScheme() {}

    /** Email/password. */
    static const UserAuthenticationScheme EMAIL_PASSWORD;
    /** User ID token. */
    static const UserAuthenticationScheme USER_ID_TOKEN;
    /** Invalid. */
    static const UserAuthenticationScheme INVALID;

    /**
     * @param name the entity authentication scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    static UserAuthenticationScheme getScheme(const std::string& name);

    /**
     * @return all known user authentication schemes.
     */
    static std::vector<UserAuthenticationScheme> values();

    /**
     * @return the scheme identifier.
     */
    std::string name() const { return name_; }

    std::string toString() const { return name(); }

protected:
    /**
     * Define a user authentication scheme with the specified name.
     *
     * @param name the user authentication scheme name.
     */
    UserAuthenticationScheme(const std::string& name);

private:
    static util::IMutex& mutex();
    typedef std::map<std::string, UserAuthenticationScheme> MapType;
    /** Map of names onto schemes. */
    
    static std::map<std::string, UserAuthenticationScheme>& schemes();
    std::string name_;
};

bool operator==(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b);
bool operator!=(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b);
bool operator<(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b);

}}} // namespace netflix::msl::userauth

#endif /* SRC_USERAUTH_USERAUTHENTICATIONSCHEME_H_ */
