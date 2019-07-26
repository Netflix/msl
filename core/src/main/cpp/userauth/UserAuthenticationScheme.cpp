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

#include <userauth/UserAuthenticationScheme.h>

using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace userauth {

//StaticMslMutex UserAuthenticationScheme::mutex_;
//std::map<std::string, UserAuthenticationScheme> UserAuthenticationScheme::schemes();

const UserAuthenticationScheme UserAuthenticationScheme::EMAIL_PASSWORD("EMAIL_PASSWORD");
const UserAuthenticationScheme UserAuthenticationScheme::USER_ID_TOKEN("USER_ID_TOKEN");
const UserAuthenticationScheme UserAuthenticationScheme::INVALID("INVALID");

// static
IMutex& UserAuthenticationScheme::mutex()
{
    static StaticMslMutex mutex;
    return mutex;
}
    
// static
std::map<std::string, UserAuthenticationScheme>& UserAuthenticationScheme::schemes()
{
    static std::map<std::string, UserAuthenticationScheme> schemes;
    return schemes;
}

// static
UserAuthenticationScheme UserAuthenticationScheme::getScheme(const std::string& name)
{
    LockGuard lockGuard(mutex());
    const MapType::const_iterator it = schemes().find(name);
    return (it == schemes().end()) ? INVALID : it->second;
}

// static
std::vector<UserAuthenticationScheme> UserAuthenticationScheme::values()
{
    LockGuard lockGuard(mutex());
    std::vector<UserAuthenticationScheme> v;
    for(MapType::const_iterator it = schemes().begin(); it != schemes().end(); ++it)
        if (it->second != INVALID) v.push_back(it->second);
    return v;
}

UserAuthenticationScheme::UserAuthenticationScheme(const std::string& name) : name_(name)
{
    LockGuard lockGuard(UserAuthenticationScheme::mutex());
    schemes().insert(std::make_pair(name, *this));
}

bool operator==(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b)
{
    return a.name() == b.name();
}

bool operator!=(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b)
{
    return !(a == b);
}

bool operator<(const UserAuthenticationScheme& a, const UserAuthenticationScheme& b) {
    return a.name() > b.name();
}

}}} // namespace netflix::msl::userauth
