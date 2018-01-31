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

#include "MockEmailPasswordStore.h"

#include <IllegalArgumentException.h>
#include <tokens/MslUser.h>

using namespace std;
using namespace netflix::msl::tokens;

namespace netflix {
namespace msl {
namespace userauth {

void MockEmailPasswordStore::addUser(const string& email, const string& password,
        shared_ptr<MslUser> user)
{
    if (strTrim(email).empty())
        throw IllegalArgumentException("Email cannot be blank.");
    if (strTrim(password).empty())
        throw IllegalArgumentException("Password cannot be blank.");

    const UserAndPassword iap(user, password);
    credentials.erase(email);
    credentials.insert(make_pair(email, iap));
}

void MockEmailPasswordStore::clear()
{
    credentials.clear();
}

shared_ptr<MslUser> MockEmailPasswordStore::isUser(const string& email, const string& password)
{
    map<string, UserAndPassword>::const_iterator it = credentials.find(email);
    if (it == credentials.end())
        return shared_ptr<MslUser>();
    return (it->second.password == password) ? it->second.user : shared_ptr<MslUser>();
}

}}} // namespace netflix::msl::userauth
