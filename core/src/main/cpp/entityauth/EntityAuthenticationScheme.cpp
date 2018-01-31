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

#include <entityauth/EntityAuthenticationScheme.h>
#include <util/Mutex.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

EntityAuthenticationScheme EntityAuthenticationScheme::PSK("PSK", true, true);
EntityAuthenticationScheme EntityAuthenticationScheme::PSK_PROFILE("PSK_PROFILE", true, true);
EntityAuthenticationScheme EntityAuthenticationScheme::X509("X509", false, true);
EntityAuthenticationScheme EntityAuthenticationScheme::RSA("RSA", false, true);
EntityAuthenticationScheme EntityAuthenticationScheme::ECC("ECC", false, true);
EntityAuthenticationScheme EntityAuthenticationScheme::NONE("NONE", false, false);
EntityAuthenticationScheme EntityAuthenticationScheme::NONE_SUFFIXED("NONE_SUFFIXED", false, false);
EntityAuthenticationScheme EntityAuthenticationScheme::MT_PROTECTED("MT_PROTECTED", false, false);
EntityAuthenticationScheme EntityAuthenticationScheme::PROVISIONED("PROVISIONED", false, false);
EntityAuthenticationScheme EntityAuthenticationScheme::INVALID("INVALID", false, false);
    
// static
StaticMslMutex& EntityAuthenticationScheme::mutex()
{
    static StaticMslMutex mutex;
    return mutex;
}
    
// static
std::map<std::string, EntityAuthenticationScheme>& EntityAuthenticationScheme::schemes()
{
    static std::map<std::string, EntityAuthenticationScheme> schemes;
    return schemes;
}

EntityAuthenticationScheme::EntityAuthenticationScheme(const string& name,
        bool encrypts, bool protects)
    : name_(name)
    , encrypts_(encrypts)
    , protects_(protects)
{
    LockGuard lockGuard(mutex());
    schemes().insert(make_pair(name, *this));
}

//static
EntityAuthenticationScheme EntityAuthenticationScheme::getScheme(const string& name)
{
    LockGuard lockGuard(mutex());
    const MapType::const_iterator it = schemes().find(name);
    return (it == schemes().end()) ? INVALID : it->second;
}

//static
vector<EntityAuthenticationScheme> EntityAuthenticationScheme::values()
{
    LockGuard lockGuard(mutex());
    vector<EntityAuthenticationScheme> v;
    for(MapType::const_iterator it = schemes().begin(); it != schemes().end(); ++it)
        if (it->second != INVALID) v.push_back(it->second);
    return v;
}

bool operator==(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b) {
    return a.name() == b.name();
}

bool operator!=(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b) {
    return !(a == b);
}

bool operator<(const EntityAuthenticationScheme& a, const EntityAuthenticationScheme& b) {
    return a.name() > b.name();
}

}}} // namespace netflix::msl::entityauth
