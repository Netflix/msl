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

#include <keyx/KeyExchangeScheme.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

/** Asymmetric key wrapped. */
KeyExchangeScheme KeyExchangeScheme::ASYMMETRIC_WRAPPED("ASYMMETRIC_WRAPPED");
/** Diffie-Hellman exchange (Netflix SHA-384 key derivation). */
KeyExchangeScheme KeyExchangeScheme::DIFFIE_HELLMAN("DIFFIE_HELLMAN");
/** JSON web encryption ladder exchange. */
KeyExchangeScheme KeyExchangeScheme::JWE_LADDER("JWE_LADDER");
/** JSON web key ladder exchange. */
KeyExchangeScheme KeyExchangeScheme::JWK_LADDER("JWK_LADDER");
/** Symmetric key wrapped. */
KeyExchangeScheme KeyExchangeScheme::SYMMETRIC_WRAPPED("SYMMETRIC_WRAPPED");
/** Invalid. */
KeyExchangeScheme KeyExchangeScheme::INVALID("INVALID");
    
StaticMslMutex& KeyExchangeScheme::mutex()
{
    static StaticMslMutex mutex;
    return mutex;
}

std::map<std::string, KeyExchangeScheme>& KeyExchangeScheme::schemes()
{
    static std::map<std::string, KeyExchangeScheme> schemes;
    return schemes;
}


KeyExchangeScheme::KeyExchangeScheme(const std::string& name) : name_(name)
{
    // Add this scheme to the map.
    LockGuard lockGuard(mutex());
    schemes().insert(std::make_pair(name, *this));
}

//static
KeyExchangeScheme KeyExchangeScheme::getScheme(const std::string& name)
{
    LockGuard lockGuard(mutex());
    const MapType::const_iterator it = schemes().find(name);
    return (it == schemes().end()) ? INVALID : it->second;
}

//static
vector<KeyExchangeScheme> KeyExchangeScheme::values()
{
    LockGuard lockGuard(mutex());
    vector<KeyExchangeScheme> v;
    for(MapType::const_iterator it = schemes().begin(); it != schemes().end(); ++it)
        if (it->second != INVALID) v.push_back(it->second);
    return v;
}

bool operator==(const KeyExchangeScheme& a, const KeyExchangeScheme& b)
{
    return a.name() == b.name();
}


}}} // namespace netflix::msl::keyx
