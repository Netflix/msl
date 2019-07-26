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

#include "MockAuthenticationUtils.h"
#include <entityauth/EntityAuthenticationScheme.h>
#include <tokens/MslUser.h>
#include <userauth/UserAuthenticationScheme.h>
#include <keyx/KeyExchangeScheme.h>

using namespace std;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;

namespace netflix {
namespace msl {
namespace util {

void MockAuthenticationUtils::reset()
{
    revokedEntityIdentities.clear();
    revokedEntityAuthSchemes.clear();
    revokedUserAuthSchemes.clear();
    revokedEntityUserAuthSchemes.clear();
    revokedKeyxSchemes.clear();
}

void MockAuthenticationUtils::revokeEntity(const string& identity)
{
    revokedEntityIdentities.insert(identity);
}

void MockAuthenticationUtils::accept(string identity)
{
    revokedEntityIdentities.erase(identity);
}

bool MockAuthenticationUtils::isEntityRevoked(const string& identity)
{
    return revokedEntityIdentities.count(identity);
}

void MockAuthenticationUtils::permitScheme(const string& identity,
        const EntityAuthenticationScheme& scheme)
{
    // Find the revoked schemes set corresponding to this identity.
    map<string, set<EntityAuthenticationScheme>>::const_iterator it = revokedEntityAuthSchemes.find(identity);
    if (it == revokedEntityAuthSchemes.end())
        return;
    // Copy the found revoked schemes set from the container.
    set<EntityAuthenticationScheme> revokedSchemes = it->second;
    // Remove the permitted scheme from the revoked schemes copy.
    revokedSchemes.erase(scheme);
    // Remove the old revoked schemes set from the container,
    revokedEntityAuthSchemes.erase(it);
    // and replace with the modified one.
    revokedEntityAuthSchemes.insert(make_pair(identity, revokedSchemes));
}

void MockAuthenticationUtils::disallowScheme(const string& identity, const EntityAuthenticationScheme& scheme)
{
    map<string, set<EntityAuthenticationScheme>>::const_iterator it = revokedEntityAuthSchemes.find(identity);
    set<EntityAuthenticationScheme> revokedSchemes;
    // If a set of revoked schemes for this identity is found, make a copy and
    // remove it, since we have to modify and replace it
    if (it != revokedEntityAuthSchemes.end()) {
        revokedSchemes = it->second;
        revokedEntityAuthSchemes.erase(it);
    }
    // Add the revoked scheme and (re)insert into revokedEntityAuthSchemes.
    revokedSchemes.insert(scheme);
    revokedEntityAuthSchemes.insert(make_pair(identity, revokedSchemes));
}

bool MockAuthenticationUtils::isSchemePermitted(const string& identity, const EntityAuthenticationScheme& scheme)
{
    map<string, set<EntityAuthenticationScheme>>::const_iterator it = revokedEntityAuthSchemes.find(identity);
    if (it == revokedEntityAuthSchemes.end())
        return true;
    return it->second.count(scheme) == 0;
}

void MockAuthenticationUtils::permitScheme(const string& identity, const UserAuthenticationScheme& scheme)
{
    // Find the revoked schemes set corresponding to this identity.
    map<string, set<UserAuthenticationScheme>>::const_iterator it = revokedUserAuthSchemes.find(identity);
    if (it == revokedUserAuthSchemes.end())
        return;
    // Copy the found revoked schemes set from the container.
    set<UserAuthenticationScheme> revokedSchemes = it->second;
    // Remove the permitted scheme from the revoked schemes copy.
    revokedSchemes.erase(scheme);
    // Remove the old revoked schemes set from the container,
    revokedUserAuthSchemes.erase(it);
    // and replace with the modified one.
    revokedUserAuthSchemes.insert(make_pair(identity, revokedSchemes));
}

void MockAuthenticationUtils::disallowScheme(const string& identity, const UserAuthenticationScheme& scheme)
{
    map<string, set<UserAuthenticationScheme>>::const_iterator it = revokedUserAuthSchemes.find(identity);
    set<UserAuthenticationScheme> revokedSchemes;
    // If a set of revoked schemes for this identity is found, make a copy and
    // remove it, since we have to modify and replace it
    if (it != revokedUserAuthSchemes.end()) {
        revokedSchemes = it->second;
        revokedUserAuthSchemes.erase(it);
    }
    // Add the revoked scheme to the copy and put back the modified one.
    revokedSchemes.insert(scheme);
    revokedUserAuthSchemes.insert(make_pair(identity, revokedSchemes));
}

bool MockAuthenticationUtils::isSchemePermitted(const string& identity, const UserAuthenticationScheme& scheme)
{
    map<string, set<UserAuthenticationScheme>>::const_iterator it = revokedUserAuthSchemes.find(identity);
    if (it == revokedUserAuthSchemes.end())
        return true;
    return it->second.count(scheme) == 0;
}

void MockAuthenticationUtils::permitScheme(const string& identity, shared_ptr<MslUser> user, const UserAuthenticationScheme& scheme)
{
    map<string, map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>>::const_iterator it = revokedEntityUserAuthSchemes.find(identity);
    if (it == revokedEntityUserAuthSchemes.end())
        return;
    map<shared_ptr<MslUser>, set<UserAuthenticationScheme>> newEntityUsers = it->second; // copy

    map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>::const_iterator jt = newEntityUsers.find(user);
    if (jt == newEntityUsers.end())
        return;
    set<UserAuthenticationScheme> revokedSchemes = jt->second; // copy

    revokedSchemes.erase(scheme);

    // replace revokedSchemes with new edited version
    newEntityUsers.erase(jt);
    newEntityUsers.insert(make_pair(user, revokedSchemes));

    // replace entityusers with new edited version
    revokedEntityUserAuthSchemes.erase(it);
    revokedEntityUserAuthSchemes.insert(make_pair(identity, newEntityUsers));
}

void MockAuthenticationUtils::disallowScheme(const string& identity, shared_ptr<MslUser> user, const UserAuthenticationScheme& scheme)
{
    map<string, map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>>::const_iterator it = revokedEntityUserAuthSchemes.find(identity);
    map<shared_ptr<MslUser>, set<UserAuthenticationScheme>> entityUsers;
    if (it != revokedEntityUserAuthSchemes.end()) {
        entityUsers = it->second; // copy
        revokedEntityUserAuthSchemes.erase(it);
    }

    map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>::const_iterator jt = entityUsers.find(user);
    set<UserAuthenticationScheme> revokedSchemes;
    if (jt != entityUsers.end()) {
        revokedSchemes = jt->second; // copy
        entityUsers.erase(jt);
    }

    revokedSchemes.insert(scheme);
    entityUsers.insert(make_pair(user, revokedSchemes));
    revokedEntityUserAuthSchemes.insert(make_pair(identity, entityUsers));
}

bool MockAuthenticationUtils::isSchemePermitted(const string& identity, shared_ptr<MslUser> user, const UserAuthenticationScheme& scheme)
{
    map<string, map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>>::const_iterator it = revokedEntityUserAuthSchemes.find(identity);
    if (it == revokedEntityUserAuthSchemes.end())
        return true;
    const map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>& entityUsers = it->second;

    map<shared_ptr<MslUser>, set<UserAuthenticationScheme>>::const_iterator jt = entityUsers.find(user);
    if (jt == it->second.end())
        return true;
    const set<UserAuthenticationScheme>& revokedSchemes = jt->second;

    return revokedSchemes.count(scheme) == 0;
}

void MockAuthenticationUtils::permitScheme(const string& identity, const KeyExchangeScheme& scheme)
{
    std::map<std::string, set<KeyExchangeScheme>>::const_iterator it = revokedKeyxSchemes.find(identity);
    if (it == revokedKeyxSchemes.end())
        return;
    set<KeyExchangeScheme> revokedSchemes = it->second; // copy
    revokedSchemes.erase(scheme);
    revokedKeyxSchemes.erase(it);
    revokedKeyxSchemes.insert(make_pair(identity, revokedSchemes));
}

void MockAuthenticationUtils::disallowScheme(const string& identity, const KeyExchangeScheme& scheme)
{
    map<string, set<keyx::KeyExchangeScheme>>::const_iterator it = revokedKeyxSchemes.find(identity);
    set<keyx::KeyExchangeScheme> revokedSchemes;
    if (it != revokedKeyxSchemes.end()) {
        revokedSchemes = it->second; // copy
        revokedKeyxSchemes.erase(it);
    }
    revokedSchemes.insert(scheme);
    revokedKeyxSchemes.insert(make_pair(identity, revokedSchemes));
}

bool MockAuthenticationUtils::isSchemePermitted(const std::string& identity, const keyx::KeyExchangeScheme& scheme)
{
    map<string, set<KeyExchangeScheme>>::const_iterator it = revokedKeyxSchemes.find(identity);
    if (it == revokedKeyxSchemes.end())
        return true;
    return it->second.count(scheme) == 0;
}


}}} // namespace neetflix::msl::util
