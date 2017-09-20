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

#include "MockRsaStore.h"

using namespace std;
using namespace netflix::msl::crypto;

namespace netflix {
namespace msl {
namespace entityauth {

set<string> MockRsaStore::getIdentities() {
	set<string> identities;
	for (map<string,PublicKey>::const_iterator pubit = keys_.begin();
		 pubit != keys_.end();
		 ++pubit)
	{
		identities.insert(pubit->first);
	}
	for (map<string,PrivateKey>::const_iterator privit = privateKeys_.begin();
		 privit != privateKeys_.end();
		 ++privit)
	{
		identities.insert(privit->first);
	}
	return identities;
}

PublicKey MockRsaStore::getPublicKey(const string& identity) {
	map<string,PublicKey>::const_iterator pubit = keys_.find(identity);
	if (pubit == keys_.end())
		return PublicKey();
	return pubit->second;
}

PrivateKey MockRsaStore::getPrivateKey(const string& identity) {
	map<string,PrivateKey>::const_iterator privit = privateKeys_.find(identity);
	if (privit == privateKeys_.end())
		return PrivateKey();
	return privit->second;
}

void MockRsaStore::addPublicKey(const string& identity, const PublicKey& pubkey) {
	keys_.erase(identity);
	keys_.insert(make_pair(identity, pubkey));
}

void MockRsaStore::addPrivateKey(const string& identity, const PrivateKey& privkey) {
	privateKeys_.erase(identity);
	privateKeys_.insert(make_pair(identity, privkey));
}

void MockRsaStore::clear() {
	keys_.clear();
	privateKeys_.clear();
}

}}} // namespace netflix::msl::entityauth
