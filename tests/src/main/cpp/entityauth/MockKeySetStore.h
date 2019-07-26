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

#ifndef TEST_ENTITYAUTH_MOCKKEYSETSTORE_H_
#define TEST_ENTITYAUTH_MOCKKEYSETSTORE_H_

#include <entityauth/KeySetStore.h>

#include <map>

namespace netflix {
namespace msl {
namespace entityauth {

class MockKeySetStore: public KeySetStore
{
public:
    virtual ~MockKeySetStore() {}
    MockKeySetStore() {}

    /**
     * Add a preshared key set to the store.
     *
     * @param identity preshared keys entity identity.
     * @param encryptionKey the encryption key.
     * @param hmacKey the HMAC key.
     * @param wrappingKey the wrapping key.
     */
    void addKeys(const std::string identity, const crypto::SecretKey& encryptionKey,
            const crypto::SecretKey& hmacKey, const crypto::SecretKey& wrappingKey)
    {
        KeySet keyset(encryptionKey, hmacKey, wrappingKey);
        keysets.erase(identity);
        keysets.insert(std::make_pair(identity, keyset));
    }

    /**
     * Remove all preshared key sets from the store.
     */
    void clear() { keysets.clear(); }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.KeySetStore#getKeys(java.lang.String)
     */
    virtual bool getKeys(const std::string& identity, KeySet& keyset) const {
        if (keysets.count(identity)) {
            keyset = keysets.at(identity);
            return true;
        }
        return false;
    }
private:
    /** Key sets. */
    std::map<std::string, KeySet> keysets;

};

}}} // namespace netflix::msl::entityauth

#endif /* TEST_ENTITYAUTH_MOCKKEYSETSTORE_H_ */
