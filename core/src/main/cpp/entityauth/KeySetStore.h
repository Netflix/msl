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

#ifndef SRC_ENTITYAUTH_KEYSETSTORE_H_
#define SRC_ENTITYAUTH_KEYSETSTORE_H_

#include <crypto/Key.h>

namespace netflix {
namespace msl {
namespace entityauth {

class KeySetStore
{
public:
    virtual ~KeySetStore() {}
    /**
     * A set of encryption, HMAC, and wrapping keys.
     */
    struct KeySet
    {
        /**
         * Create a new key set with the given keys.
         *
         * @param encryptionKey the encryption key.
         * @param hmacKey the HMAC key.
         * @param wrappingKey the wrapping key.
         */
        KeySet(const crypto::SecretKey& encryptionKey,
                const crypto::SecretKey& hmacKey,
                const crypto::SecretKey& wrappingKey)
        : encryptionKey(encryptionKey)
        , hmacKey(hmacKey)
        , wrappingKey(wrappingKey)
        {}

        /**
         * Create an empty key set.
         */
        KeySet()
        : encryptionKey(crypto::SecretKey())
        , hmacKey(crypto::SecretKey())
        , wrappingKey(crypto::SecretKey())
        {}

        KeySet(const KeySet& other)
        : encryptionKey(other.encryptionKey)
        , hmacKey(other.hmacKey)
        , wrappingKey(other.wrappingKey)
        {}

        KeySet& operator=(const KeySet& rhs) {
            encryptionKey = rhs.encryptionKey;
            hmacKey = rhs.hmacKey;
            wrappingKey = rhs.wrappingKey;
            return *this;
        }

        /** Encryption key. */
        crypto::SecretKey encryptionKey;
        /** HMAC key. */
        crypto::SecretKey hmacKey;
        /** Wrapping key. */
        crypto::SecretKey wrappingKey;
    };

    /**
     * Return the encryption, HMAC, and wrapping keys for the given identity.
     *
     * @param identity key set identity.
     * @param the keys set associated with the identity, if found.
     * @return true if found, false otherwise.
     */
    virtual bool getKeys(const std::string& identity, KeySet& keyset) const = 0;
};

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_KEYSETSTORE_H_ */
