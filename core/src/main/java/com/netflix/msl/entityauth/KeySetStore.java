/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.entityauth;

import javax.crypto.SecretKey;

/**
 * A key set store contains trusted key sets.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface KeySetStore {
    /**
     * A set of encryption, HMAC, and wrapping keys.
     */
    public static class KeySet {
        /**
         * Create a new key set with the given keys.
         * 
         * @param encryptionKey the encryption key.
         * @param hmacKey the HMAC key.
         * @param wrappingKey the wrapping key.
         */
        public KeySet(final SecretKey encryptionKey, final SecretKey hmacKey, final SecretKey wrappingKey) {
            this.encryptionKey = encryptionKey;
            this.hmacKey = hmacKey;
            this.wrappingKey = wrappingKey;
        }
        
        /** Encryption key. */
        public final SecretKey encryptionKey;
        /** HMAC key. */
        public final SecretKey hmacKey;
        /** Wrapping key. */
        public final SecretKey wrappingKey;
    }
    
    /**
     * Return the encryption, HMAC, and wrapping keys for the given identity.
     * 
     * @param identity key set identity.
     * @return the keys set associated with the identity or null if not found.
     */
    public KeySet getKeys(final String identity);
}
