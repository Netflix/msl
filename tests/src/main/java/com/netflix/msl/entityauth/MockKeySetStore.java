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

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

/**
 * Test preshared keys store.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockKeySetStore implements KeySetStore {
    /**
     * Add a key set to the store.
     * 
     * @param identity keys set identity.
     * @param encryptionKey the encryption key.
     * @param hmacKey the HMAC key.
     * @param wrappingKey the wrapping key.
     */
    public void addKeys(final String identity, final SecretKey encryptionKey, final SecretKey hmacKey, final SecretKey wrappingKey) {
        final KeySet keyset = new KeySet(encryptionKey, hmacKey, wrappingKey);
        keysets.put(identity, keyset);
    }
    
    /**
     * Remove all preshared key sets from the store.
     */
    public void clear() {
        keysets.clear();
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.KeySetStore#getKeys(java.lang.String)
     */
    @Override
    public KeySet getKeys(final String identity) {
        return keysets.get(identity);
    }
    
    /** Key sets. */
    private final Map<String,KeySet> keysets = new HashMap<String,KeySet>();
}
