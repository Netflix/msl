/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

package mslcli.common.entityauth;

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.PresharedKeyStore.KeySet;

/**
 * <p>An example preshared key store backed by memory.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimplePresharedKeyStore implements PresharedKeyStore {
    /**
     * <p>Create a new preshared store that will return the provided preshared
     * keys for the specified identity.</p>
     * 
     * @param presharedKeys {identity, preshared_keys} map
     */
    public SimplePresharedKeyStore(final Map<String,KeySet> presharedKeys) {
        if (presharedKeys == null) {
            throw new IllegalArgumentException("NULL preshared key map");
        }
        this.presharedKeys.putAll(presharedKeys);
    }
    
    @Override
    public KeySet getKeys(final String identity) {
        if (identity == null) {
            throw new IllegalArgumentException("NULL identity");
        }
        return presharedKeys.get(identity);
    }

    /** preshared keys database */
    private final Map<String,KeySet> presharedKeys = new HashMap<String,KeySet>();
};
