/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
package oneshot;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.entityauth.RsaStore;

/**
 * <p>Simple RSA store for the oneshot example.</p>
 */
public class OneshotRsaStore implements RsaStore {
    /**
     * <p>Create a new RSA store for the specified entity identity and matching
     * public key.</p>
     * 
     * @param identity entity identity.
     * @param pubkey entity public key.
     */
    public OneshotRsaStore(final String identity, final PublicKey pubkey) {
        this.identity = identity;
        this.pubkey = pubkey;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getIdentities()
     */
    @Override
    public Set<String> getIdentities() {
        return new HashSet<String>(Arrays.asList(identity));
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getPublicKey(java.lang.String)
     */
    @Override
    public PublicKey getPublicKey(final String identity) {
        if (this.identity.equals(identity))
            return pubkey;
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.RsaStore#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(final String identity) {
        return null;
    }

    /** Entity identity. */
    private final String identity;
    /** Public key. */
    private final PublicKey pubkey;
}
