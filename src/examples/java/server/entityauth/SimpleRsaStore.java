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
package server.entityauth;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.entityauth.RsaStore;

/**
 * <p>An example RSA key store.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleRsaStore implements RsaStore {
    /**
     * <p>Create a new RSA store that will return the provided public and/or
     * private keys for the specified server entity identity. A public key must
     * be provided to authenticate remote entities. A private key must be
     * provided to authenticate local entities.</p>
     * 
     * @param serverId server entity identity.
     * @param publicKey server RSA public key. May be null.
     * @param privateKey server RSA private key. May be null.
     */
    public SimpleRsaStore(final String serverId, final PublicKey publicKey, final PrivateKey privateKey) {
        this.serverId = serverId;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    
    @Override
    public Set<String> getIdentities() {
        return new HashSet<String>(Arrays.asList(serverId));
    }

    @Override
    public PublicKey getPublicKey(final String identity) {
        if (serverId.equals(identity))
            return publicKey;
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(final String identity) {
        if (serverId.equals(identity))
            return privateKey;
        return null;
    }
    
    /** Server entity identity. */
    private final String serverId;
    /** Server RSA public key. */
    private final PublicKey publicKey;
    /** Server RSA private key. */
    private final PrivateKey privateKey;
};