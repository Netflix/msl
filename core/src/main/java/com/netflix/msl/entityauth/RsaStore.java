/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

/**
 * An RSA public key store contains trusted RSA public and private keys.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface RsaStore {
    /**
     * @return the known key pair identities.
     */
    public Set<String> getIdentities();

    /**
     * Return the public key of the identified RSA key pair.
     *
     * @param identity RSA key pair identity.
     * @return the public key of the identified key pair or null if not found.
     */
    public PublicKey getPublicKey(final String identity);
    
    /**
     * Return the private key of the identified RSA key pair.
     * 
     * @param identity RSA key pair identity.
     * @return the private key of the identified key pair or null if not found.
     */
    public PrivateKey getPrivateKey(final String identity);
}
