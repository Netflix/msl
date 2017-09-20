/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * A entity authentication factory creates authentication data instances and
 * authenticators for a specific entity authentication scheme.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class EntityAuthenticationFactory {
    /**
     * Create a new entity authentication factory for the specified scheme.
     * 
     * @param scheme the entity authentication scheme.
     */
    protected EntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        this.scheme = scheme;
    }
    
    /**
     * @return the entity authentication scheme this factory is for.
     */
    public EntityAuthenticationScheme getScheme() {
        return scheme;
    }
    
    /**
     * Construct a new entity authentication data instance from the provided
     * MSL object.
     * 
     * @param ctx MSL context.
     * @param entityAuthMo the MSL object.
     * @return the entity authentication data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     * @throws MslEntityAuthException if there is an error creating the entity
     *         authentication data.
     */
    public abstract EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException, MslEntityAuthException;
    
    /**
     * Create a crypto context that can be used to encrypt/decrypt and
     * authenticate data from the entity. The implementation of this function
     * must, by necessity, authenticate the entity authentication data.
     * 
     * @param ctx MSL context.
     * @param authdata the authentication data.
     * @return the entity crypto context.
     * @throws MslCryptoException if there is an error instantiating the crypto
     *         context.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    public abstract ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException;
    
    /** The factory's entity authentication scheme. */
    private final EntityAuthenticationScheme scheme;
}
