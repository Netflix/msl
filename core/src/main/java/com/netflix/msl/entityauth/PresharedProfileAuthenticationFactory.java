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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.KeySetStore.KeySet;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Preshared keys profile entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PresharedProfileAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Construct a new preshared keys profile authentication factory instance.
     *
     * @param store preshared key store.
     * @param authutils authentication utilities.
     */
    public PresharedProfileAuthenticationFactory(final KeySetStore store, final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.PSK_PROFILE);
        this.store = store;
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException {
        return new PresharedProfileAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof PresharedProfileAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final PresharedProfileAuthenticationData ppad = (PresharedProfileAuthenticationData)authdata;
        
        // Check for revocation.
        final String pskId = ppad.getPresharedKeysId();
        if (authutils.isEntityRevoked(pskId))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "psk profile " + pskId).setEntityAuthenticationData(ppad);
        
        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(pskId, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + pskId + ":" + getScheme()).setEntityAuthenticationData(ppad);
        
        // Load key set.
        final KeySet keys = store.getKeys(pskId);
        if (keys == null)
            throw new MslEntityAuthException(MslError.ENTITY_NOT_FOUND, "psk profile " + pskId).setEntityAuthenticationData(ppad);
        
        // Return the crypto context.
        final String identity = ppad.getIdentity();
        return new SymmetricCryptoContext(ctx, identity, keys.encryptionKey, keys.hmacKey, keys.wrappingKey);
    }

    /** Preshared keys store. */
    private final KeySetStore store;
    /** Authentication utilities. */
    private final AuthenticationUtils authutils;
}
