/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Unauthenticated suffixed entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UnauthenticatedSuffixedAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Construct a new unauthenticated suffixed authentication factory instance.
     * 
     * @param authutils authentication utilities.
     */
    public UnauthenticatedSuffixedAuthenticationFactory(final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.NONE_SUFFIXED);
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException {
        return new UnauthenticatedSuffixedAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof UnauthenticatedSuffixedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final UnauthenticatedSuffixedAuthenticationData usad = (UnauthenticatedSuffixedAuthenticationData)authdata;
        
        // Check for revocation.
        final String root = usad.getRoot();
        if (authutils.isEntityRevoked(root))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "none suffixed " + root).setEntityAuthenticationData(usad);
        
        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(root, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + root + ":" + getScheme()).setEntityAuthenticationData(usad);
        
        // Return the crypto context.
        return new NullCryptoContext();
    }
    
    /** Authentication utilities. */
    final AuthenticationUtils authutils;
}