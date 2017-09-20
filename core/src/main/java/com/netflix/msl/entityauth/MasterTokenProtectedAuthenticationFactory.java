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

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;

/**
 * <p>Master token protected entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenProtectedAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * <p>Construct a new master token protected entity authentication factory
     * instance.</p>
     * 
     * @param authutils authentication utilities.
     */
    public MasterTokenProtectedAuthenticationFactory(final AuthenticationUtils authutils) {
        super(EntityAuthenticationScheme.MT_PROTECTED);
        this.authutils = authutils;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        return new MasterTokenProtectedAuthenticationData(ctx, entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof MasterTokenProtectedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final MasterTokenProtectedAuthenticationData mtpad = (MasterTokenProtectedAuthenticationData)authdata;
        
        // Check for revocation.
        final String identity = mtpad.getIdentity();
        if (authutils.isEntityRevoked(identity))
            throw new MslEntityAuthException(MslError.ENTITY_REVOKED, "none " + identity).setEntityAuthenticationData(mtpad);

        // Verify the scheme is permitted.
        if (!authutils.isSchemePermitted(identity, getScheme()))
            throw new MslEntityAuthException(MslError.INCORRECT_ENTITYAUTH_DATA, "Authentication Scheme for Device Type Not Supported " + identity + ":" + getScheme()).setEntityAuthenticationData(mtpad);
        
        // Authenticate using the encapsulated authentication data.
        final EntityAuthenticationData ead = mtpad.getEncapsulatedAuthdata();
        final EntityAuthenticationScheme scheme = ead.getScheme();
        final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
        if (factory == null)
            throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name()).setEntityAuthenticationData(mtpad);
        return factory.getCryptoContext(ctx, ead);
    }
    
    /** Authentication utilities. */
    final AuthenticationUtils authutils;
}
