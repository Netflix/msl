/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>Provisioned entity authentication factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProvisionedAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * An identity provisioning service returns unique entity identities.
     */
    public interface IdentityProvisioningService {
        /**
         * @return the next unique entity identity.
         */
        public String nextIdentity();
    }
    
    /**
     * Construct a new provisioned authentication factory instance.
     * 
     * @param service the identity provisioning service to use.
     */
    public ProvisionedAuthenticationFactory(final IdentityProvisioningService service) {
        super(EntityAuthenticationScheme.PROVISIONED);
        this.service = service;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) {
        return new ProvisionedAuthenticationData(entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        // Make sure we have the right kind of entity authentication data.
        if (!(authdata instanceof ProvisionedAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + authdata.getClass().getName() + ".");
        final ProvisionedAuthenticationData pad = (ProvisionedAuthenticationData)authdata;
        
        // Provision an entity identity.
        final String identity = service.nextIdentity();
        pad.setIdentity(identity);
        
        // Return the crypto context.
        return new NullCryptoContext();
    }

    /** Identity provisioning service. */
    final IdentityProvisioningService service;
}
