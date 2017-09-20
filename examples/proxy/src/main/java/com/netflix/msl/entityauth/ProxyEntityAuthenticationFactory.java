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
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>The proxy entity authentication factory acts as a front for the proxy's
 * entity's authentication factory.</p>
 * 
 * <p>Attempting to authenticate a remote entity using this factory will throw
 * a {@link MslEntityAuthException} containing the specified MSL error. The
 * proxy will be authenticated using the backing factory.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ProxyEntityAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * <p>Create a new proxy entity authentication factory that will use the
     * provided backing factory to authenticate the specified entity identity,
     * and will throw exceptions using the specified MSL error.</p>
     * 
     * @param proxyIdentity the proxy entity identity.
     * @param proxyFactory the proxy entity authentication factory.
     * @param error the error to throw.
     */
    public ProxyEntityAuthenticationFactory(final String proxyIdentity, final EntityAuthenticationFactory proxyFactory, final MslError error) {
        super(proxyFactory.getScheme());
        this.proxyIdentity = proxyIdentity;
        this.proxyFactory = proxyFactory;
        this.error = error;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        return proxyFactory.createData(ctx, entityAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslCryptoException, MslEntityAuthException {
        // Authenticate the local entity.
        final String identity = authdata.getIdentity();
        if (proxyIdentity.equals(identity))
            return proxyFactory.getCryptoContext(ctx, authdata);
        
        // Otherwise throw an exception indicating the message requires
        // external processing.
        throw new MslEntityAuthException(error);
    }

    /** Proxy entity identity. */
    private final String proxyIdentity;
    /** Proxy entity authentication factory. */
    private final EntityAuthenticationFactory proxyFactory;
    /** MSL error. */
    private final MslError error;
}
