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

import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>Failing entity authentication factory.</p>
 * 
 * <p>When used, this factory throws an {@link MslEntityAuthException}
 * containing the MSL error specified when constructed.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FailingEntityAuthenticationFactory extends EntityAuthenticationFactory {
    /**
     * Create a new failing entity authentication factory for the specified
     * scheme.
     * 
     * @param scheme the entity authentication scheme.
     * @param error the error to throw.
     */
    public FailingEntityAuthenticationFactory(final EntityAuthenticationScheme scheme, final MslError error) {
        super(scheme);
        this.error = error;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final MslObject entityAuthMo) throws MslEntityAuthException {
        throw new MslEntityAuthException(error);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    @Override
    public ICryptoContext getCryptoContext(final MslContext ctx, final EntityAuthenticationData authdata) throws MslEntityAuthException {
        throw new MslEntityAuthException(error);
    }

    /** MSL error. */
    private final MslError error;
}
