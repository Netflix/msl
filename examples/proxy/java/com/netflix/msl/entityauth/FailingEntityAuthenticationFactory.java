/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.entityauth;

import org.json.JSONObject;

import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.ICryptoContext;
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
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, org.json.JSONObject)
     */
    @Override
    public EntityAuthenticationData createData(final MslContext ctx, final JSONObject entityAuthJO) throws MslEntityAuthException {
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
