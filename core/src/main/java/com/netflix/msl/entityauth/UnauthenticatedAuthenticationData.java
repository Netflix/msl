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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>Unauthenticated entity authentication data. This form of authentication
 * is used by entities that cannot provide any form of entity
 * authentication.</p>
 * 
 * <p>Unauthenticated entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "identity" ],
 *   "identity" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UnauthenticatedAuthenticationData extends EntityAuthenticationData {
    /** Key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    
    /**
     * Construct a new unauthenticated entity authentication data instance from
     * the specified entity identity.
     * 
     * @param identity the entity identity.
     */
    public UnauthenticatedAuthenticationData(final String identity) {
        super(EntityAuthenticationScheme.NONE);
        this.identity = identity;
    }
    
    /**
     * Construct a new unauthenticated entity authentication data instance from
     * the provided MSL object.
     * 
     * @param unauthenticatedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL data.
     */
    UnauthenticatedAuthenticationData(final MslObject unauthenticatedAuthMo) throws MslEncodingException {
        super(EntityAuthenticationScheme.NONE);
        try {
            identity = unauthenticatedAuthMo.getString(KEY_IDENTITY);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "unauthenticated authdata " + unauthenticatedAuthMo, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return identity;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_IDENTITY, identity);
        return mo;
    }

    /** Entity identity. */
    private final String identity;

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof UnauthenticatedAuthenticationData)) return false;
        final UnauthenticatedAuthenticationData that = (UnauthenticatedAuthenticationData)obj;
        return super.equals(obj) && this.identity.equals(that.identity);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ identity.hashCode();
    }
}
