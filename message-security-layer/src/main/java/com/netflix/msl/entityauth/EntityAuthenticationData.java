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

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;
import org.json.JSONStringer;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.util.MslContext;

/**
 * <p>The entity authentication data provides proof of entity identity.</p>
 * 
 * <p>Specific entity authentication mechanisms should define their own entity
 * authentication data types.</p>
 * 
 * <p>Entity authentication data is represented as
 * {@code
 * entityauthdata = {
 *   "#mandatory" : [ "scheme", "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the entity authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific entity authentication data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class EntityAuthenticationData implements JSONString {
    /** JSON key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    
    /**
     * Create a new entity authentication data object with the specified entity
     * authentication scheme.
     * 
     * @param scheme the entity authentication scheme.
     */
    protected EntityAuthenticationData(final EntityAuthenticationScheme scheme) {
        this.scheme = scheme;
    }
    
    /**
     * Construct a new entity authentication data instance of the correct type
     * from the provided JSON object.
     * 
     * @param ctx MSL context.
     * @param entityAuthJO the JSON object.
     * @return the entity authentication data concrete instance.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslCryptoException if there is an error creating the entity
     *         authentication data crypto.
     */
    public static EntityAuthenticationData create(final MslContext ctx, final JSONObject entityAuthJO) throws MslEntityAuthException, MslEncodingException, MslCryptoException {
        try {
            // Identify the concrete subclass from the authentication scheme.
            final String schemeName = entityAuthJO.getString(KEY_SCHEME);
            final EntityAuthenticationScheme scheme = EntityAuthenticationScheme.getScheme(schemeName);
            if (scheme == null)
                throw new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME, schemeName);
            final JSONObject authdata = entityAuthJO.getJSONObject(KEY_AUTHDATA);
            
            // Construct an instance of the concrete subclass.
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            return factory.createData(ctx, authdata);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "entityauthdata " + entityAuthJO.toString(), e);
        }
    }
    
    /**
     * @return the entity authentication scheme.
     */
    public EntityAuthenticationScheme getScheme() {
        return scheme;
    }
    
    /**
     * @return the entity identity.
     * @throws MslCryptoException if there is a crypto error accessing the
     *         entity identity.
     */
    public abstract String getIdentity() throws MslCryptoException;
    
    /**
     * @return the authentication data JSON representation.
     * @throws MslEncodingException if there was an error constructing the
     *         JSON representation.
     */
    public abstract JSONObject getAuthData() throws MslEncodingException;
    
    /** Entity authentication scheme. */
    private final EntityAuthenticationScheme scheme;
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public final String toJSONString() {
        try {
            return new JSONStringer()
                .object()
                    .key(KEY_SCHEME).value(scheme.name())
                    .key(KEY_AUTHDATA).value(getAuthData())
                .endObject()
                .toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        } catch (final MslEncodingException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof EntityAuthenticationData)) return false;
        final EntityAuthenticationData that = (EntityAuthenticationData)obj;
        return this.scheme.equals(that.scheme);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return scheme.hashCode();
    }
}
