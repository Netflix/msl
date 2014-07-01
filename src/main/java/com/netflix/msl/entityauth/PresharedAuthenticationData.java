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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;

/**
 * <p>Preshared keys entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity" ],
 *   "identity" : "string"
 * } where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PresharedAuthenticationData extends EntityAuthenticationData {
    /** JSON key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    
    /**
     * Construct a new preshared keys authentication data instance from the
     * specified entity identity.
     * 
     * @param identity the entity identity.
     */
    public PresharedAuthenticationData(final String identity) {
        super(EntityAuthenticationScheme.PSK);
        this.identity = identity;
    }
    
    /**
     * Construct a new preshared keys authentication data instance from the
     * provided JSON object.
     * 
     * @param presharedAuthJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    PresharedAuthenticationData(final JSONObject presharedAuthJO) throws MslEncodingException {
        super(EntityAuthenticationScheme.PSK);
        try {
            identity = presharedAuthJO.getString(KEY_IDENTITY);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "psk authdata " + presharedAuthJO.toString(), e);
        }
    }
    
    /**
     * @return the entity identity.
     */
    @Override
    public String getIdentity() {
        return identity;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_IDENTITY, identity);
            return jsonObj;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "psk authdata", e);
        }
    }

    /** Entity identity. */
    private final String identity;

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof PresharedAuthenticationData)) return false;
        final PresharedAuthenticationData that = (PresharedAuthenticationData)obj;
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
