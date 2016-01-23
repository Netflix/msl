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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;

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
@EqualsAndHashCode(callSuper = true)
@Getter
public class UnauthenticatedAuthenticationData extends EntityAuthenticationData {
    /** JSON key entity identity. */
    private static final String KEY_IDENTITY = "identity";

    /** Entity identity. */
    private final String identity;

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
     * the provided JSON object.
     * 
     * @param unauthenticatedAuthJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     */
    UnauthenticatedAuthenticationData(final JSONObject unauthenticatedAuthJO) throws MslEncodingException {
        super(EntityAuthenticationScheme.NONE);
        try {
            identity = unauthenticatedAuthJO.getString(KEY_IDENTITY);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "unauthenticated authdata " + unauthenticatedAuthJO.toString(), e);
        }
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
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "unauthenticated authdata", e);
        }
    }

}
