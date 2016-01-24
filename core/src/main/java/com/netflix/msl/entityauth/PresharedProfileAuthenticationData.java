/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
 * <p>Preshared keys profile entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "pskid", "profile" ],
 *   "pskid" : "string",
 *   "profile" : "string",
 * }} where:
 * <ul>
 * <li>{@code pskid} is the entity preshared keys identity</li>
 * <li>{@code profile} is the entity profile</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@EqualsAndHashCode(callSuper = true)
@Getter
public class PresharedProfileAuthenticationData extends EntityAuthenticationData {
    /** JSON key entity preshared keys identity. */
    private static final String KEY_PSKID = "pskid";

    /** JSON key entity profile. */
    private static final String KEY_PROFILE = "profile";
    
    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = "-";

    /** Entity preshared keys identity. */
    private final String presharedKeysId;

    /** Entity profile. */
    private final String profile;

    /**
     * Construct a new preshared keys authentication data instance from the
     * specified entity preshared keys identity and profile.
     * 
     * @param presharedKeysId the entity preshared keys identity.
     * @param profile the entity profile.
     */
    public PresharedProfileAuthenticationData(final String presharedKeysId, final String profile) {
        super(EntityAuthenticationScheme.PSK_PROFILE);
        this.presharedKeysId = presharedKeysId;
        this.profile = profile;
    }

    /**
     * Construct a new preshared keys profile authentication data instance from
     * the provided JSON object.
     * 
     * @param authJo the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    public PresharedProfileAuthenticationData(final JSONObject authJo) throws MslEncodingException {
        super(EntityAuthenticationScheme.PSK_PROFILE);
        try {
            presharedKeysId = authJo.getString(KEY_PSKID);
            profile = authJo.getString(KEY_PROFILE);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "psk profile authdata " + authJo.toString(), e);
        }
    }

    /**
     * <p>Returns the entity identity. This is equal to the preshared keys
     * identity and profile strings joined with a hyphen, e.g.
     * {@code pskid-profile}.</p>
     * 
     * @return the entity identity.
     */
    @Override
    public String getIdentity() {
        return presharedKeysId + CONCAT_CHAR + profile;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_PSKID, presharedKeysId);
            jsonObj.put(KEY_PROFILE, profile);
            return jsonObj;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "psk profile authdata", e);
        }
    }

}
