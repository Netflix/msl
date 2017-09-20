/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
public class PresharedProfileAuthenticationData extends EntityAuthenticationData {
    /** Key entity preshared keys identity. */
    private static final String KEY_PSKID = "pskid";
    /** Key entity profile. */
    private static final String KEY_PROFILE = "profile";
    
    /** Identity concatenation character. */
    private static final String CONCAT_CHAR = "-";

    /**
     * Construct a new preshared keys authentication data instance from the
     * specified entity preshared keys identity and profile.
     * 
     * @param pskid the entity preshared keys identity.
     * @param profile the entity profile.
     */
    public PresharedProfileAuthenticationData(final String pskid, final String profile) {
        super(EntityAuthenticationScheme.PSK_PROFILE);
        this.pskid = pskid;
        this.profile = profile;
    }

    /**
     * Construct a new preshared keys profile authentication data instance from
     * the provided MSL object.
     * 
     * @param authMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    public PresharedProfileAuthenticationData(final MslObject authMo) throws MslEncodingException {
        super(EntityAuthenticationScheme.PSK_PROFILE);
        try {
            pskid = authMo.getString(KEY_PSKID);
            profile = authMo.getString(KEY_PROFILE);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "psk profile authdata " + authMo.toString(), e);
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
        return pskid + CONCAT_CHAR + profile;
    }
    
    /**
     * @return the entity preshared keys identity.
     */
    public String getPresharedKeysId() {
        return pskid;
    }
    
    /**
     * @return the entity profile.
     */
    public String getProfile() {
        return profile;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_PSKID, pskid);
        mo.put(KEY_PROFILE, profile);
        return mo;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof PresharedProfileAuthenticationData)) return false;
        final PresharedProfileAuthenticationData that = (PresharedProfileAuthenticationData)obj;
        return super.equals(obj) && this.pskid.equals(that.pskid) && this.profile.equals(that.profile);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ pskid.hashCode() ^ profile.hashCode();
    }

    /** Entity preshared keys identity. */
    private final String pskid;
    /** Entity profile. */
    private final String profile;
}
