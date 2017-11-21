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

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>RSA asymmetric keys entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity", "pubkeyid" ],
 *   "identity" : "string",
 *   "pubkeyid" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * <li>{@code pubkeyid} is the identity of the RSA public key associated with this identity</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RsaAuthenticationData extends EntityAuthenticationData {
    /** Key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    /** Key public key ID. */
    private static final String KEY_PUBKEY_ID = "pubkeyid";
    
    /**
     * Construct a new public key authentication data instance from the
     * specified entity identity and public key ID.
     * 
     * @param identity the entity identity.
     * @param pubkeyid the public key ID.
     */
    public RsaAuthenticationData(final String identity, final String pubkeyid) {
        super(EntityAuthenticationScheme.RSA);
        this.identity = identity;
        this.pubkeyid = pubkeyid;
    }
    
    /**
     * Construct a new RSA asymmetric keys authentication data instance from
     * the provided MSL object.
     * 
     * @param rsaAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the MSL data.
     */
    public RsaAuthenticationData(final MslObject rsaAuthMo) throws MslCryptoException, MslEncodingException {
        super(EntityAuthenticationScheme.RSA);
        try {
            // Extract RSA authentication data.
            identity = rsaAuthMo.getString(KEY_IDENTITY);
            pubkeyid = rsaAuthMo.getString(KEY_PUBKEY_ID);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "RSA authdata " + rsaAuthMo, e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return identity;
    }
    
    /**
     * @return the public key ID.
     */
    public String getPublicKeyId() {
        return pubkeyid;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_IDENTITY, identity);
        mo.put(KEY_PUBKEY_ID, pubkeyid);
        return mo;
    }

    /** Entity identity. */
    private final String identity;
    /** Public key ID. */
    private final String pubkeyid;

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof RsaAuthenticationData)) return false;
        final RsaAuthenticationData that = (RsaAuthenticationData)obj;
        return super.equals(obj) && this.identity.equals(that.identity) && this.pubkeyid.equals(that.pubkeyid);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ (identity + "|" + pubkeyid).hashCode();
    }
}
