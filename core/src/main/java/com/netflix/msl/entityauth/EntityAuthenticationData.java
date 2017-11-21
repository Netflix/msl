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

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
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
public abstract class EntityAuthenticationData implements MslEncodable {
    /** Key entity authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
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
     * from the provided MSL object.
     * 
     * @param ctx MSL context.
     * @param entityAuthMo the MSL object.
     * @return the entity authentication data concrete instance.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslCryptoException if there is an error creating the entity
     *         authentication data crypto.
     */
    public static EntityAuthenticationData create(final MslContext ctx, final MslObject entityAuthMo) throws MslEntityAuthException, MslEncodingException, MslCryptoException {
        try {
            // Identify the concrete subclass from the authentication scheme.
            final String schemeName = entityAuthMo.getString(KEY_SCHEME);
            final EntityAuthenticationScheme scheme = ctx.getEntityAuthenticationScheme(schemeName);
            if (scheme == null)
                throw new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME, schemeName);
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final MslObject authdata = entityAuthMo.getMslObject(KEY_AUTHDATA, encoder);
            
            // Construct an instance of the concrete subclass.
            final EntityAuthenticationFactory factory = ctx.getEntityAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            return factory.createData(ctx, authdata);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "entityauthdata " + entityAuthMo, e);
        }
    }
    
    /**
     * @return the entity authentication scheme.
     */
    public EntityAuthenticationScheme getScheme() {
        return scheme;
    }
    
    /**
     * @return the entity identity. May be {@code null} if unknown.
     * @throws MslCryptoException if there is a crypto error accessing the
     *         entity identity.
     */
    public abstract String getIdentity() throws MslCryptoException;
    
    /**
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the authentication data MSL representation.
     * @throws MslEncoderException if there was an error constructing the
     *         MSL object.
     */
    public abstract MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException;
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public final byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);
        
        // Encode the entity authentication data.
        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME, scheme.name());
        mo.put(KEY_AUTHDATA, getAuthData(encoder, format));
        final byte[] encoding = encoder.encodeObject(mo, format);
        
        // Cache and return the encoding.
        encodings.put(format, encoding);
        return encoding;
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
    
    /** Entity authentication scheme. */
    private final EntityAuthenticationScheme scheme;
    
    /** Cached encodings. */
    private final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
}
