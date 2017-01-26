/**
 * Copyright 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.msl.userauth;

import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;


/**
 * <p>The user authentication data provides proof of user identity.</p>
 * 
 * <p>Specific user authentication mechanisms should define their own user
 * authentication data types.</p>
 * 
 * <p>User authentication data is represented as
 * {@code
 * userauthdata = {
 *   "#mandatory" : [ "scheme"., "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where
 * <ul>
 * <li>{@code scheme} is the user authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific authentication data</li>
 * </ul></p>
 */
public abstract class UserAuthenticationData implements MslEncodable {
    /** Key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    
    /**
     * Create a new user authentication data object with the specified user
     * authentication scheme.
     * 
     * @param scheme the user authentication scheme.
     */
    protected UserAuthenticationData(final UserAuthenticationScheme scheme) {
        this.scheme = scheme;
    }

    /**
     * <p>Construct a new user authentication data instance of the correct type
     * from the provided MSL object.</p>
     * 
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken the master token associated with the user
     *        authentication data. May be {@code null}.
     * @param userAuthMo the MSL object.
     * @return the user authentication data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if there is an error instantiating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     */
    public static UserAuthenticationData create(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslUserAuthException, MslEncodingException, MslCryptoException {
        try {
            // Pull the scheme.
            final String schemeName = userAuthMo.getString(KEY_SCHEME);
            final UserAuthenticationScheme scheme = ctx.getUserAuthenticationScheme(schemeName);
            if (scheme == null)
                throw new MslUserAuthException(MslError.UNIDENTIFIED_USERAUTH_SCHEME, schemeName);
            
            // Construct an instance of the concrete subclass.
            final UserAuthenticationFactory factory = ctx.getUserAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name());
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            return factory.createData(ctx, masterToken, userAuthMo.getMslObject(KEY_AUTHDATA, encoder));
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "userauthdata " + userAuthMo, e);
        }
    }
    
    /**
     * @return the user authentication scheme.
     */
    public UserAuthenticationScheme getScheme() {
        return scheme;
    }
    
    /**
     * Returns the scheme-specific user authentication data. This method is
     * expected to succeed unless there is an internal error.
     * 
     * @param encoder the encoder factory.
     * @param format the encoder format.
     * @return the authentication data MSL object.
     * @throws MslEncoderException if there was an error constructing the
     *         MSL object.
     */
    public abstract MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException;
    
    /** User authentication scheme. */
    private final UserAuthenticationScheme scheme;
    
    /** Cached encodings. */
    private final Map<MslEncoderFormat,byte[]> encodings = new HashMap<MslEncoderFormat,byte[]>();
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        // Return any cached encoding.
        if (encodings.containsKey(format))
            return encodings.get(format);
        
        // Encode the user authentication data.
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
        if (!(obj instanceof UserAuthenticationData)) return false;
        final UserAuthenticationData that = (UserAuthenticationData)obj;
        return scheme.equals(that.scheme);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return scheme.hashCode();
    }
    
}