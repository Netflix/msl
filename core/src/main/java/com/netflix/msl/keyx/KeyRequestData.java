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
package com.netflix.msl.keyx;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.util.MslContext;

/**
 * <p>Key request data contains all the data needed to facilitate a exchange of
 * session keys with the requesting entity.</p>
 * 
 * <p>Specific key exchange mechanisms should define their own key request data
 * types.</p>
 * 
 * <p>Key request data is represented as
 * {@code
 * keyrequestdata = {
 *   "#mandatory" : [ "scheme", "keydata" ],
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class KeyRequestData implements MslEncodable {
    /** Key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    /**
     * Create a new key request data object with the specified key exchange
     * scheme.
     * 
     * @param scheme the key exchange scheme.
     */
    protected KeyRequestData(final KeyExchangeScheme scheme) {
        this.scheme = scheme;
    }
    
    /**
     * Construct a new key request data instance of the correct type from the
     * provided MSL object.
     * 
     * @param ctx MSL context.
     * @param keyRequestDataMo the MSL object.
     * @return the key request data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error verifying the key
     *         request data.
     * @throws MslEntityAuthException if the entity authentication data could
     *         not be created.
     * @throws MslKeyExchangeException if unable to create the key request
     *         data.
     */
    public static KeyRequestData create(final MslContext ctx, final MslObject keyRequestDataMo) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslKeyExchangeException {
        try {
            // Pull the key data.
            final String schemeName = keyRequestDataMo.getString(KEY_SCHEME);
            final KeyExchangeScheme scheme = ctx.getKeyExchangeScheme(schemeName);
            if (scheme == null)
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            final MslObject keyData = keyRequestDataMo.getMslObject(KEY_KEYDATA, encoder);

            // Construct an instance of the concrete subclass.
            final KeyExchangeFactory keyFactory = ctx.getKeyExchangeFactory(scheme);
            if (keyFactory == null)
                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name());
            return keyFactory.createRequestData(ctx, keyData);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keyrequestdata " + keyRequestDataMo, e);
        }
    }
    
    /**
     * @return the key exchange scheme.
     */
    public KeyExchangeScheme getKeyExchangeScheme() {
        return scheme;
    }
    
    /**
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @return the key data MSL representation.
     * @throws MslEncoderException if there was an error constructing the MSL
     *         representation.
     */
    protected abstract MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException;
    
    /** Key exchange scheme. */
    private final KeyExchangeScheme scheme;
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public final byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_SCHEME, scheme.name());
        mo.put(KEY_KEYDATA, getKeydata(encoder, format));
        return encoder.encodeObject(mo, format);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof KeyRequestData)) return false;
        final KeyRequestData that = (KeyRequestData)obj;
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
