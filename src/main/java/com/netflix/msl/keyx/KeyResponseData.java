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
package com.netflix.msl.keyx;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;
import org.json.JSONStringer;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>Key response data contains all the data needed to facilitate a exchange of
 * session keys from the responseor.</p>
 * 
 * <p>Specific key exchange mechanisms should define their own key response data
 * types.</p>
 * 
 * <p>Key response data is represented as
 * {@code
 * keyresponsedata = {
 *   "#mandatory" : [ "mastertoken", "scheme", "keydata" ],
 *   "mastertoken" : mastertoken,
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token associated with the session keys</li>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class KeyResponseData implements JSONString {
    /** JSON key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key key data. */
    private static final String KEY_KEYDATA = "keydata";
    
    /**
     * Create a new key response data object with the specified key exchange
     * scheme and associated master token.
     * 
     * @param masterToken the master token.
     * @param scheme the key exchange scheme.
     */
    protected KeyResponseData(final MasterToken masterToken, final KeyExchangeScheme scheme) {
        this.masterToken = masterToken;
        this.scheme = scheme;
    }
    
    /**
     * Construct a new key response data instance of the correct type from the
     * provided JSON object.
     * 
     * @param ctx MSL context.
     * @param keyResponseDataJO the JSON object.
     * @return the key response data concrete instance.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslKeyExchangeException if unable to create the key response
     *         data.
     * @throws MslCryptoException if there is an error verifying the they key
     *         response data.
     * @throws MslException if the key response master token expiration
     *         timestamp occurs before the renewal window.
     */
    public static KeyResponseData create(final MslContext ctx, final JSONObject keyResponseDataJO) throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
        try {
            // Pull the key data.
            final MasterToken masterToken = new MasterToken(ctx, keyResponseDataJO.getJSONObject(KEY_MASTER_TOKEN));
            final String schemeName = keyResponseDataJO.getString(KEY_SCHEME);
            final KeyExchangeScheme scheme = KeyExchangeScheme.getScheme(schemeName);
            if (scheme == null)
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);
            final JSONObject keyData = keyResponseDataJO.getJSONObject(KEY_KEYDATA);
            
            // Construct an instance of the concrete subclass.
            final KeyExchangeFactory factory = ctx.getKeyExchangeFactory(scheme);
            if (factory == null)
                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name());
            return factory.createResponseData(ctx, masterToken, keyData);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keyresponsedata " + keyResponseDataJO.toString(), e);
        }
    }
    
    /**
     * @return the master token.
     */
    public MasterToken getMasterToken() {
        return masterToken;
    }
    
    /**
     * @return the key exchange scheme.
     */
    public KeyExchangeScheme getKeyExchangeScheme() {
        return scheme;
    }
    
    /**
     * @return the key data JSON representation.
     * @throws JSONException if there was an error constructing the JSON
     *         representation.
     */
    protected abstract JSONObject getKeydata() throws JSONException;
    
    /** Master token. */
    private final MasterToken masterToken;
    /** Key exchange scheme. */
    private final KeyExchangeScheme scheme;
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public final String toJSONString() {
        try {
            return new JSONStringer()
                .object()
                    .key(KEY_MASTER_TOKEN).value(masterToken)
                    .key(KEY_SCHEME).value(scheme.name())
                    .key(KEY_KEYDATA).value(getKeydata())
                .endObject()
                .toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return toJSONString();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof KeyResponseData)) return false;
        final KeyResponseData that = (KeyResponseData)obj;
        return masterToken.equals(that.masterToken) && scheme.equals(that.scheme);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return masterToken.hashCode() ^ scheme.hashCode();
    }
}
