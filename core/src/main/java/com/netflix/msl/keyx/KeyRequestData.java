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

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Value;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;
import org.json.JSONStringer;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
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
@EqualsAndHashCode
@Getter
@AllArgsConstructor
public abstract class KeyRequestData implements JSONString {
    /** JSON key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    private static final String KEY_KEYDATA = "keydata";

    /** Key exchange scheme. */
    private final KeyExchangeScheme keyExchangeScheme;

    /**
     * Construct a new key request data instance of the correct type from the
     * provided JSON object.
     * 
     * @param ctx MSL context.
     * @param keyRequestDataJO the JSON object.
     * @return the key request data concrete instance.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error verifying the key
     *         request data.
     * @throws MslEntityAuthException if the entity authentication data could
     *         not be created.
     * @throws MslKeyExchangeException if unable to create the key request
     *         data.
     */
    public static KeyRequestData create(final MslContext ctx, final JSONObject keyRequestDataJO) throws MslEncodingException, MslCryptoException, MslEntityAuthException, MslKeyExchangeException {
        try {
            // Pull the key data.
            final String schemeName = keyRequestDataJO.getString(KEY_SCHEME);
            final KeyExchangeScheme scheme = ctx.getKeyExchangeScheme(schemeName);
            if (scheme == null)
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);
            final JSONObject keyData = keyRequestDataJO.getJSONObject(KEY_KEYDATA);

            // Construct an instance of the concrete subclass.
            final KeyExchangeFactory keyFactory = ctx.getKeyExchangeFactory(scheme);
            if (keyFactory == null)
                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name());
            return keyFactory.createRequestData(ctx, keyData);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keyrequestdata " + keyRequestDataJO.toString(), e);
        }
    }
    
    /**
     * @return the key data JSON representation.
     * @throws JSONException if there was an error constructing the JSON
     *         representation.
     */
    protected abstract JSONObject getKeydata() throws JSONException;
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public final String toJSONString() {
        try {
            return new JSONStringer()
                .object()
                    .key(KEY_SCHEME).value(keyExchangeScheme.name())
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

}
