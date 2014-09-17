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
package com.netflix.msl.msg;

import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>A MSL header contains entity authentication data or a master token
 * identifying the message sender and data used to authenticate the header
 * data. Portions of the header may be encrypted.</p>
 * 
 * <p>A message header is represented as
 * {@code
 * header = {
 *   "#mandatory" : [ "headerdata", "signature" ],
 *   "#conditions" : [ "entityauthdata xor mastertoken" ],
 *   "entityauthdata" : entityauthdata,
 *   "mastertoken" : mastertoken,
 *   "headerdata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data (mutually exclusive with mastertoken)</li>
 * <li>{@code mastertoken} is the master token (mutually exclusive with entityauthdata)</li>
 * <li>{@code headerdata} is the Base64-encoded encrypted header data (headerdata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the header data</li>
 * </ul></p>
 * 
 * <p>An error header is represented as
 * {@code
 * errorheader = {
 *   "#mandatory" : [ "entityauthdata", "errordata", "signature" ],
 *   "entityauthdata" : entityauthdata,
 *   "errordata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data</li>
 * <li>{@code errordata} is the Base64-encoded encrypted error data (errordata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the error data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class Header implements JSONString {
    /** JSON key entity authentication data. */
    protected static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** JSON key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON key header data. */
    protected static final String KEY_HEADERDATA = "headerdata";
    /** JSON key error data. */
    protected static final String KEY_ERRORDATA = "errordata";
    /** JSON key error data signature. */
    protected static final String KEY_SIGNATURE = "signature";
    
    /**
     * <p>Construct a new header from the provided JSON object.</p>
     * 
     * <p>Headers are encrypted and signed. If a master token is found, it will
     * be used for this purpose. Otherwise the crypto context appropriate for
     * the entity authentication scheme will be used.</p>
     * 
     * <p>For message headers the master token or entity authentication data
     * must be found. For error headers the entity authentication data must be
     * found.</p>
     * 
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     * 
     * @param ctx MSL context.
     * @param headerJO header JSON object.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the header.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the message.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the header signature is invalid.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token or a token is improperly
     *         bound to another token.
     */
    public static Header parseHeader(final MslContext ctx, final JSONObject headerJO, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslMessageException, MslException {
        // Pull authentication data.
        final EntityAuthenticationData entityAuthData;
        final MasterToken masterToken;
        final byte[] signature;
        try {
            // Pull message data.
            entityAuthData = (headerJO.has(KEY_ENTITY_AUTHENTICATION_DATA))
                ? EntityAuthenticationData.create(ctx, headerJO.getJSONObject(KEY_ENTITY_AUTHENTICATION_DATA))
                : null;
            masterToken = (headerJO.has(KEY_MASTER_TOKEN))
                ? new MasterToken(ctx, headerJO.getJSONObject(KEY_MASTER_TOKEN))
                : null;
            try {
                signature = DatatypeConverter.parseBase64Binary(headerJO.getString(KEY_SIGNATURE));
            } catch (final IllegalArgumentException e) {
                throw new MslMessageException(MslError.HEADER_SIGNATURE_INVALID, "header/errormsg " + headerJO.toString());
            }
            if (signature == null)
                throw new MslMessageException(MslError.HEADER_SIGNATURE_INVALID, "header/errormsg " + headerJO.toString());
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header/errormsg " + headerJO.toString(), e);
        }

        try {
            // Process message headers.
            if (headerJO.has(KEY_HEADERDATA)) {
                final String headerdata = headerJO.getString(KEY_HEADERDATA);
                final MessageHeader messageHeader = new MessageHeader(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts);
                
                // Make sure the header was verified and decrypted.
                //
                // Throw different errors depending on whether or not a master
                // token was used.
                if (!messageHeader.isDecrypted()) {
                    if (masterToken != null)
                        throw new MslCryptoException(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED).setEntity(masterToken);
                    else
                        throw new MslCryptoException(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED).setEntity(entityAuthData);
                }
                
                // Return the header.
                return messageHeader;
            }
            
            // Process error headers.
            else if (headerJO.has(KEY_ERRORDATA)) {
                final String errordata = headerJO.getString(KEY_ERRORDATA);
                return new ErrorHeader(ctx, errordata, entityAuthData, signature);
            }
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header/errormsg " + headerJO.toString(), e);
        }
        
        // Unknown header.
        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, headerJO.toString());
    }
}
