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
package com.netflix.msl.msg;

import java.util.Map;

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
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslObject;
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
 *   "headerdata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data (mutually exclusive with mastertoken)</li>
 * <li>{@code mastertoken} is the master token (mutually exclusive with entityauthdata)</li>
 * <li>{@code headerdata} is the encrypted header data (headerdata)</li>
 * <li>{@code signature} is the verification data of the header data</li>
 * </ul></p>
 * 
 * <p>An error header is represented as
 * {@code
 * errorheader = {
 *   "#mandatory" : [ "entityauthdata", "errordata", "signature" ],
 *   "entityauthdata" : entityauthdata,
 *   "errordata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code entityauthdata} is the entity authentication data</li>
 * <li>{@code errordata} is the encrypted error data (errordata)</li>
 * <li>{@code signature} is the verification data of the error data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class Header implements MslEncodable {
    /** Key entity authentication data. */
    public static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    /** Key master token. */
    public static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key header data. */
    public static final String KEY_HEADERDATA = "headerdata";
    /** Key error data. */
    public static final String KEY_ERRORDATA = "errordata";
    /** Key signature. */
    public static final String KEY_SIGNATURE = "signature";
    
    /**
     * <p>Construct a new header from the provided MSL object.</p>
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
     * @param headerMo header MSL object.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the header.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the message.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token or a token is improperly
     *         bound to another token.
     */
    public static Header parseHeader(final MslContext ctx, final MslObject headerMo, final Map<String,ICryptoContext> cryptoContexts) throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslUserAuthException, MslMessageException, MslException {
        // Pull authentication data.
        final EntityAuthenticationData entityAuthData;
        final MasterToken masterToken;
        final byte[] signature;
        try {
            // Pull message data.
            final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
            entityAuthData = (headerMo.has(Header.KEY_ENTITY_AUTHENTICATION_DATA))
                ? EntityAuthenticationData.create(ctx, headerMo.getMslObject(Header.KEY_ENTITY_AUTHENTICATION_DATA, encoder))
                : null;
            masterToken = (headerMo.has(Header.KEY_MASTER_TOKEN))
                ? new MasterToken(ctx, headerMo.getMslObject(Header.KEY_MASTER_TOKEN, encoder))
                : null;
            signature = headerMo.getBytes(Header.KEY_SIGNATURE);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "header/errormsg " + headerMo, e);
        }

        try {
            // Process message headers.
            if (headerMo.has(Header.KEY_HEADERDATA)) {
                final byte[] headerdata = headerMo.getBytes(Header.KEY_HEADERDATA);
                if (headerdata.length == 0)
                    throw new MslMessageException(MslError.HEADER_DATA_MISSING).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
                return new MessageHeader(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts);
            }
            
            // Process error headers.
            else if (headerMo.has(Header.KEY_ERRORDATA)) {
                final byte[] errordata = headerMo.getBytes(Header.KEY_ERRORDATA);
                if (errordata.length == 0)
                    throw new MslMessageException(MslError.HEADER_DATA_MISSING).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
                return new ErrorHeader(ctx, errordata, entityAuthData, signature);
            }
            
            // Unknown header.
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, headerMo.toString());
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "header/errormsg " + headerMo, e);
        }
    }
}
