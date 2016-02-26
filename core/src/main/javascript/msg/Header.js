/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
var Header$parseHeader;

(function() {
    /**
     * JSON key entity authentication data.
     * @const
     * @type {string}
     */
    var KEY_ENTITY_AUTHENTICATION_DATA = Header$KEY_ENTITY_AUTHENTICATION_DATA;
    /**
     * JSON key master token.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = Header$KEY_MASTER_TOKEN;
    /**
     * JSON key header data.
     * @const
     * @type {string}
     */
    var KEY_HEADERDATA = Header$KEY_HEADERDATA;
    /**
     * JSON key error data.
     * @const
     * @type {string}
     */
    var KEY_ERRORDATA = Header$KEY_ERRORDATA;
    /**
     * JSON key signature.
     * @const
     * @type {string}
     */
    var KEY_SIGNATURE = Header$KEY_SIGNATURE;

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
     * @param {MslContext} ctx MSL context.
     * @param {Object} headerJO header JSON object.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @param {{result: function(MessageHeader|ErrorHeader), error: function(Error)}}
     *        callback the callback functions that will receive the header or
     *        or any thrown exceptions.
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
    Header$parseHeader = function Header$parseHeader(ctx, headerJO, cryptoContexts, callback) {
        AsyncExecutor(callback, function() {
            // Pull message data.
            var entityAuthDataJo = headerJO[KEY_ENTITY_AUTHENTICATION_DATA];
            var masterTokenJo = headerJO[KEY_MASTER_TOKEN];
            var signatureB64 = headerJO[KEY_SIGNATURE];

            // Verify message data.
            if ((entityAuthDataJo && typeof entityAuthDataJo !== 'object') ||
                (masterTokenJo && typeof masterTokenJo !== 'object') ||
                typeof signatureB64 !== 'string')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header/errormsg " + JSON.stringify(headerJO));
            }
            // Reconstruct signature.
            var signature;
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslMessageException(MslError.HEADER_SIGNATURE_INVALID, "header/errormsg " + JSON.stringify(headerJO), e);
            }

            // Reconstruct entity authentication data.
            if (entityAuthDataJo) {
                EntityAuthenticationData$parse(ctx, entityAuthDataJo, {
                    result: function(entityAuthData) {
                        processHeaders(masterTokenJo, signature, entityAuthData);
                    },
                    error: callback.error,
                });
            } else {
                processHeaders(masterTokenJo, signature, null);
            }
        });
        
        function processHeaders(masterTokenJo, signature, entityAuthData) {
            AsyncExecutor(callback, function() {
                // Process message headers.
                var headerdata = headerJO[KEY_HEADERDATA];
                if (headerdata != undefined && headerdata != null) {
                    if (typeof headerdata !== 'string')
                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header/errormsg " + JSON.stringify(headerJO));
    
                    // Reconstruct master token.
                    if (masterTokenJo) {
                        MasterToken$parse(ctx, masterTokenJo, {
                            result: function(masterToken) {
                                MessageHeader$parse(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts, {
                                    result: function(messageHeader) {
                                        AsyncExecutor(callback, function() {
                                            // Make sure the header was verified and decrypted.
                                            if (!messageHeader.isDecrypted())
                                                throw new MslCryptoException(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED).setMasterToken(masterToken);
                                            
                                            // Return the header.
                                            return messageHeader;
                                        });
                                    },
                                    error: callback.error,
                                });
                            },
                            error: callback.error,
                        });
                        return;
                    } else {
                        MessageHeader$parse(ctx, headerdata, entityAuthData, null, signature, cryptoContexts, {
                            result: function(messageHeader) {
                                AsyncExecutor(callback, function() {
                                    // Make sure the header was verified and decrypted.
                                    if (!messageHeader.isDecrypted())
                                        throw new MslCryptoException(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
                                    
                                    // Return the header.
                                    return messageHeader;
                                });
                            },
                            error: callback.error,
                        });
                        return;
                    }
                }
    
                // Process error headers.
                var errordata = headerJO[KEY_ERRORDATA];
                if (errordata != undefined && errordata != null) {
                    if (typeof errordata !== 'string')
                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "header/errormsg " + JSON.stringify(headerJO));
                    ErrorHeader$parse(ctx, errordata, entityAuthData, signature, callback);
                    return;
                }
    
                // Unknown header.
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, JSON.stringify(headerJO));
            });
        }
    };
})();
