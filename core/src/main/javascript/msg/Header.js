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
(function(require, module) {
	"use strict";
	
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslError = require('../MslError.js');
	
	// Cyclic dependency declarations.
	var MessageHeader,
	    ErrorHeader;
	
	/**
	 * Common header keys.
	 * @const
	 * @type {string}
	 */
	var Header$KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
	/**
	 * Key master token.
	 * @const
	 * @type {string}
	 */
	var Header$KEY_MASTER_TOKEN = "mastertoken";
	/**
	 * Key header data.
	 * @const
	 * @type {string}
	 */
	var Header$KEY_HEADERDATA = "headerdata";
	/**
	 * Key error data.
	 * @const
	 * @type {string}
	 */
	var Header$KEY_ERRORDATA = "errordata";
	/**
	 * Key signature.
	 * @const
	 * @type {string}
	 */
	var Header$KEY_SIGNATURE = "signature";
	
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
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} headerMo header MSL object.
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
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token or a token is improperly
     *         bound to another token.
     */
    var Header$parseHeader = function Header$parseHeader(ctx, headerMo, cryptoContexts, callback) {
        AsyncExecutor(callback, function() {
            // Pull authentication data.
            var entityAuthDataMo;
            var masterTokenMo;
            var signature;
            try {
                // Pull message data.
                var encoder = ctx.getMslEncoderFactory();
                entityAuthDataMo = (headerMo.has(Header$KEY_ENTITY_AUTHENTICATION_DATA))
                    ? headerMo.getMslObject(Header$KEY_ENTITY_AUTHENTICATION_DATA, encoder)
                    : null;
                masterTokenMo = (headerMo.has(Header$KEY_MASTER_TOKEN))
                    ? headerMo.getMslObject(Header$KEY_MASTER_TOKEN, encoder)
                    : null;
                signature = headerMo.getBytes(Header$KEY_SIGNATURE);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "header/errormsg " + headerMo, e);
                throw e;
            }
            
            // Reconstruct entity authentication data.
            if (entityAuthDataMo) {
                EntityAuthenticationData.parse(ctx, entityAuthDataMo, {
                    result: function(entityAuthData) {
                        reconstructMasterToken(entityAuthData, masterTokenMo, signature);
                    },
                    error: callback.error,
                });
            } else {
                reconstructMasterToken(null, masterTokenMo, signature);
            }
        });
        
        function reconstructMasterToken(entityAuthData, masterTokenMo, signature) {
            if (masterTokenMo) {
                MasterToken.parse(ctx, masterTokenMo, {
                    result: function(masterToken) {
                        processHeaders(entityAuthData, masterToken, signature);
                    },
                    error: callback.error,
                });
            } else {
                processHeaders(entityAuthData, null, signature);
            }
        }
        
        function processHeaders(entityAuthData, masterToken, signature) {
            AsyncExecutor(callback, function() {
                if (!MessageHeader) MessageHeader = require('../msg/MessageHeader.js');
                if (!ErrorHeader) ErrorHeader = require('../msg/ErrorHeader.js');
                
                try {
                    // Process message headers.
                    if (headerMo.has(Header$KEY_HEADERDATA)) {
                        var headerdata = headerMo.getBytes(Header$KEY_HEADERDATA);
                        if (headerdata.length == 0)
                            throw new MslMessageException(MslError.HEADER_DATA_MISSING).setMasterToken(masterToken).setEntityAuthenicationData(entityAuthData);
                        MessageHeader.parse(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts, callback);
                    }
                    
                    // Process error headers.
                    else if (headerMo.has(Header$KEY_ERRORDATA)) {
                        var errordata = headerMo.getBytes(Header$KEY_ERRORDATA);
                        if (errordata.length == 0)
                            throw new MslMessageException(MslError.HEADER_DATA_MISSING).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
                        ErrorHeader.parse(ctx, errordata, entityAuthData, signature, callback);
                    }
                    
                    // Unknown header.
                    else {
                    	throw new MslEncodingException(MslError.MSL_PARSE_ERROR, headerMo);
                    }
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "header/errormsg " + headerMo, e);
                    throw e;
                }
            });
        }
    };
    
    // Exports.
    module.exports.KEY_ENTITY_AUTHENTICATION_DATA = Header$KEY_ENTITY_AUTHENTICATION_DATA;
    module.exports.KEY_MASTER_TOKEN = Header$KEY_MASTER_TOKEN;
    module.exports.KEY_HEADERDATA = Header$KEY_HEADERDATA;
    module.exports.KEY_ERRORDATA = Header$KEY_ERRORDATA;
    module.exports.KEY_SIGNATURE = Header$KEY_SIGNATURE;
    module.exports.parseHeader = Header$parseHeader;
})(require, (typeof module !== 'undefined') ? module : mkmodule('Header'));
