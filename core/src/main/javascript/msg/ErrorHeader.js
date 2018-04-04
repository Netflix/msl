/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
 * <p>The error data is represented as
 * {@code
 * errordata = {
 *   "#mandatory" : [ "messageid", "errorcode" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,-)",
 *   "errorcode" : "int32(0,-)",
 *   "internalcode" : "int32(0,-)",
 *   "errormsg" : "string",
 *   "usermsg" : "string",
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code errorcode} is the error code</li>
 * <li>{@code internalcode} is an service-specific error code</li>
 * <li>{@code errormsg} is a developer-consumable error message</li>
 * <li>{@code usermsg} is a user-consumable localized error message</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var MslConstants = require('../MslConstants.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslError = require('../MslError.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEntityAuthException = require('../MslEntityAuthException.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var Header = require('../msg/Header.js');
	var MslException = require('../MslException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var Base64 = require('../util/Base64.js');
    
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;

    // Message error data.
    /**
     * Key timestamp.
     * @const
     * @type {string}
     */
    var KEY_TIMESTAMP = "timestamp";
    /**
     * Key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * Key error code.
     * @const
     * @type {string}
     */
    var KEY_ERROR_CODE = "errorcode";
    /**
     * Key internal code.
     * @const
     * @type {string}
     */
    var KEY_INTERNAL_CODE = "internalcode";
    /**
     * Key error message.
     * @const
     * @type {string}
     */
    var KEY_ERROR_MESSAGE = "errormsg";
    /**
     * Key user message.
     * @const
     * @type {string}
     */
    var KEY_USER_MESSAGE = "usermsg";

    /**
     * Create a new error data container object.
     *
     * @param {Uint8Array} errordata raw error data.
     * @param {number} timestampSeconds creation timestamp in seconds since the epoch.
     * @constructor
     */
    function CreationData(errordata, timestampSeconds) {
        this.errordata = errordata;
        this.timestampSeconds = timestampSeconds;
    }

    var ErrorHeader = module.exports = Class.create({
        /**
         * <p>Construct a new error header with the provided error data.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {EntityAuthenticationData} entityAuthData the entity authentication data.
         * @param {number} messageId the message ID.
         * @param {MslConstants.ResponseCode} errorCode the error code.
         * @param {number} internalCode the internal code. Negative to indicate no code.
         * @param {?string} errorMsg the error message. May be null.
         * @param {?string} userMsg the user message. May be null.
         * @param {?CreationData} creationData optional creation data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the message.
         * @throws MslEntityAuthException if there is an error with the entity
         *         authentication data.
         * @throws MslMessageException if no entity authentication data is
         *         provided.
         */
        init: function init(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMsg, creationData) {
            if (internalCode < 0)
                internalCode = -1;

            // Message ID must be within range.
            if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                throw new MslInternalException("Message ID " + messageId + " is out of range.");

            // Message entity must be provided.
            if (!entityAuthData)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

            // Construct the error data.
            var timestampSeconds, errordata;
            if (!creationData) {
                timestampSeconds = parseInt(ctx.getTime() / MILLISECONDS_PER_SECOND);

                // Construct the error data.
                var encoder = ctx.getMslEncoderFactory();
                errordata = encoder.createObject();
                errordata.put(KEY_TIMESTAMP, timestampSeconds);
                errordata.put(KEY_MESSAGE_ID, messageId);
                errordata.put(KEY_ERROR_CODE, errorCode);
                if (internalCode > 0) errordata.put(KEY_INTERNAL_CODE, internalCode);
                if (errorMsg) errordata.put(KEY_ERROR_MESSAGE, errorMsg);
                if (userMsg) errordata.put(KEY_USER_MESSAGE, userMsg);
            } else {
                timestampSeconds = creationData.timestampSeconds;
                errordata = creationData.errordata;
            }

            // The properties.
            var props = {
                /**
                 * MSL context.
                 * @type {MslContext}
                 */
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                /**
                 * Entity authentication data.
                 * @type {EntityAuthenticationData}
                 */
                entityAuthenticationData: { value: entityAuthData, writable: false, configurable: false },
                /**
                 * Timestamp in seconds since the epoch.
                 * @type {?number}
                 */
                timestampSeconds: { value: timestampSeconds, writable: false, enumerable: false, configurable: false },
                /**
                 * Message ID.
                 * @type {number}
                 */
                messageId: { value: messageId, writable: false, configurable: false },
                /**
                 * Error code.
                 * @type {MslConstants.ResponseCode}
                 */
                errorCode: { value: errorCode, writable: false, configurable: false },
                /**
                 * Internal code.
                 * @type {number}
                 */
                internalCode: { value: internalCode, writable: false, configurable: false },
                /**
                 * Error message.
                 * @type {?string}
                 */
                errorMessage: { value: errorMsg, writable: false, configurable: false },
                /**
                 * User message.
                 * @type {?string}
                 */
                userMessage: { value: userMsg, writable: false, configurable: false },
                /**
                 * Error data.
                 * @type {MslObject}
                 */
                errordata: { value: errordata, writable: false, enumerable: false, configurable: false },
                /**
                 * Cached encodings.
                 * @type {Object<MslEncoderFormat,Uint8Array>}
                 */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
        * @return {Date} gets the timestamp. May be null.
        */
        get timestamp() {
            if (this.timestampSeconds !== null)
                return new Date(this.timestampSeconds * MILLISECONDS_PER_SECOND);
            return null;
        },
        
        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // Create the crypto context.
                var scheme = this.entityAuthenticationData.scheme;
                var factory = this.ctx.getEntityAuthenticationFactory(scheme);
                if (!factory)
                    throw new MslEncoderException("No entity authentication factory found for entity.");
                var cryptoContext;
                try {
                    cryptoContext = factory.getCryptoContext(this.ctx, this.entityAuthenticationData);
                } catch (e) {
                    if (e instanceof MslEntityAuthException || e instanceof MslCryptoException)
                        throw new MslEncoderException("Error creating the entity crypto context.", e);
                    throw e;
                }
                
                // Encrypt and sign the error data.
                encoder.encodeObject(this.errordata, format, {
                	result: function(plaintext) {
		                cryptoContext.encrypt(plaintext, encoder, format, {
		                    result: function(ciphertext) {
		                        cryptoContext.sign(ciphertext, encoder, format, {
		                            result: function(signature) {
		                                AsyncExecutor(callback, function() {
		                                    // Create the encoding.
		                                    var header = encoder.createObject();
		                                    header.put(Header.KEY_ENTITY_AUTHENTICATION_DATA, this.entityAuthenticationData);
		                                    header.put(Header.KEY_ERRORDATA, ciphertext);
		                                    header.put(Header.KEY_SIGNATURE, signature);
		                                    encoder.encodeObject(header, format, {
		                                    	result: function(encoding) {
		                                    		AsyncExecutor(callback, function() {
		                                    			// Cache and return the encoding.
		                                    			this.encodings[format] = encoding;
		                                    			return encoding;
		                                    		}, self);
		                                    	},
		                                    	error: callback.error,
		                                    });
		                                }, self);
		                            },
		                            error: function(e) {
		                                if (e instanceof MslCryptoException)
		                                    e = new MslEncoderException("Error signing the error data.", e);
		                                callback.error(e);
		                            }
		                        });
		                    },
		                    error: function(e) {
		                        if (e instanceof MslCryptoException)
		                            e = new MslEncoderException("Error signing the error data.", e);
		                        callback.error(e);
		                    }
		                });
                	},
                	error: callback.error,
                });
            }, self);
        },
    });

    /**
     * <p>Construct a new error header with the provided error data.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {EntityAuthenticationData} entityAuthData the entity authentication data.
     * @param {number} messageId the message ID.
     * @param {MslConstants.ResponseCode} errorCode the error code.
     * @param {number} internalCode the internal code. Negative to indicate no code.
     * @param {?string} errorMsg the error message. May be null.
     * @param {?string} userMsg the user message. May be null.
     * @param {{result: function(ErrorHeader), error: function(Error)}}
     *        callback the callback functions that will receive the error
     *        header or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    var ErrorHeader$create = function ErrorHeader$create(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMsg, callback) {
        AsyncExecutor(callback, function() {
            return new ErrorHeader(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMsg, null);
        });
    };

    /**
     * <p>Construct a new error header from the provided MSL object.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {Uint8Array} errordataBytes error data MSL encoding.
     * @param {EntityAuthenticationData} entityAuthData the entity authentication data.
     * @param {Uint8Array} signature the header signature.
     * @param {{result: function(ErrorHeader), error: function(Error)}}
     *        callback the callback functions that will receive the error
     *        header or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header.
     * @throws MslEntityAuthException if the entity authentication data is not
     *         supported or erroneous.
     * @throws MslMessageException if there is no entity authentication data
     *         (null) or the error data is missing or the message ID is
     *         negative or the internal code is negative.
     */
    var ErrorHeader$parse = function ErrorHeader$parse(ctx, errordataBytes, entityAuthData, signature, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            // Validate the entity authentication data.
            if (!entityAuthData)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

            // Grab the entity crypto context.
            var cryptoContext;
            try {
                var scheme = entityAuthData.scheme;
                var factory = ctx.getEntityAuthenticationFactory(scheme);
                if (!factory)
                    throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme);
                cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
            } catch (e) {
                if (e instanceof MslException)
                    e.setEntityAuthenticationData(entityAuthData);
                throw e;
            }
            
            // Verify and decrypt the error data.
            cryptoContext.verify(errordataBytes, signature, encoder, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (!verified)
                            throw new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
                        cryptoContext.decrypt(errordataBytes, encoder, {
                            result: function(plaintext) {
                                AsyncExecutor(callback, function() {
                                    var errordata, messageId;
                                    try {
                                        errordata = encoder.parseObject(plaintext);
                                        messageId = errordata.getLong(KEY_MESSAGE_ID);
                                        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                                            throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordata).setEntityAuthenticationData(entityAuthData);
                                    } catch (e) {
                                        if (e instanceof MslEncoderException)
                                            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "errordata " + Base64.encode(plaintext), e).setEntityAuthenticationData(entityAuthData);
                                        throw e;
                                    }
                                    
                                    var timestampSeconds, errorCode, internalCode, errorMsg, userMsg;
                                    try {
                                        timestampSeconds = (errordata.has(KEY_TIMESTAMP)) ? errordata.getLong(KEY_TIMESTAMP) : null;
                                        
                                        // If we do not recognize the error code then default to fail.
                                        errorCode = errordata.getInt(KEY_ERROR_CODE);
                                        var recognized = false;
                                        for (var code in MslConstants.ResponseCode) {
                                            if (MslConstants.ResponseCode[code] == errorCode) {
                                                recognized = true;
                                                break;
                                            }
                                        }
                                        if (!recognized)
                                            errorCode = MslConstants.ResponseCode.FAIL;
                                        
                                        if (errordata.has(KEY_INTERNAL_CODE)) {
                                            internalCode = errordata.getInt(KEY_INTERNAL_CODE);
                                            if (internalCode < 0)
                                                throw new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, "errordata " + errordata).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
                                        } else {
                                            internalCode = -1;
                                        }
                                        errorMsg = errordata.optString(KEY_ERROR_MESSAGE, null);
                                        userMsg = errordata.optString(KEY_USER_MESSAGE, null);
                                    } catch (e) {
                                        if (e instanceof MslEncoderException)
                                            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "errordata " + errordata, e).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
                                        throw e;
                                    }

                                    // Return the error header.
                                    var creationData = new CreationData(errordata, timestampSeconds);
                                    return new ErrorHeader(ctx, entityAuthData, messageId, errorCode, internalCode, errorMsg, userMsg, creationData);
                                });
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setEntityAuthenticationData(entityAuthData);
                                    throw e;
                                });
                            }
                        });
                    });
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        if (e instanceof MslException)
                            e.setEntityAuthenticationData(entityAuthData);
                        throw e;
                    });
                }
            });
        });
    };
    
    // Exports.
    module.exports.create = ErrorHeader$create;
    module.exports.parse = ErrorHeader$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('ErrorHeader'));
