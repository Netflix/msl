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
 * <p>The error data is represented as
 * {@code
 * errordata = {
 *   "#mandatory" : [ "messageid", "errorcode" ],
 *   "recipient" : "string",
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,-)",
 *   "errorcode" : "int32(0,-)",
 *   "internalcode" : "int32(0,-)",
 *   "errormsg" : "string",
 *   "usermsg" : "string",
 * }} where:
 * <ul>
 * <li>{@code recipient} is the intended recipient's entity identity</li>
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
var ErrorHeader;
var ErrorHeader$create;
var ErrorHeader$parse;

(function() {
    "use strict";
    
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;

    // Message error data.
    /**
     * JSON key recipient.
     * @const
     * @type {string}
     */
    var KEY_RECIPIENT = "recipient";
    /**
     * JSON key timestamp.
     * @const
     * @type {string}
     */
    var KEY_TIMESTAMP = "timestamp";
    /**
     * JSON key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * JSON key error code.
     * @const
     * @type {string}
     */
    var KEY_ERROR_CODE = "errorcode";
    /**
     * JSON key internal code.
     * @const
     * @type {string}
     */
    var KEY_INTERNAL_CODE = "internalcode";
    /**
     * JSON key error message.
     * @const
     * @type {string}
     */
    var KEY_ERROR_MESSAGE = "errormsg";
    /**
     * JSON key user message.
     * @const
     * @type {string}
     */
    var KEY_USER_MESSAGE = "usermsg";

    /**
     * Create a new error data container object.
     *
     * @param {Uint8Array} errordata raw error data.
     * @param {Uint8Array} signature raw signature.
     * @param {number} timestampSeconds creation timestamp in seconds since the epoch.
     * @constructor
     */
    function CreationData(errordata, signature, timestampSeconds) {
        this.errordata = errordata;
        this.signature = signature;
        this.timestampSeconds = timestampSeconds;
    }

    ErrorHeader = util.Class.create({
        /**
         * <p>Construct a new error header with the provided error data.</p>
         * 
         * <p>Headers are encrypted and signed using the crypto context appropriate
         * for the entity authentication scheme.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {EntityAuthenticationData} entityAuthData the entity authentication data.
         * @param {?string} recipient the intended recipient's entity identity. May be null.
         * @param {number} messageId the message ID.
         * @param {MslConstants$ResponseCode} errorCode the error code.
         * @param {number} internalCode the internal code. Negative to indicate no code.
         * @param {?string} errorMsg the error message. May be null.
         * @param {?string} userMsg the user message. May be null.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(ErrorHeader), error: function(Error)}}
         *        callback the callback functions that will receive the error
         *        header or any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the message.
         * @throws MslEntityAuthException if there is an error with the entity
         *         authentication data.
         * @throws MslMessageException if no entity authentication data is
         *         provided.
         */
        init: function init(ctx, entityAuthData, recipient, messageId, errorCode, internalCode, errorMsg, userMsg, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (internalCode < 0)
                    internalCode = -1;

                // Message ID must be within range.
                if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                    throw new MslInternalException("Message ID " + messageId + " is out of range.");

                // Message entity must be provided.
                if (!entityAuthData)
                    throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);
                
                // Only include the recipient if the message will be encrypted.
                var scheme = entityAuthData.scheme;
                var encrypted = scheme.encrypts;
                if (!encrypted) recipient = null;

                // Construct the error data.
                if (!creationData) {
                    var timestampSeconds = ctx.getTime() / MILLISECONDS_PER_SECOND;
                    
                    // Construct the JSON.
                    var errorJO = {};
                    if (recipient) errorJO[KEY_RECIPIENT] = recipient;
                    errorJO[KEY_TIMESTAMP] = timestampSeconds;
                    errorJO[KEY_MESSAGE_ID] = messageId;
                    errorJO[KEY_ERROR_CODE] = errorCode;
                    if (internalCode > 0) errorJO[KEY_INTERNAL_CODE] = internalCode;
                    if (errorMsg) errorJO[KEY_ERROR_MESSAGE] = errorMsg;
                    if (userMsg) errorJO[KEY_USER_MESSAGE] = userMsg;

                    // Create the crypto context.
                    var cryptoContext;
                    try {
                        var factory = ctx.getEntityAuthenticationFactory(entityAuthData.scheme);
                        cryptoContext = factory.getCryptoContext(ctx, entityAuthData);
                    } catch (e) {
                        if (e instanceof MslException) {
                            e.setEntityAuthenticationData(entityAuthData);
                            e.setMessageId(messageId);
                        }
                        throw e;
                    }

                    // Encrypt and sign the error data.
                    var plaintext = textEncoding$getBytes(JSON.stringify(errorJO), MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(errordata) {
                            AsyncExecutor(callback, function() {
                                cryptoContext.sign(errordata, {
                                    result: function(signature) {
                                        AsyncExecutor(callback, function() {
                                            // The properties.
                                            var props = {
                                                entityAuthenticationData: { value: entityAuthData, writable: false, configurable: false },
                                                recipient: { value: recipient, writable: false, configurable: false },
                                                timestampSeconds: { value: timestampSeconds, writable: false, enumerable: false, configurable: false },
                                                messageId: { value: messageId, writable: false, configurable: false },
                                                errorCode: { value: errorCode, writable: false, configurable: false },
                                                internalCode: { value: internalCode, writable: false, configurable: false },
                                                errorMessage: { value: errorMsg, writable: false, configurable: false },
                                                userMessage: { value: userMsg, writable: false, configurable: false },
                                                errordata: { value: errordata, writable: false, enumerable: false, configurable: false },
                                                signature: { value: signature, writable: false, enumerable: false, configurable: false }
                                            };
                                            Object.defineProperties(this, props);
                                            return this;
                                        }, self);
                                    },
                                    error: function(e) {
                                        AsyncExecutor(callback, function() {
                                            if (e instanceof MslException) {
                                                e.setEntityAuthenticationData(entityAuthData);
                                                e.setMessageId(messageId);
                                            }
                                            throw e;
                                        }, self);
                                    }
                                });
                            }, self);
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException) {
                                    e.setEntityAuthenticationData(entityAuthData);
                                    e.setMessageId(messageId);
                                }
                                throw e;
                            }, self);
                        }
                    });
                } else {
                    var timestampSeconds = creationData.timestampSeconds;
                    var errordata = creationData.errordata;
                    var signature = creationData.signature;

                    // The properties.
                    var props = {
                        entityAuthenticationData: { value: entityAuthData, writable: false, configurable: false },
                        recipient: { value: recipient, writable: false, configurable: false },
                        timestampSeconds: { value: timestampSeconds, writable: false, enumerable: false, configurable: false },
                        messageId: { value: messageId, writable: false, configurable: false },
                        errorCode: { value: errorCode, writable: false, configurable: false },
                        internalCode: { value: internalCode, writable: false, configurable: false },
                        errorMessage: { value: errorMsg, writable: false, configurable: false },
                        userMessage: { value: userMsg, writable: false, configurable: false },
                        errordata: { value: errordata, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false }
                    };
                    Object.defineProperties(this, props);
                    return this;
                };
            }, self);
        },

        /**
        * @return {Date} gets the timestamp.
        */
        get timestamp() {
            return new Date(this.timestampSeconds * MILLISECONDS_PER_SECOND);
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var jsonObj = {};
            jsonObj[Header$KEY_ENTITY_AUTHENTICATION_DATA] = this.entityAuthenticationData;
            jsonObj[Header$KEY_ERRORDATA] = base64$encode(this.errordata);
            jsonObj[Header$KEY_SIGNATURE] = base64$encode(this.signature);
            return jsonObj;
        },
    });

    /**
     * <p>Construct a new error header from the provided JSON object.</p>
     * 
     * <p>Headers are encrypted and signed using the crypto context appropriate
     * for the entity authentication scheme.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {EntityAuthenticationData} entityAuthData the entity authentication data.
     * @param {?string} recipient the intended recipient's entity identity. May be null.
     * @param {number} messageId the message ID.
     * @param {MslConstants$ResponseCode} errorCode the error code.
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
    ErrorHeader$create = function ErrorHeader$create(ctx, entityAuthData, recipient, messageId, errorCode, internalCode, errorMsg, userMsg, callback) {
        new ErrorHeader(ctx, entityAuthData, recipient, messageId, errorCode, internalCode, errorMsg, userMsg, null, callback);
    };

    /**
     * Construct a new error header from the provided JSON object.
     *
     * Headers are encrypted and signed using the crypto context appropriate
     * for the entity authentication scheme.
     *
     * @param {MslContext} ctx MSL context.
     * @param {string} errordata error data JSON representation.
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
    ErrorHeader$parse = function ErrorHeader$parse(ctx, errordata, entityAuthData, signature, callback) {
        AsyncExecutor(callback, function() {
            if (!entityAuthData)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

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
            try {
                errordata = base64$decode(errordata);
            } catch (e) {
                throw new MslMessageException(MslError.HEADER_DATA_INVALID, errordata, e).setEntityAuthenticationData(entityAuthData);
            }
            if (!errordata || errordata.length == 0)
                throw new MslMessageException(MslError.HEADER_DATA_MISSING, errordata).setEntityAuthenticationData(entityAuthData);
            cryptoContext.verify(errordata, signature, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (!verified)
                            throw new MslCryptoException(MslError.MESSAGE_VERIFICATION_FAILED).setEntityAuthenticationData(entityAuthData);
                        cryptoContext.decrypt(errordata, {
                            result: function(plaintext) {
                                AsyncExecutor(callback, function() {
                                    // Reconstruct error data.
                                    var errordataJson = textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET);
                                    var errordataJO;
                                    try {
                                        errordataJO = JSON.parse(errordataJson);
                                    } catch (e) {
                                        if (e instanceof SyntaxError)
                                            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJson, e).setEntityAuthenticationData(entityAuthData);
                                        throw e;
                                    }

                                    // Pull the error data.
                                    var recipient = (errordataJO[KEY_RECIPIENT] !== undefined) ? errordataJO[KEY_RECIPIENT] : null;
                                    var timestampSeconds = (errordataJO[KEY_TIMESTAMP] !== undefined) ? errordataJO[KEY_TIMESTAMP] : null;
                                    var messageId = parseInt(errordataJO[KEY_MESSAGE_ID]);
                                    var errorCode = parseInt(errordataJO[KEY_ERROR_CODE]);
                                    var internalCode = parseInt(errordataJO[KEY_INTERNAL_CODE]);
                                    var errorMsg = errordataJO[KEY_ERROR_MESSAGE];
                                    var userMsg = errordataJO[KEY_USER_MESSAGE];

                                    // Verify the error data.
                                    if ((recipient && typeof recipient !== 'string') ||
                                        (timestampSeconds && typeof timestampSeconds !== 'number') ||
                                        !messageId || messageId != messageId ||
                                        !errorCode || errorCode != errorCode ||
                                        (errordataJO[KEY_INTERNAL_CODE] && internalCode != internalCode) ||
                                        (errorMsg && typeof errorMsg !== 'string') ||
                                        (userMsg && typeof userMsg !== 'string'))
                                    {
                                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "errordata " + errordataJson).setEntityAuthenticationData(entityAuthData);
                                    }

                                    // The message ID must be within range.
                                    if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                                        throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "errordata " + errordataJson).setEntityAuthenticationData(entityAuthData);

                                    // If we do not recognize the error code then default to fail.
                                    var recognized = false;
                                    for (var code in MslConstants$ResponseCode) {
                                        if (MslConstants$ResponseCode[code] == errorCode) {
                                            recognized = true;
                                            break;
                                        }
                                    }
                                    if (!recognized)
                                        errorCode = MslConstants$ResponseCode.FAIL;

                                    // The parsed internal code cannot be negative.
                                    if (internalCode) {
                                        if (internalCode < 0)
                                            throw new MslMessageException(MslError.INTERNAL_CODE_NEGATIVE, "errordata " + errordataJson).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
                                    } else {
                                        internalCode = -1;
                                    }

                                    // Return the error header.
                                    var creationData = new CreationData(errordata, signature, timestampSeconds);
                                    new ErrorHeader(ctx, entityAuthData, recipient, messageId, errorCode, internalCode, errorMsg, userMsg, creationData, callback);
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
})();
