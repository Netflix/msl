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
 * <p>A MSL message consists of a single MSL header followed by one or more
 * payload chunks carrying application data. Each payload chunk is individually
 * packaged but sequentially ordered. No payload chunks may be included in an
 * error message.</p>
 *
 * <p>Data is read until an end-of-message payload chunk is encountered or an
 * error occurs. Closing a {@code MessageInputStream} does not close the source
 * input stream in case additional MSL messages will be read.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');
	var MslKeyExchangeException = require('../MslKeyExchangeException.js');
	var MslError = require('../MslError.js');
	var InterruptibleExecutor = require('../util/InterruptibleExecutor.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var InputStream = require('../io/InputStream.js');
	var Header = require('../msg/Header.js');
	var ErrorHeader = require('../msg/ErrorHeader.js');
	var BlockingQueue = require('../util/BlockingQueue.js');
	var MslException = require('../MslException.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslMasterTokenException = require('../MslMasterTokenException.js');
	var MslUserIdTokenException = require('../MslUserIdTokenException.js');
	var MslInternalException = require('../MslInternalException.js');
	var PayloadChunk = require('../msg/PayloadChunk.js');
	var MslIoException = require('../MslIoException.js');
	var MessageHeader = require('../msg/MessageHeader.js');

    /**
     * <p>Return the crypto context resulting from key response data contained
     * in the provided header.</p>
     *
     * <p>The {@link MslException}s thrown by this method will not have the
     * entity or user set.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {MessageHeader} header header.
     * @param {Array.<KeyRequestData>} keyRequestData key request data for key exchange.
     * @param {{result: function(ICryptoContext), error: function(Error)}}
     *        callback the callback that will receive the crypto context, which
     *        may be null if the header does not contain key response data or
     *        is an error message, or any thrown exceptions.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity.
     */
    function getKeyxCryptoContext(ctx, header, keyRequestData, callback) {
        AsyncExecutor(callback, function() {
            // Pull the header data.
            var messageHeader = header;
            var masterToken = messageHeader.masterToken;
            var keyResponse = messageHeader.keyResponseData;

            // If there is no key response data then return null.
            if (!keyResponse)
                return null;

            // If the key response data master token is decrypted then use the
            // master token keys to create the crypto context.
            var keyxMasterToken = keyResponse.masterToken;
            if (keyxMasterToken.isDecrypted())
                return new SessionCryptoContext(ctx, keyxMasterToken);

            // Perform the key exchange.
            var responseScheme = keyResponse.keyExchangeScheme;
            var factory = ctx.getKeyExchangeFactory(responseScheme);
            if (!factory)
                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, responseScheme);

            // Attempt the key exchange but if it fails then try with the next
            // key request data before giving up.
            var keyxException;
            var requestIndex = 0;
            function nextExchange() {
                AsyncExecutor(callback, function() {
                    // If we've reached the end of the requests then stop.
                    if (requestIndex >= keyRequestData.length) {
                        // We did not perform a successful key exchange. If we caught an
                        // exception then throw that exception now.
                        if (keyxException)
                            throw keyxException;

                        // If we didn't find any then we're unable to perform key
                        // exchange.
                        throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, keyRequestData);
                    }

                    // Grab this iteration's request.
                    var keyRequest = keyRequestData[requestIndex];
                    if (responseScheme != keyRequest.keyExchangeScheme) {
                        // Try the next request.
                        ++requestIndex;
                        nextExchange();
                        return;
                    }

                    // Attempt the key exchange.
                    factory.getCryptoContext(ctx, keyRequest, keyResponse, masterToken, {
                        result: callback.result,
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                // Immediately deliver anything that's not a
                                // MslException.
                                if (!(e instanceof MslException))
                                    throw e;

                                // Otherwise save this exception and try the next
                                // combination.
                                keyxException = e;
                                ++requestIndex;
                                nextExchange();
                            });
                        }
                    });
                });
            }

            nextExchange();
        });
    }

    var MessageInputStream = module.exports = InputStream.extend({
        /**
         * <p>Construct a new message input stream. The header is parsed.</p>
         *
         * <p>If key request data is provided and a matching key response data is
         * found in the message header the key exchange will be performed to
         * process the message payloads.</p>
         *
         * <p>Service tokens will be decrypted and verified with the provided crypto
         * contexts identified by token name. A default crypto context may be
         * provided by using the empty string as the token name; if a token name is
         * not explcitly mapped onto a crypto context, the default crypto context
         * will be used.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {InputStream} source MSL input stream.
         * @param {Array.<KeyRequestData>} keyRequestData key request data to use when processing key
         *        response data.
         * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
         *        contexts used to decrypt and verify service tokens.
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the message input
         *        stream, or any thrown exceptions.
         * @throws IOException if there is a problem reading from the input stream.
         * @throws MslEncodingException if there is an error parsing the message.
         * @throws MslCryptoException if there is an error decrypting or verifying
         *         the header or creating the message payload crypto context.
         * @throws MslEntityAuthException if unable to create the entity
         *         authentication data.
         * @throws MslUserAuthException if unable to create the user authentication
         *         data.
         * @throws MslMessageException if the message master token is expired and
         *         the message is not renewable.
         * @throws MslMasterTokenException if the master token is not trusted and
         *         needs to be or if it has been revoked.
         * @throws MslUserIdTokenException if the user ID token has been revoked.
         * @throws MslKeyExchangeException if there is an error with the key
         *         request data or key response data or the key exchange scheme is
         *         not supported.
         * @throws MslMessageException if the message does not contain an entity
         *         authentication data or a master token, the header data is
         *         missing or invalid, or the message ID is negative, or the
         *         message is not encrypted and contains user authentication data,
         *         or if the message master token is expired and the message is not
         *         renewable.
         * @throws MslException if the message does not contain an entity
         *         authentication data or a master token, or a token is improperly
         *         bound to another token.
         */
        init: function init(ctx, source, keyRequestData, cryptoContexts, timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                var encoder = ctx.getMslEncoderFactory();
                encoder.createTokenizer(source, null, timeout, {
                    result: setProperties,
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
            
            function setProperties(tokenizer) {
                InterruptibleExecutor(callback, function() {
                    // Set properties.
                    var props = {
                        _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                        _source: { value: source, writable: false, enumerable: false, configurable: false },
                        _tokenizer: { value: tokenizer, writable: false, enumerable: false, configurable: false },
                        _header: { value: undefined, writable: true, enumerable: false, configurable: false },
                        _cryptoContext: { value: undefined, writable: true, enumerable: false, configurable: false },
                        _keyxCryptoContext: { value: undefined, writable: true, enumerable: false, configurable: false },
                        _payloadSequenceNumber: { value: 1, writable: true, enuemrable: false, configurable: false },
                        _eom: { value: false, writable: true, enumerable: false, configurable: false },
                        _handshake: { value: null, writable: true, enumerable: false, configurable: false },
                        _closeSource: { value: false, writable: true, enumerable: false, configurable: false },
                        /**
                         * True if buffering.
                         * 
                         * @type {boolean}
                         */
                        _buffering: { value: false, writable: true, enumerable: false, configurable: false },
                        /**
                         * Buffered payload data.
                         * 
                         * @type {Array.<Uint8Array>}
                         */
                        _payloads: { value: [], writable: true, enumerable: false, configurable: false },
                        _payloadIndex: { value: -1, writable: true, enumerable: false, configurable: false },
                        _payloadOffset: { value: 0, writable: true, enuemrable: false, configurable: false },
                        /**
                         * First payload byte offset when {@link #mark(int)}
                         * was called.
                         * 
                         * @type {number}
                         */
                        _markOffset: { value: 0, writable: true, enumerable: false, configurable: false },
                        /**
                         * Mark read limit. -1 for no limit.
                         * 
                         * @type {number}
                         */
                        _readlimit: { value: 0, writable: true, enumerable: false, configurable: false },
                        /**
                         * Mark read count.
                         * 
                         * @type {number}
                         */
                        _readcount: { value: 0, writable: true, enumerable: false, configurable: false },
                        _currentPayload: { value: null, writable: true, enumerable: false, configurable: false },
                        _readException: { value: null, writable: true, enumerable: false, configurable: false },
                        // Set true once the header has been read and payloads may
                        // be read.
                        _ready: { value: false, writable: true, enumerable: false, configurable: false },
                        // Use a blocking queue as a semaphore.
                        _readyQueue: { value: new BlockingQueue(), writable: false, enumerable: false, configurable: false },
                        _aborted: { value: false, writable: true, enumerable: false, configurable: false },
                        // If timed out reading the header then deliver the timeout
                        // at the next operation.
                        _timedout: { value: false, writable: true, enumerable: false, configurable: false },
                        // If an error occurs while reading the header then deliver
                        // it at the next operation.
                        _errored: { value: null, writable: true, enumerable: false, configurable: false },
                    };
                    Object.defineProperties(this, props);

                    this._tokenizer.more(-1, {
                        result: function(available) {
                            if (!available) {
                                self._errored = new MslEncodingException(MslError.MESSAGE_DATA_MISSING);
                                ready();
                                return;
                            }
                            parseHeader();
                        },
                        timeout: function() {
                            self._timedout = true;
                            ready();
                        },
                        error: function(e) {
                            if (e instanceof MslEncoderException)
                                e = new MslEncodingException(MslError.MSL_PARSE_ERROR, "header", e);
                            self._errored = e;
                            ready();
                        }
                    });

                    // Return this immediately instead of after reading the header
                    // so the read can be aborted.
                    return this;
                }, self);
            }

            function ready() {
                self._ready = true;
                self._readyQueue.add(true);
            }
            
            function parseHeader() {
                self._tokenizer.nextObject(-1, {
                    result: function(mo) {
                        Header.parseHeader(ctx, mo, cryptoContexts, {
                            result: processHeader,
                            error: function(e) {
                                self._errored = e;
                                ready();
                            }
                        });
                    },
        			timeout: function() {
        				self._timedout = true;
        				ready();
        			},
                    error: function(e) {
                        if (e instanceof MslEncoderException)
                            e = new MslEncodingException(MslError.MSL_PARSE_ERROR, "header", e);
                        self._errored = e;
                        ready();
                    }
                });
            }
                
            function processHeader(header) {
                self._header = header;

                // For error messages there are no key exchange or payload crypto
                // contexts.
                if (self._header instanceof ErrorHeader) {
                    self._keyxCryptoContext = null;
                    self._cryptoContext = null;
                    ready();
                    return;
                }

                // Grab the key exchange crypto context, if any.
                var messageHeader = self._header;
                getKeyxCryptoContext(ctx, messageHeader, keyRequestData, {
                    result: function(keyxCryptoContext) {
                        setCryptoContexts(ctx, messageHeader, keyxCryptoContext);
                    },
                    error: function(e) {
                        if (e instanceof MslException) {
                            e.setMasterToken(messageHeader.masterToken);
                            e.setEntityAuthenticationData(messageHeader.entityAuthenticationData);
                            e.setUserIdToken(messageHeader.userIdToken);
                            e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                            e.setMessageId(messageHeader.messageId);
                        }
                        self._errored = e;
                        ready();
                    }
                });
            }

            function setCryptoContexts(ctx, messageHeader, keyxCryptoContext) {
                try {
                    self._keyxCryptoContext = keyxCryptoContext;

                    // In peer-to-peer mode or in trusted network mode with no key
                    // exchange the payload crypto context equals the header crypto
                    // context.
                    if (ctx.isPeerToPeer() || !self._keyxCryptoContext)
                        self._cryptoContext = messageHeader.cryptoContext;

                    // Otherwise the payload crypto context equals the key exchange
                    // crypto context.
                    else
                        self._cryptoContext = self._keyxCryptoContext;

                    checkHandshakeProperties(ctx, messageHeader);
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setEntityAuthenticationData(messageHeader.entityAuthenticationData);
                        e.setUserIdToken(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkHandshakeProperties(ctx, messageHeader) {
                try {
                    // If this is a handshake message but it is not renewable or does
                    // not contain key request data then reject the message.
                    if (messageHeader.isHandshake() &&
                        (!messageHeader.isRenewable() || messageHeader.keyRequestData.length == 0))
                    {
                        throw new MslMessageException(MslError.HANDSHAKE_DATA_MISSING, messageHeader);
                    }

                    checkMasterToken(ctx, messageHeader);
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setEntityAuthenticationData(messageHeader.entityAuthenticationData);
                        e.setUserIdToken(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkMasterToken(ctx, messageHeader) {
                try {
                    // If I am in peer-to-peer mode or the master token is verified
                    // (i.e. issued by the local entity which is therefore a trusted
                    // network server) then perform the master token checks.
                    var masterToken = messageHeader.masterToken;
                    if (masterToken && (ctx.isPeerToPeer() || masterToken.isVerified())) {
                        checkMasterTokenRevoked(ctx, messageHeader);
                    } else {
                        checkNonReplayableId(ctx, messageHeader);
                    }
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setEntityAuthenticationData(messageHeader.userIdToken);
                        e.setUserIdToken(messageHeader.userAuthenticationData);
                        e.setUserAuthenticationData(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkMasterTokenRevoked(ctx, messageHeader) {
                try {
                    // If the master token has been revoked then reject the
                    // message.
                    var masterToken = messageHeader.masterToken;
                    var factory = ctx.getTokenFactory();
                    factory.isMasterTokenRevoked(ctx, masterToken, {
                        result: function(revoked) {
                            if (revoked) {
                                self._errored = new MslMasterTokenException(revoked, masterToken)
                                .setUserIdToken(messageHeader.userIdToken)
                                .setUserAuthenticationData(messageHeader.userAuthenticationData)
                                .setMessageId(messageHeader.messageId);
                                ready();
                            } else {
                                checkUserIdTokenRevoked(ctx, messageHeader);
                            }
                        },
                        error: function(e) {
                            if (e instanceof MslException) {
                                e.setMasterToken(messageHeader.masterToken);
                                e.setUserIdToken(messageHeader.userIdToken);
                                e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                                e.setMessageId(messageHeader.messageId);
                            }
                            self._errored = e;
                            ready();
                        }
                    });
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setUserIdToken(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkUserIdTokenRevoked(ctx, messageHeader) {
                try {
                    // If the user ID token has been revoked then reject the
                    // message. We know the master token is not null and that it is
                    // verified so we assume the user ID token is as well.
                    var masterToken = messageHeader.masterToken;
                    var userIdToken = messageHeader.userIdToken;
                    if (userIdToken) {
                        var factory = ctx.getTokenFactory();
                        factory.isUserIdTokenRevoked(ctx, masterToken, userIdToken, {
                            result: function(revoked) {
                                if (revoked) {
                                    self._errored = new MslUserIdTokenException(revoked, userIdToken)
                                    .setMasterToken(masterToken)
                                    .setUserIdToken(userIdToken)
                                    .setMessageId(messageHeader.messageId);
                                    ready();
                                } else {
                                    checkMasterTokenExpired(ctx, messageHeader);
                                }
                            },
                            error: function(e) {
                                if (e instanceof MslException) {
                                    e.setMasterToken(messageHeader.masterToken);
                                    e.setUserIdToken(messageHeader.userIdToken);
                                    e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                                    e.setMessageId(messageHeader.messageId);
                                }
                                self._errored = e;
                                ready();
                            }
                        });
                    } else {
                        checkMasterTokenExpired(ctx, messageHeader);
                    }
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setUserIdToken(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkMasterTokenExpired(ctx, messageHeader) {
                try {
                    // If the master token is expired...
                    var masterToken = messageHeader.masterToken;
                    if (masterToken.isExpired(null)) {
                        // If the message is not renewable or does not contain key
                        // request data then reject the message.
                        if (!messageHeader.isRenewable()) {
                            self._errored = new MslMessageException(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE, messageHeader)
                            .setMasterToken(masterToken)
                            .setUserIdToken(messageHeader.userIdToken)
                            .setUserAuthenticationData(messageHeader.userAuthenticationData)
                            .setMessageId(messageHeader.messageId);
                            ready();
                            return;
                        }
                        else if (messageHeader.keyRequestData.length == 0) {
                            self._errored = new MslMessageException(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA, messageHeader)
                            .setMasterToken(masterToken)
                            .setUserIdToken(messageHeader.userIdToken)
                            .setUserAuthenticationData(messageHeader.userAuthenticationData)
                            .setMessageId(messageHeader.messageId);
                            ready();
                            return;
                        }

                        // If the master token will not be renewed by the token
                        // factory then reject the message.
                        //
                        // This throws an exception if the master token is not
                        // renewable.
                        var factory = ctx.getTokenFactory();
                        factory.isMasterTokenRenewable(ctx, masterToken, {
                            result: function(notRenewable) {
                                if (notRenewable) {
                                    self._errored = new MslMessageException(notRenewable, "Master token is expired and not renewable.")
                                        .setMasterToken(masterToken)
                                        .setUserIdToken(messageHeader.userIdToken)
                                        .setUserAuthenticationData(messageHeader.userAuthenticationData)
                                        .setMessageId(messageHeader.messageId);
                                    ready();
                                } else {
                                    checkNonReplayableId(ctx, messageHeader);
                                }
                            },
                            error: function(e) {
                                if (e instanceof MslException) {
                                    e.setMasterToken(messageHeader.masterToken);
                                    e.setUserIdToken(messageHeader.userIdToken);
                                    e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                                    e.setMessageId(messageHeader.messageId);
                                }
                                self._errored = e;
                                ready();
                            },
                        });
                    } else {
                        checkNonReplayableId(ctx, messageHeader);
                    }
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setUserIdTokne(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }

            function checkNonReplayableId(ctx, messageHeader) {
                try {
                    // If the message is non-replayable (it is not from a trusted
                    // network server).
                    var masterToken = messageHeader.masterToken;
                    var nonReplayableId = messageHeader.nonReplayableId;
                    if (typeof nonReplayableId === 'number') {
                        // ...and does not include a master token then reject the
                        // message.
                        if (!masterToken) {
                            self._errored = new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE, messageHeader)
                            .setEntityAuthenticationData(messageHeader.entityAuthenticationData)
                            .setUserIdToken(messageHeader.userIdToken)
                            .setUserAuthenticationData(messageHeader.userAuthenticationData)
                            .setMessageId(messageHeader.messageId);
                            ready();
                            return;
                        }

                        // If the non-replayable ID is not accepted then notify the
                        // sender.
                        var factory = ctx.getTokenFactory();
                        factory.acceptNonReplayableId(ctx, masterToken, nonReplayableId, {
                            result: function(replayed) {
                                if (replayed) {
                                    self._errored = new MslMessageException(replayed, messageHeader)
                                    .setMasterToken(masterToken)
                                    .setUserIdToken(messageHeader.userIdToken)
                                    .setUserAuthenticationData(messageHeader.userAuthenticationData)
                                    .setMessageId(messageHeader.messageId);
                                }

                                // Notify all that it is ready.
                                ready();
                            },
                            error: function(e) {
                                if (e instanceof MslException) {
                                    e.setMasterToken(masterToken);
                                    e.setUserIdToken(messageHeader.userIdToken);
                                    e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                                    e.setMessageId(messageHeader.messageId);
                                }
                                self._errored = e;
                                ready();
                            }
                        });
                    }

                    // Notify all that it is ready.
                    else {
                        ready();
                    }
                } catch (e) {
                    if (e instanceof MslException) {
                        e.setMasterToken(messageHeader.masterToken);
                        e.setEntityAuthenticationData(messageHeader.entityAuthenticationData);
                        e.setUserIdToken(messageHeader.userIdToken);
                        e.setUserAuthenticationData(messageHeader.userAuthenticationData);
                        e.setMessageId(messageHeader.messageId);
                    }
                    self._errored = e;
                    ready();
                }
            }
        },

        /**
         * Retrieve the next MSL object.
         * 
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MslObject), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the next MSL object
         *        or null if none remaining, or any thrown exceptions.
         * @throws MslEncodingException if there is a problem parsing the data.
         */
        nextMslObject: function nextMslObject(timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                // Make sure this message is allowed to have payload chunks.
                var messageHeader = this.getMessageHeader();
                if (!messageHeader)
                    throw new MslInternalException("Read attempted with error message.");

                // If we previously reached the end of the mesage don't try to
                // read more.
                if (this._eom)
                    return null;
                
                // Otherwise read the next MSL object.
                this._tokenizer.more(-1, {
                    result: function(available) {
                        InterruptibleExecutor(callback, function() {
                            if (!available) {
                                this._eom = true;
                                return null;
                            }
                            this._tokenizer.nextObject(-1, {
                                result: callback.result,
                                timeout: callback.timeout,
                                error: function(e) {
                                    InterruptibleExecutor(callback, function() {
                                        if (e instanceof MslEncoderException)
                                            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payloadchunk", e);
                                        throw e;
                                    }, self);
                                }
                            });
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: function(e) {
                        InterruptibleExecutor(callback, function() {
                            if (e instanceof MslEncoderException)
                                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "payloadchunk", e);
                            throw e;
                        }, self);
                    }
                });
            }, self);
        },

        /**
         * Retrieve the next payload chunk data.
         *
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(Uint8Array), timeout: function(), error: function(Error)}} callback
         *        the callback that will receive the next payload chunk data or
         *        null if none remaining, or any thrown exceptions.
         * @throws MslCryptoException if there is a problem decrypting or verifying
         *         the payload chunk.
         * @throws MslEncodingException if there is a problem parsing the data.
         * @throws MslMessageException if the payload verification failed.
         * @throws MslInternalException if attempting to access payloads of an
         *         error message.
         * @throws MslException if there is an error uncompressing the data.
         */
        nextData: function nextData(timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                // Make sure this message is allowed to have payload chunks.
                var messageHeader = this.getMessageHeader();
                if (!messageHeader)
                    throw new MslInternalException("Read attempted with error message.");

                // If reading buffered data return the next buffered payload data.
                if (this._payloadIndex != -1 && this._payloadIndex < this._payloads.length)
                    return this._payloads[this._payloadIndex++];

                // If we previously reached the end of the mesage don't try to
                // read more.
                if (this._eom)
                    return null;

                // Otherwise read the next payload.
                this.nextMslObject(timeout, {
                    result: function(payloadMo) {
                        InterruptibleExecutor(callback, function() {
                            if (!payloadMo) return null;
                            PayloadChunk.parse(this._ctx, payloadMo, this._cryptoContext, {
                                result: function(payload) {
                                    InterruptibleExecutor(callback, function() {
                                        // Make sure the payload belongs to this message and is the one
                                        // we are expecting.
                                        var masterToken = messageHeader.masterToken;
                                        var entityAuthData = messageHeader.entityAuthenticationData;
                                        var userIdToken = messageHeader.userIdToken;
                                        var userAuthData = messageHeader.getUserAuthenticationData;
                                        if (payload.messageId != messageHeader.messageId) {
                                            throw new MslMessageException(MslError.PAYLOAD_MESSAGE_ID_MISMATCH, "payload mid " + payload.messageId + " header mid " + messageHeader.messageId)
	                                            .setMasterToken(masterToken)
	                                            .setEntityAuthenticationData(entityAuthData)
	                                            .setUserIdToken(userIdToken)
	                                            .setUserAuthenticationData(userAuthData);
                                        }
                                        if (payload.sequenceNumber != this._payloadSequenceNumber) {
                                            throw new MslMessageException(MslError.PAYLOAD_SEQUENCE_NUMBER_MISMATCH, "payload seqno " + payload.sequenceNumber + " expected seqno " + this._payloadSequenceNumber)
	                                            .setMasterToken(masterToken)
	                                            .setEntityAuthenticationData(entityAuthData)
	                                            .setUserIdToken(userIdToken)
	                                            .setUserAuthenticationData(userAuthData);
                                        }
                                        ++this._payloadSequenceNumber;

                                        // FIXME remove this logic once the old handshake inference logic
                                        // is no longer supported.
                                        // Check for a handshake if this is the first payload chunk.
                                        if (this._handshake == null) {
                                            this._handshake = (messageHeader.isRenewable() && messageHeader.keyRequestData.length > 0 &&
                                            				   payload.isEndOfMessage() && payload.data.length == 0);
                                        }

                                        // Check for end of message.
                                        if (payload.isEndOfMessage())
                                            this._eom = true;

                                        // If mark was called save the payload in the buffer. We have to unset
                                        // the payload iterator since we're adding to the payloads list.
                                        var data = payload.data;
                                        if (this._markOffset != -1) {
                                            this._payloads.push(data);
                                            this._payloadIndex = -1;
                                        }
                                        return data;
                                    }, self);
                                },
                                error: callback.error,
                            });
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, self);
        },

        /**
         * Block until the message input stream successfully read the message
         * header and been fully initialized. The timeout callback will be
         * triggered based off the timeout value provided to the constructor.
         *
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback will receive true once the message
         *        input stream is ready or false if it has been aborted,
         *        notified of timeout, or any exceptions thrown during the
         *        message initialization.
         */
        isReady: function isReady(callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // If not ready wait until we are ready.
                if (!this._ready) {
                    this._readyQueue.poll(-1, {
                        result: function(elem) {
                            InterruptibleExecutor(callback, function() {
                                // If aborted return false.
                                if (elem === undefined) return false;
                                perform();
                            }, self);
                        },
                        timeout: function() {
                            AsyncExecutor(callback, function() {
                                throw new MslInternalException("Timeout while waiting for MessageInputStream.isReady() despite no timeout being specified.");
                            });
                        },
                        error: callback.error,
                    });
                } else {
                    perform();
                }
            }, self);

            function perform() {
                InterruptibleExecutor(callback, function() {
                    // Check if already aborted, timedout, or errored.
                    if (this._aborted)
                        return false;
                    if (this._timedout) {
                        callback.timeout();
                        return;
                    }
                    if (this._errored)
                        throw this._errored;

                    // Ready.
                    return true;
                }, self);
            }
        },

        /**
         * Returns true if the message is a handshake message.
         *
         * FIXME
         * This method should be removed by a direct query of the message header
         * once the old behavior of inferred handshake messages based on a single
         * empty payload chunk is no longer supported.
         *
         * @param {number} timeout read timeout in milliseconds or -1 for no
         *        timeout.
         * @param {{result: function(boolean), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive true if the message
         *        is a handshake message or any thrown exceptions.
         * @throws MslCryptoException if there is a problem decrypting or verifying
         *         the payload chunk.
         * @throws MslEncodingException if there is a problem parsing the data.
         * @throws MslMessageException if the payload verification failed.
         * @throws MslInternalException if attempting to access payloads of an
         *         error message.
         * @throws MslException if there is an error uncompressing the data.
         */
        isHandshake: function isHandshake(timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                var messageHeader = this.getMessageHeader();

                // Error messages are not handshake messages.
                if (!messageHeader) return false;

                // If the message header has its handshake flag set return true.
                if (messageHeader.isHandshake()) return true;

                // If we haven't read a payload we don't know if this is a handshake
                // message or not. This also implies the current payload is null.
                if (this._handshake == null) {
                    // nextData() will set the value of handshake if a payload is
                    // found.
                    this.nextData(timeout, {
                        result: function(payload) {
                            InterruptibleExecutor(callback, function() {
                                // If we were aborted then return undefined.
                                if (this._aborted)
                                    return undefined;

                                this._currentPayload = payload;
                                this._payloadOffset = 0;
                                if (!this._currentPayload)
                                    this._handshake = false;

                                // Return the current handshake status.
                                return this._handshake;
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // Save the exception to be thrown next time read() is called.
                                if (e instanceof MslException)
                                    this._readException = new MslIoException("Error reading the payload chunk.", e);
                                throw e;
                            }, self);
                        }
                    });
                }

                // Return the current handshake status.
                else {
                    return this._handshake;
                }
            }, self);
        },

        /**
         * @return {MessageHeader} the message header. Will be null for error messages.
         */
        getMessageHeader: function getMessageHeader() {
            if (this._header instanceof MessageHeader)
                return this._header;
            return null;
        },

        /**
         * @return {ErrorHeader} the error header. Will be null except for error messages.
         */
        getErrorHeader: function getErrorHeader() {
            if (this._header instanceof ErrorHeader)
                return this._header;
            return null;
        },

        /**
         * Returns the sender's entity identity. The identity will be unknown if
         * the local entity is a trusted network client and the message was sent by
         * a trusted network server using the local entity's master token.
         *
         * @return {string} the sender's entity identity or null if unknown.
         * @throws MslCryptoException if there is a crypto error accessing the
         *         entity identity;
         */
        getIdentity: function getIdentity() {
            var messageHeader = this.getMessageHeader();
            if (messageHeader) {
                var masterToken = messageHeader.masterToken;
                if (masterToken)
                    return masterToken.identity;
                return messageHeader.entityAuthenticationData.getIdentity();
            }
            var errorHeader = this.getErrorHeader();
            return errorHeader.entityAuthenticationData.getIdentity();
        },

        /**
         * Returns the user associated with the message. The user will be unknown
         * if the local entity is a trusted network client and the message was sent
         * by a trusted network server.
         *
         * @return {MslUser} the user associated with the message or null if unknown.
         */
        getUser: function getUser() {
            var messageHeader = this.getMessageHeader();
            if (!messageHeader)
                return null;
            return messageHeader.user;
        },

        /**
         * @return {ICryptoContext} the payload crypto context. Will be null for error messages.
         */
        getPayloadCryptoContext: function getPayloadCryptContext() {
            return this._cryptoContext;
        },

        /**
         * @return {ICryptoContext} the key exchange crypto context. Will be null if no key response
         *         data was returned in this message and for error messages.
         */
        getKeyExchangeCryptoContext: function getKeyExchangeCryptoContext() {
            return this._keyxCryptoContext;
        },
        
        /**
         * Returns true if the payload application data is encrypted. This will be
         * true if the entity authentication scheme provides encryption or if
         * session keys were used. Returns false for error messages which do not
         * have any payload chunks.
         * 
         * @return {boolean} true if the payload application data is encrypted. Will be false
         *         for error messages.
         */
        encryptsPayloads: function encryptsPayloads() {
            // Return false for error messages.
            var messageHeader = this.getMessageHeader();
            if (!messageHeader)
                return false;
            
            // If the message uses entity authentication data for an entity
            // authentication scheme that provides encryption, return true.
            var entityAuthData = messageHeader.entityAuthenticationData;
            if (entityAuthData && entityAuthData.scheme.encrypts)
                return true;
            
            // If the message uses a master token, return true.
            var masterToken = messageHeader.masterToken;
            if (masterToken)
                return true;
            
            // If the message includes key response data, return true.
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData)
                return true;
            
            // Otherwise return false.
            return false;
        },
        
        /**
         * Returns true if the payload application data is integrity protected.
         * This will be true if the entity authentication scheme provides integrity
         * protection or if session keys were used. Returns false for error
         * messages which do not have any payload chunks.
         * 
         * @return {boolean} true if the payload application data is integrity protected.
         *         Will be false for error messages.
         */
        protectsPayloadIntegrity: function protectsPayloadIntegrity() {
            // Return false for error messages.
            var messageHeader = this.getMessageHeader();
            if (!messageHeader)
                return false;
            
            // If the message uses entity authentication data for an entity
            // authentication scheme that provides integrity protection, return
            // true.
            var entityAuthData = messageHeader.entityAuthenticationData;
            if (entityAuthData && entityAuthData.scheme.protectsIntegrity)
                return true;
            
            // If the message uses a master token, return true.
            var masterToken = messageHeader.masterToken;
            if (masterToken)
                return true;
            
            // If the message includes key response data, return true.
            var keyResponseData = messageHeader.keyResponseData;
            if (keyResponseData)
                return true;
            
            // Otherwise return false.
            return false;
        },

        /**
         * By default the source input stream is not closed when this message input
         * stream is closed. If it should be closed then this method can be used to
         * dictate the desired behavior.
         *
         * @param {boolean} close true if the source input stream should be closed, false if
         *        it should not.
         */
        closeSource: function closeSource(close) {
            this._closeSource = close;
        },

        /** @inheritDoc */
        abort: function abort() {
            this._aborted = true;
            this._source.abort();
            this._readyQueue.cancelAll();
        },

        /** @inheritDoc */
        close: function close(timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Close the tokenizer.
                self._tokenizer.close(timeout, {
                    result: function(success) {
                        // Only close the source if instructed to do so because we might want
                        // to reuse the connection.
                        if (this._closeSource) {
                            this._source.close(timeout, callback);
                        }

                        // Otherwise if this is not a handshake message or error message then
                        // consume all payloads that may still be on the source input stream.
                        else {
                            if (!this.getMessageHeader()) return true;
                            this.isHandshake(timeout, {
                                result: function(handshake) {
                                    if (!handshake) callback.result(true);
                                    else consume();
                                },
                                timeout: callback.timeout,
                                // Ignore exceptions.
                                error: function() { callback.result(true); },
                            });
                        }

                        function consume() {
                            self.nextData(timeout, {
                                result: function(data) {
                                    if (data) consume();
                                    else callback.result(true);
                                },
                                timeout: callback.timeout,
                                // Ignore exceptions.
                                error: function() { callback.result(true); },
                            });
                        }
                    },
                    timeout: callback.timeout,
                    error: function(e) {
                        // Ignore exceptions.
                        callback.result(true);
                    },
                });
            }, self);
        },

        /** @inheritDoc */
        mark: function mark(readlimit) {
            // Remember the read limit, reset the read count.
            this._readlimit = (readlimit) ? readlimit : -1;
            this._readcount = 0;

            // Start buffering.
            this._buffering = true;
            
            // If there is a current payload...
            if (this._currentPayload) {
                // Remove all buffered data earlier than the current payload.
                while (this._payloads.length > 0 && this._payloads[0] !== this._currentPayload)
                    this._payloads.shift();
                
                // Add the current payload if it was not already buffered.
                if (this._payloads.length == 0)
                    this._payloads.push(this._currentPayload);

                // Reset the iterator to continue reading buffered data from the
                // current payload.
                this._payloadIndex = 0;
                this._currentPayload = this._payloads[this._payloadIndex++];

                // Set the new mark point on the current payload.
                this._markOffset = this._payloadOffset;
                return;
            }

            // Otherwise we've either read to the end or haven't read anything at
            // all yet. Discard all buffered data.
            this._payloadIndex = -1;
            this._payloads = [];
        },

        /** @inheritDoc */
        markSupported: function markSupported() {
            return true;
        },

        /** @inheritDoc */
        read: function read(len, timeout, callback) {
            var self = this;

            InterruptibleExecutor(callback, function() {
                // Error on illegal length values.
                if (len < -1)
                    throw new RangeError("read requested with illegal length " + len);

                // If not ready wait until we are ready.
                if (!this._ready) {
                    this._readyQueue.poll(timeout, {
                        result: function(elem) {
                            // If aborted return false.
                            if (elem === undefined) callback.result(false);
                            else initialChecks();
                        },
                        timeout: function() { callback.timeout(new Uint8Array(0)); },
                        error: callback.error,
                    });
                } else {
                    initialChecks();
                }
            }, self);

            function initialChecks() {
                InterruptibleExecutor(callback, function() {
                    // Check if already aborted, timedout, or errored.
                    if (this._aborted)
                        return new Uint8Array(0);
                    if (this._timedout) {
                        callback.timeout(new Uint8Array(0));
                        return;
                    }
                    if (this._errored)
                        throw this._errored;

                    // Throw any cached read exception.
                    if (this._readException != null) {
                        var e = this._readException;
                        this._readException = null;
                        throw e;
                    }

                    // Return end of stream immediately for handshake messages.
                    this.isHandshake(timeout, {
                        result: function(handshake) {
                            InterruptibleExecutor(callback, function() {
                                // FIXME: This can be removed once the old
                                // handshake logic is no longer supported.
                                // Check if aborted.
                                if (handshake === undefined)
                                    return new Uint8Array(0);
                                if (handshake)
                                    return null;
                                perform();
                            }, self);
                        },
                        timeout: callback.timeout,
                        error: function(e) {
                            InterruptibleExecutor(callback, function() {
                                // FIXME
                                // Unset the read exception since we are going to throw it right
                                // now. This logic can go away once the old handshake logic is
                                // removed.
                                this._readException = null;
                                throw new MslIoException("Error reading the payload chunk.", e);
                            }, self);
                        }
                    });
                }, self);
            }

            function perform() {
                InterruptibleExecutor(callback, function() {
                    // Allocate the data buffer if the caller requested a
                    // specific amount of data. Otherwise we'll allocate once
                    // we have some data available.
                    //
                    // The data buffer size is equal to the amount of data
                    // requested by the caller.
                    var data = (len != -1) ? new Uint8Array(len) : undefined;

                    // Read from payloads until we are done or cannot read anymore.
                    var dataOffset = 0;
                    var bytesRead = 0;
                    function readMore(callback) {
                        InterruptibleExecutor(callback, function() {
                            // If we've read everything then return the result.
                            if (data && (bytesRead >= data.length))
                                return data.subarray(0, bytesRead);

                            // Read from the current payload.
                            var read = -1;
                            if (this._currentPayload) {
                                // If the caller requested everything available
                                // allocate the data buffer as needed.
                                var currentAvailable = this._currentPayload.length - this._payloadOffset;
                                if (!data) {
                                    // Start with the bytes available in the
                                    // current buffer. Add any subsequent
                                    // buffered payloads.
                                    var readlen = currentAvailable;
                                    if (this._payloadIndex != -1) {
                                        for (var i = this._payloadIndex; i < this._payloads.length; ++i) {
                                            var payload = this._payloads[i];
                                            readlen += payload.length;
                                        }
                                    }

                                    // If there is something available then
                                    // allocate the data buffer.
                                    if (readlen > 0)
                                        data = new Uint8Array(readlen);
                                }

                                // Copy into the data buffer.
                                //
                                // If there is nothing available then the count
                                // will be zero and we won't attempt to use
                                // the data buffer (as it may not exist).
                                var remaining = (data) ? data.length - bytesRead : 0;
                                var count = Math.min(currentAvailable, remaining);
                                if (count > 0) {
                                    var end = this._payloadOffset + count;
                                    var payloadData = this._currentPayload.subarray(this._payloadOffset, end);
                                    data.set(payloadData, dataOffset);

                                    // Update our read count and offsets.
                                    read = count;
                                    dataOffset += count;
                                    this._payloadOffset += count;

                                    // If buffering data increment the read count.
                                    if (this._buffering) {
                                        this._readcount += count;
                                        
                                        // If the read count exceeds the read limit stop buffering payloads
                                        // and reset the read count and limit, but retain the payload
                                        // iterator as we need to continue reading from any buffered data.
                                        if (this._readlimit != -1 && this._readcount > this._readlimit) {
                                            this._buffering = false;
                                            this._readcount = this._readlimit = 0;
                                        }
                                    }
                                }
                            }

                            // If we read some data continue.
                            if (read != -1) {
                                bytesRead += read;
                                readMore(callback);
                                return;
                            }

                            // Otherwise grab the next payload data.
                            this.nextData(timeout, {
                                result: function(payload) {
                                    InterruptibleExecutor(callback, function() {
                                        // If we were aborted then return whatever
                                        // has been read.
                                        if (this._aborted)
                                            return (data) ? data.subarray(0, bytesRead) : new Uint8Array(0);

                                        this._currentPayload = payload;
                                        this._payloadOffset = 0;

                                        // If we got more data, continue.
                                        if (this._currentPayload) {
                                            readMore(callback);
                                            return;
                                        }

                                        // If nothing was read (but something was requested) return end of
                                        // stream.
                                        if (bytesRead == 0 && len != 0)
                                            return null;

                                        // Return whatever data we have, which
                                        // may be none.
                                        return (data) ? data.subarray(0, bytesRead) : new Uint8Array(0);
                                    }, self);
                                },
                                timeout: function() {
                                    // Return whatever data we have, which may be
                                    // none.
                                    callback.timeout((data) ? data.subarray(0, bytesRead) : new Uint8Array(0));
                                },
                                error: function(e) {
                                    InterruptibleExecutor(callback, function() {
                                        // If we already read some data return it and save the
                                        // exception to be thrown next time read() is called.
                                        if (e instanceof MslException)
                                            e = new MslIoException("Error reading the payload chunk.", e);
                                        if (bytesRead > 0) {
                                            self._readException = e;
                                            return data.subarray(0, bytesRead);
                                        }

                                        // Otherwise throw the exception now.
                                        throw e;
                                    }, self);
                                }
                            });
                        }, self);
                    }

                    readMore(callback);
                }, self);
            }
        },

        /** @inheritDoc */
        reset: function reset() {
            // Do nothing if we are not buffering.
            if (!this._buffering)
                return;
            
            // Reset all payloads and initialize the payload iterator.
            //
            // We need to reset the payloads since we are going to re-read them and
            // want the correct value returned when queried for available bytes.
            this._payloadIndex = 0;
            if (this._payloads.length > 0) {
                this._currentPayload = this._payloads[this._payloadIndex++];
                this._payloadOffset = this._markOffset;
            } else {
                this._currentPayload = null;
            }
            
            // Reset the read count.
            this._readcount = 0;
        },
    });

    /**
     * <p>Construct a new message input stream. The header is parsed.</p>
     *
     * <p>If key request data is provided and a matching key response data is
     * found in the message header the key exchange will be performed to
     * process the message payloads.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {InputStream} source MSL input stream.
     * @param {Array.<KeyRequestData>} keyRequestData key request data to use when processing key
     *        response data.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @param {number} timeout read timeout in milliseconds.
     * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
     *        callback the callback that will receive the message input
     *        stream, or any thrown exceptions.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token.
     */
    var MessageInputStream$create = function MessageInputStream$create(ctx, source, keyRequestData, cryptoContexts, timeout, callback) {
        new MessageInputStream(ctx, source, keyRequestData, cryptoContexts, timeout, callback);
    };
    
    // Exports.
    module.exports.create = MessageInputStream$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageInputStream'));
