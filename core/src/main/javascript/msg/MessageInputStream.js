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
var MessageInputStream;
var MessageInputStream$create;

(function() {
    "use strict";

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
     * @throws MslEncodingException if there is an error parsing the JSON.
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
                        throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, JSON.stringify(keyRequestData));
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

    MessageInputStream = InputStream.extend({
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
         * @param {string} charset input stream character set encoding.
         * @param {Array.<KeyRequestData>} keyRequestData key request data to use when processing key
         *        response data.
         * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
         *        contexts used to decrypt and verify service tokens.
         * @param {number} timeout read timeout in milliseconds.
         * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
         *        callback the callback that will receive the message input
         *        stream, or any thrown exceptions.
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
         * @throws MslMessageException if the message master token is expired and
         *         the message is not renewable.
         * @throws MslException if the message does not contain an entity
         *         authentication data or a master token, or a token is improperly
         *         bound to another token.
         */
        init: function init(ctx, source, charset, keyRequestData, cryptoContexts, timeout, callback) {
            var self = this;
            InterruptibleExecutor(callback, function() {
                // Set properties.
                var props = {
                    _source: { value: source, writable: false, enumerable: false, configurable: false },
                    _parser: { value: undefined, writable: true, enumerable: false, configurable: false },
                    _charset: { value: charset, writable: false, enumerable: false, configurable: false },
                    _remainingData: { value: '', writable: true, enumerable: false, configurable: false },
                    _header: { value: undefined, writable: true, enumerable: false, configurable: false },
                    _cryptoContext: { value: undefined, writable: true, enumerable: false, configurable: false },
                    _keyxCryptoContext: { value: undefined, writable: true, enumerable: false, configurable: false },
                    _payloadSequenceNumber: { value: 1, writable: true, enuemrable: false, configurable: false },
                    _eom: { value: false, writable: true, enumerable: false, configurable: false },
                    _handshake: { value: null, writable: true, enumerable: false, configurable: false },
                    _closeSource: { value: false, writable: true, enumerable: false, configurable: false },
                    /** @type {Array.<Uint8Array>} */
                    _payloads: { value: new Array(), writable: true, enumerable: false, configurable: false },
                    _payloadIndex: { value: -1, writable: true, enumerable: false, configurable: false },
                    _payloadOffset: { value: 0, writable: true, enuemrable: false, configurable: false },
                    _markOffset: { value: 0, writable: true, enumerable: false, configurable: false },
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

                function ready() {
                    self._ready = true;
                    self._readyQueue.add(true);
                }

                inputStreamToJSON(self._source, timeout, {
                    result: function (json) {
                        self._json = json;
                        self._jsonIndex = 0;

                        if (self._json === null) {
                            self._errored = new MslEncodingException(MslError.MESSAGE_DATA_MISSING);
                            ready();
                            return;
                        }

                        Header$parseHeader(ctx, self._json[self._jsonIndex++], cryptoContexts, {
                            result: function(header) {
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
                                            e.setEntity(messageHeader.masterToken);
                                            e.setEntity(messageHeader.entityAuthenticationData);
                                            e.setUser(messageHeader.userIdToken);
                                            e.setUser(messageHeader.userAuthenticationData);
                                            e.setMessageId(messageHeader.messageId);
                                        }
                                        self._errored = e;
                                        ready();
                                    }
                                });
                            },
                            error: function(e) {
                                self._errored = e;
                                ready();
                            }
                        });
                    },
                    timeout: function () {
                        self._timedout = true;
                        ready();
                    },
                    error: function (e) {
                        self._errored = e;
                        ready();
                    }
                });

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
                            e.setEntity(messageHeader.masterToken);
                            e.setEntity(messageHeader.entityAuthenticationData);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
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
                            throw new MslMessageException(MslError.HANDSHAKE_DATA_MISSING, JSON.stringify(messageHeader));
                        }
                        
                        checkMasterToken(ctx, messageHeader);
                    } catch (e) {
                        if (e instanceof MslException) {
                            e.setEntity(messageHeader.masterToken);
                            e.setEntity(messageHeader.entityAuthenticationData);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
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
                            e.setEntity(messageHeader.masterToken);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
                            e.setMessageId(messageHeader.messageId);
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
                                    .setUser(messageHeader.userIdToken)
                                    .setUser(messageHeader.userAuthenticationData)
                                    .setMessageId(messageHeader.messageId);
                                    ready();
                                } else {
                                    checkUserIdTokenRevoked(ctx, messageHeader);
                                }
                            },
                            error: function(e) {
                                if (e instanceof MslException) {
                                    e.setEntity(messageHeader.masterToken);
                                    e.setUser(messageHeader.userIdToken);
                                    e.setUser(messageHeader.userAuthenticationData);
                                    e.setMessageId(messageHeader.messageId);
                                }
                                self._errored = e;
                                ready();
                            }
                        });
                    } catch (e) {
                        if (e instanceof MslException) {
                            e.setEntity(messageHeader.masterToken);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
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
                                        .setEntity(masterToken)
                                        .setUser(userIdToken)
                                        .setMessageId(messageHeader.messageId);
                                        ready();
                                    } else {
                                        checkMasterTokenExpired(ctx, messageHeader);
                                    }
                                },
                                error: function(e) {
                                    if (e instanceof MslException) {
                                        e.setEntity(messageHeader.masterToken);
                                        e.setUser(messageHeader.userIdToken);
                                        e.setUser(messageHeader.userAuthenticationData);
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
                            e.setEntity(messageHeader.masterToken);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
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
                            if (!messageHeader.isRenewable() || messageHeader.keyRequestData.length == 0) {
                                self._errored = new MslMessageException(MslError.MESSAGE_EXPIRED, JSON.stringify(messageHeader))
                                .setEntity(masterToken)
                                .setUser(messageHeader.userIdToken)
                                .setUser(messageHeader.userAuthenticationData)
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
                                        .setEntity(masterToken)
                                        .setUser(messageHeader.userIdToken)
                                        .setUser(messageHeader.userAuthenticationData)
                                        .setMessageId(messageHeader.messageId);;
                                        ready();
                                    } else {
                                        checkNonReplayableId(ctx, messageHeader);
                                    }
                                },
                                error: function(e) {
                                    if (e instanceof MslException) {
                                        e.setEntity(messageHeader.masterToken);
                                        e.setUser(messageHeader.userIdToken);
                                        e.setUser(messageHeader.userAuthenticationData);
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
                            e.setEntity(messageHeader.masterToken);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
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
                                self._errored = new MslMessageException(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE, JSON.stringify(messageHeader))
                                .setEntity(messageHeader.entityAuthenticationData)
                                .setUser(messageHeader.userIdToken)
                                .setUser(messageHeader.userAuthenticationData)
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
                                        self._errored = new MslMessageException(replayed, JSON.stringify(messageHeader))
                                        .setEntity(masterToken)
                                        .setUser(messageHeader.userIdToken)
                                        .setUser(messageHeader.userAuthenticationData)
                                        .setMessageId(messageHeader.messageId);
                                    }

                                    // Notify all that it is ready.
                                    ready();
                                },
                                error: function(e) {
                                    if (e instanceof MslException) {
                                        e.setEntity(masterToken);
                                        e.setUser(messageHeader.userIdToken);
                                        e.setUser(messageHeader.userAuthenticationData);
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
                            e.setEntity(messageHeader.masterToken);
                            e.setEntity(messageHeader.entityAuthenticationData);
                            e.setUser(messageHeader.userIdToken);
                            e.setUser(messageHeader.userAuthenticationData);
                            e.setMessageId(messageHeader.messageId);
                        }
                        self._errored = e;
                        ready();
                    }
                }

                // Return this immediately instead of after reading the header
                // so the read can be aborted.
                return this;
            }, self);
        },

        /**
         * Retrieve the next JSON object.
         * 
         * @param {number} timeout read timeout in milliseconds.
         * @return {object} the next JSON object or null if none remaining.
         * @throws MslEncodingException if there is a problem parsing the JSON.
         */
        nextJsonObject: function nextJsonObject(timeout, callback) {
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
                
                // Otherwise read the next JSON object.
                function nextObject(callback) {
                    InterruptibleExecutor(callback, function() {
                        var payloadJo;
                        //var payloadJo = this._parser.nextValue();
                        if (this._jsonIndex < this._json.length) {
                            payloadJo = this._json[this._jsonIndex++];
                            return payloadJo;
                        } else {
                            // in this case there's been a request for
                            // another payload, but we don't actually have
                            // the object parsed yet. So we need to parse
                            // the source again
                            inputStreamToJSON(this._source, timeout, {
                                result: function (json) {
                                    if (json && json.length && json.length > 0) {
                                        json.forEach(function (elt) {
                                            this._json.push(elt);
                                        });
                                        nextObject(callback);
                                    } else {
                                        // we've reached the end of the stream
                                        this._eom = true;
                                        callback.result(null);
                                    }
                                },
                                timeout: callback.timeout,
                                error: callback.error,
                            });
                        }
                    }, self);
                }
                nextObject({
                    result: function(payloadJo) {
                        InterruptibleExecutor(callback, function() {
                            if (!payloadJo)
                                return null;
                            if (typeof payloadJo !== 'object')
                                throw new MslEncodingException(MslError.MESSAGE_FORMAT_ERROR);
                            return payloadJo;
                        }, self);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
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
         * @throws MslEncodingException if there is a problem parsing the JSON.
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
                this.nextJsonObject(timeout, {
                    result: function(payloadJo) {
                        InterruptibleExecutor(callback, function() {
                            if (!payloadJo) return null;
                            PayloadChunk$parse(payloadJo, this._cryptoContext, {
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
                                            .setEntity(masterToken)
                                            .setEntity(entityAuthData)
                                            .setUser(userIdToken)
                                            .setUser(userAuthData);
                                        }
                                        if (payload.sequenceNumber != this._payloadSequenceNumber) {
                                            throw new MslMessageException(MslError.PAYLOAD_SEQUENCE_NUMBER_MISMATCH, "payload seqno " + payload.sequenceNumber + " expected seqno " + this._payloadSequenceNumber)
                                            .setEntity(masterToken)
                                            .setEntity(entityAuthData)
                                            .setUser(userIdToken)
                                            .setUser(userAuthData);
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

                                        // Save the payload in the buffer and return it. We have to
                                        // unset the payload iterator since we're adding to the
                                        // payloads list.
                                        var data = payload.data;
                                        this._payloads.push(data);
                                        this._payloadIndex = -1;
                                        return data;
                                    }, self);
                                },
                                error: function(e) {
                                    if (e instanceof SyntaxError)
                                        e = new MslEncodingException(MslError.JSON_PARSE_ERROR, "payloadchunk", e);
                                    callback.error(e);
                                }
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
                        error: function(e) { callback.error(e); }
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
         * @return {boolean} true if the message is a handshake message or
         *         undefined if aborted.
         * @throws MslCryptoException if there is a problem decrypting or verifying
         *         the payload chunk.
         * @throws MslEncodingException if there is a problem parsing the JSON.
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
                            if (handshake) callback.result(true);
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
            }, self);
        },

        /** @inheritDoc */
        mark: function mark() {
            // If there is a current payload...
            if (this._currentPayload) {
                // Remove all buffered data earlier than the current payload.
                while (this._payloads.length > 0 && this._payloads[0] !== this._currentPayload)
                    this._payloads.shift();

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
                        error: function(e) { callback.error(e); }
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
     * @param {string} charset input stream character set encoding.
     * @param {Array.<KeyRequestData>} keyRequestData key request data to use when processing key
     *        response data.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @param {number} timeout read timeout in milliseconds.
     * @param {{result: function(MessageInputStream), timeout: function(), error: function(Error)}}
     *        callback the callback that will receive the message input
     *        stream, or any thrown exceptions.
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
    MessageInputStream$create = function MessageInputStream$create(ctx, source, charset, keyRequestData, cryptoContexts, timeout, callback) {
        new MessageInputStream(ctx, source, charset, keyRequestData, cryptoContexts, timeout, callback);
    };
})();
