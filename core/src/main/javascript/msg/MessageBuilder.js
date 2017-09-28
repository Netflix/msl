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
 * <p>A message builder provides methods for building messages.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	const MslConstants = require('../MslConstants.js');
	const MslInternalException = require('../MslInternalException.js');
	const AsyncExecutor = require('../util/AsyncExecutor.js');
	const MslKeyExchangeException = require('../MslKeyExchangeException.js');
	const MslError = require('../MslError.js');
	const MslException = require('../MslException.js');
	const MslUserAuthException = require('../MslUserAuthException.js');
	const MessageCapabilities = require('../msg/MessageCapabilities.js');
	const ErrorHeader = require('../msg/ErrorHeader.js');
	const Class = require('../util/Class.js');
	const MslMessageException = require('../MslMessageException.js');
	const MessageHeader = require('../msg/MessageHeader.js');
	const ServiceToken = require('../tokens/ServiceToken.js');
	const NullCryptoContext = require('../crypto/NullCryptoContext.js');
	const MslUtils = require('../util/MslUtils.js');
	
    /**
     * Empty service token data.
     * @const
     * @type {Uint8Array}
     */
    var EMPTY_DATA = new Uint8Array(0);

    /**
     * Increments the provided message ID by 1, wrapping around to zero if
     * the provided value is equal to {@link MslConstants.MAX_LONG_VALUE}.
     *
     * @param {number} messageId the message ID to increment.
     * @return {number} the message ID + 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    var MessageBuilder$incrementMessageId = function MessageBuilder$incrementMessageId(messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        return (messageId == MslConstants.MAX_LONG_VALUE) ? 0 : messageId + 1;
    };

    /**
     * Decrements the provided message ID by 1, wrapping around to
     * {@link MslConstants.MAX_LONG_VALUE} if the provided value is equal to 0.
     *
     * @param {number} messageId the message ID to decrement.
     * @return {number} the message ID - 1.
     * @throws MslInternalException if the provided message ID is out of range.
     */
    var MessageBuilder$decrementMessageId = function MessageBuilder$incrementMessageId(messageId) {
        if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
        return (messageId == 0) ? MslConstants.MAX_LONG_VALUE : messageId - 1;
    };

    /**
     * Issue a new master token for the specified identity or renew an existing
     * master token.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslEncoderFormat} format MSL encoder format.
     * @param {Array.<KeyRequestData>} keyRequestData available key request data.
     * @param {MasterToken} masterToken master token to renew. Null if the identity is
     *        provided.
     * @param {EntityAuthenticationData} entityAuthData entity authentication data. Null if a master token
     *        is provided.
     * @param {{result: function(KeyExchangeData), error: function(Error)}}
     *        callback the callback that will receive the key exchange data, or
     *        null if the factory chooses not to perform key exchange, or any
     *        thrown exceptions.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created or none
     *         of the key exchange schemes are supported.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the JSON.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity or entity identity.
     * @throws MslException if there is an error creating or renewing the
     *         master token.
     */
    function issueMasterToken(ctx, format, keyRequestData, masterToken, entityAuthData, callback) {
        var factoryIndex = 0, requestIndex = 0;
        var factories = ctx.getKeyExchangeFactories();
        var keyxException;
        var entityToken = (masterToken) ? masterToken : entityAuthData;

        // Attempt key exchange in the preferred order.
        function nextExchange() {
            AsyncExecutor(callback, function() {
                // If we've reached the end of the key request data, try them all
                // again with the next factory.
                if (requestIndex >= keyRequestData.length) {
                    requestIndex = 0;
                    ++factoryIndex;
                }

                // If we've reached the end of the factories then stop.
                if (factoryIndex >= factories.length) {
                    // We did not perform a successful key exchange. If we caught an
                    // exception then throw that exception now.
                    if (keyxException)
                        throw keyxException;

                    // If we didn't find any then we're unable to perform key exchange.
                    throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, keyRequestData);
                }

                // Grab this iteration's factory and request.
                var factory = factories[factoryIndex];
                var request = keyRequestData[requestIndex];
                if (factory.scheme != request.keyExchangeScheme) {
                    // Try the next request.
                    ++requestIndex;
                    nextExchange();
                    return;
                }

                // Attempt the key exchange.
                factory.generateResponse(ctx, format, request, entityToken, {
                    result: function(keyExchangeData) {
                        // Deliver the result.
                        callback.result(keyExchangeData);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            // Immediately deliver anything that's not a MslException.
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
    }

    /**
     * Performs key exchange for the request message header if key exchange
     * should occur.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslEncoderFormat} format MSL encoder format.
     * @param {MessageHeader} requestHeader message with which to attempt key exchange.
     * @param {?EntityAuthenticationData} entityAuthData message header entity authentication data.
     * @param {?MasterToken} message header master token.
     * @param {{result: function(KeyExchangeData), error: function(Error)}}
     *        callback the callback that will receive the key exchange data or
     *        any thrown exceptions.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created or none
     *         of the key exchange schemes are supported.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslEncodingException if there is an error parsing or encoding
     *         the JSON.
     * @throws MslEntityAuthException if there is a problem with the master
     *         token identity or entity identity.
     * @throws MslException if there is an error creating or renewing the
     *         master token.
     */
    function performKeyExchange(ctx, format, requestHeader, entityAuthData, masterToken, callback) {
        AsyncExecutor(callback, function() {
            // If the message contains key request data and is renewable...
            var keyRequestData = requestHeader.keyRequestData;
            if (requestHeader.isRenewable() && keyRequestData.length > 0) {
                // If the message contains a master token...
                if (masterToken) {
                    // If the master token is renewable or expired then renew
                    // the master token.
                    if (masterToken.isRenewable(null) || masterToken.isExpired(null)) {
                        issueMasterToken(ctx, format, keyRequestData, masterToken, null, callback);
                    } else {
                        return null;
                    }
                }

                // Otherwise use the entity authentication data to issue a
                // master token.
                else {
                    // The message header is already authenticated via the
                    // entity authentication data's crypto context so we can
                    // simply proceed with the master token issuance.
                    issueMasterToken(ctx, format, keyRequestData, null, entityAuthData, callback);
                }
            }

            // If the message does not contain key request data there is no key
            // exchange for us to do.
            else {
                return null;
            }
        });
    }

    /**
     * <p>Create a new message builder that will craft a new message. If a
     * message ID is provided it will be used for the new message's message ID.
     * Otherwise a random message ID will be generated.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken master token. May be null unless a user ID token is
     *        provided.
     * @param {UserIdToken} userIdToken user ID token. May be null.
     * @param {?string} recipient message recipient. May be null.
     * @param {?number} messageId the message ID to use. Must be within range.
     * @param {{result: function(MessageBuilder), error: function(Error)}}
     *        callback the callback that will receive the message builder or
     *        any thrown exceptions.
     * @throws MslException if a user ID token is not bound to its
     *         corresponding master token.
     */
    var MessageBuilder$createRequest = function MessageBuilder$createRequest(ctx, masterToken, userIdToken, recipient, messageId, callback) {
        AsyncExecutor(callback, function() {
            if (messageId == undefined || messageId == null) {
                messageId = MslUtils.getRandomLong(ctx);
            } else {
                if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                    throw new MslInternalException("Message ID " + messageId + " is outside the valid range.");
            }

            // Grab the local entity authentication data.
            ctx.getEntityAuthenticationData(null, {
                result: function(entityAuthData) {
                    AsyncExecutor(callback, function() {
                        var capabilities = ctx.getMessageCapabilities();
                        return new MessageBuilder(ctx, recipient, messageId, capabilities, entityAuthData, masterToken, userIdToken, null, null, null, null, null);
                    });
                },
                error: function(e) { callback.error(e); }
            });
        });
    };

    /**
     * Return the user ID token that should be included in the message header
     * creating in response to a request. The request's user ID token may be
     * renewed or a new user ID token issued if user authentication data is
     * provided.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MessageHeader} requestHeader request message header.
     * @param {MasterToken} masterToken master token to verify/bind the user ID
     *        token against.
     * @param {{result: function(UserIdToken), error: function(Error)}} callback
     *        the callback that will receive the user ID token or any thrown
     *        exceptions.
     * @throws MslUserAuthException if the user authentication scheme is not
     *         supported.
     */
    function getUserIdToken(ctx, requestHeader, masterToken, callback) {
        AsyncExecutor(callback, function() {
            var userIdToken = requestHeader.userIdToken;
            var userAuthData = requestHeader.userAuthenticationData;
            var requestMessageId = requestHeader.messageId;

            // If the message contains a user ID token issued by the local
            // entity...
            if (userIdToken && userIdToken.isVerified()) {
                // If the user ID token is renewable and the message is
                // renewable, or it is expired, or it needs to be rebound
                // to the new master token then renew the user ID token.
                if ((userIdToken.isRenewable(null) && requestHeader.isRenewable()) ||
                    userIdToken.isExpired(null) ||
                    !userIdToken.isBoundTo(masterToken))
                {
                    let tokenFactory = ctx.getTokenFactory();
                    tokenFactory.renewUserIdToken(ctx, userIdToken, masterToken, callback);
                    return;
                }
            }

            // If the message is renewable and contains user authentication
            // data and a master token then we need to attempt user
            // authentication and issue a user ID token.
            else if (requestHeader.isRenewable() && masterToken && userAuthData) {
                // If this request was parsed then its user authentication data
                // should have been authenticated and the user will exist. If
                // it was not parsed, then we need to perform user
                // authentication now.
                var user = requestHeader.user;
                if (!user) {
                    var scheme = userAuthData.scheme;
                    var factory = ctx.getUserAuthenticationFactory(scheme);
                    if (!factory) {
                        throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme)
	                        .setMasterToken(masterToken)
	                        .setUserAuthenticationData(userAuthData)
	                        .setMessageId(requestMessageId);
                    }
                    user = factory.authenticate(ctx, masterToken.identity, userAuthData, null);
                }
                let tokenFactory = ctx.getTokenFactory();
                tokenFactory.createUserIdToken(ctx, user, masterToken, callback);
                return;
            }

            // Otherwise return the header's user ID token (may be null).
            return userIdToken;
        });
    }

    /**
     * Create a new message builder that will craft a new message in response
     * to another message. The constructed message may be used as a request.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MessageHeader} requestHeader message header to respond to.
     * @param {{result: function(MessageBuilder), error: function(Error)}}
     *        callback the callback that will receive the message builder or
     *        any thrown exceptions.
     * @throws MslMasterTokenException if the provided message's master token
     *         is not trusted.
     * @throws MslCryptoException if the crypto context from a key exchange
     *         cannot be created.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or the key response data cannot be created.
     * @throws MslUserAuthException if there is an error with the user
     *         authentication data or the user ID token cannot be created.
     * @throws MslException if a user ID token in the message header is not
     *         bound to its corresponding master token or there is an error
     *         creating or renewing the master token.
     */
    var MessageBuilder$createResponse = function MessageBuilder$createResponse(ctx, requestHeader, callback) {
        AsyncExecutor(callback, function() {
            var masterToken = requestHeader.masterToken;
            var entityAuthData = requestHeader.entityAuthenticationData;
            var userIdToken = requestHeader.userIdToken;
            var userAuthData = requestHeader.userAuthenticationData;

            // The response recipient is the requesting entity.
            var recipient = (masterToken) ? masterToken.identity : entityAuthData.getIdentity();

            // The response message ID must be equal to the request message ID + 1.
            var requestMessageId = requestHeader.messageId;
            var messageId = MessageBuilder$incrementMessageId(requestMessageId);
            
            // Compute the intersection of the request and response message
            // capabilities.
            var capabilities = MessageCapabilities.intersection(requestHeader.messageCapabilities, ctx.getMessageCapabilities());
            
            // Identify the response format.
            var encoder = ctx.getMslEncoderFactory();
            var formats = (capabilities) ? capabilities.encoderFormats : null;
            var format = encoder.getPreferredFormat(formats);

            // Perform key exchange.
            performKeyExchange(ctx, format, requestHeader, entityAuthData, masterToken, {
                result: function(keyExchangeData) {
                    AsyncExecutor(callback, function() {
                        // If we successfully performed key exchange, use the new master
                        // token for user authentication.
                        var userAuthMasterToken = (keyExchangeData)
                            ? keyExchangeData.keyResponseData.masterToken
                            : userAuthMasterToken = masterToken;

                        // Grab the local entity authentication data.
                        ctx.getEntityAuthenticationData(null, {
                            result: function(entityAuthData) {
                                AsyncExecutor(callback, function() {
                                    // Grab the user ID token for this response.
                                    getUserIdToken(ctx, requestHeader, userAuthMasterToken, {
                                        result: function(token) {
                                            AsyncExecutor(callback, function() {
                                                userIdToken = token;
                                                
                                                // Create the message builder.
                                                //
                                                // Peer-to-peer responses swap the tokens.
                                                var keyResponseData = requestHeader.keyResponseData;
                                                var serviceTokens = requestHeader.serviceTokens;
                                                if (ctx.isPeerToPeer()) {
                                                    var peerMasterToken = (keyResponseData) ? keyResponseData.masterToken : requestHeader.peerMasterToken;
                                                    var peerUserIdToken = requestHeader.peerUserIdToken;
                                                    var peerServiceTokens = requestHeader.peerServiceTokens;
                                                    return new MessageBuilder(ctx, recipient, messageId, capabilities, entityAuthData, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, keyExchangeData);
                                                } else {
                                                    var localMasterToken = (keyResponseData) ? keyResponseData.masterToken : masterToken;
                                                    return new MessageBuilder(ctx, recipient, messageId, capabilities, entityAuthData, localMasterToken, userIdToken, serviceTokens, null, null, null, keyExchangeData);
                                                }
                                            });
                                        },
                                        error: handleError,
                                    });
                                });
                            },
                            error: handleError,
                        });
                    });
                },
                error: handleError,
            });

            function handleError(e) {
                AsyncExecutor(callback, function() {
                    if (e instanceof MslException) {
                        e.setMasterToken(masterToken);
                        e.setEntityAuthenticationData(entityAuthData);
                        e.setUserIdToken(userIdToken);
                        e.setUserAuthenticationData(userAuthData);
                        e.setMessageId(requestMessageId);
                    }
                    throw e;
                });
            }
        });
    };

    /**
     * <p>Create a new message builder that will craft a new error message in
     * response to another message. If the message ID of the request is not
     * specified (i.e. unknown) then a random message ID will be generated.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {?string} recipient error response recipient. May be null.
     * @param {?number} requestMessageId message ID of request. May be null.
     * @param {MslError} error the MSL error.
     * @param {string} userMessage localized user-consumable error message. May be null.
     * @param {{result: function(ErrorHeader), error: function(Error)}}
     *        callback the callback that will receive the error header or any
     *        thrown exceptions.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data was
     *         returned by the MSL context.
     */
    var MessageBuilder$createErrorResponse = function MessageBuilder$createErrorResponse(ctx, recipient, requestMessageId, error, userMessage, callback) {
        AsyncExecutor(callback, function() {
            ctx.getEntityAuthenticationData(null, {
                result: function(entityAuthData) {
                    AsyncExecutor(callback, function() {
                        // If we have the request message ID then the error response message ID
                        // must be equal to the request message ID + 1.
                        var messageId;
                        if (requestMessageId != undefined && requestMessageId != null) {
                            messageId = MessageBuilder$incrementMessageId(requestMessageId);
                        }
                        // Otherwise use a random message ID.
                        else {
                            messageId = MslUtils.getRandomLong(ctx);
                        }
                        var errorCode = error.responseCode;
                        var internalCode = error.internalCode;
                        var errorMsg = error.message;
                        ErrorHeader.create(ctx, entityAuthData, recipient, messageId, errorCode, internalCode, errorMsg, userMessage, callback);
                    });
                },
                error: function(e) { callback.error(e); }
            });
        });
    };

    var MessageBuilder = module.exports = Class.create({
        /**
         * Create a new message builder with the provided tokens and key exchange
         * data if a master token was issued or renewed.
         *
         * @param {MslContext} ctx MSL context.
         * @param {?string} recipient message recipient. May be null.
         * @param {number} messageId message ID.
         * @param {MessageCapabilities} message capabilities.
         * @param {EntityAuthenticationData} entityAuthData entity
         *        authentication data.
         * @param {MsaterToken} masterToken master token. May be null unless a user ID token is
         *        provided.
         * @param {UserIdToken} userIdToken user ID token. May be null.
         * @param {Array.<ServiceToken>} serviceTokens initial set of service tokens. May be null.
         * @param {MasterToken }peerMasterToken peer master token. May be null unless a peer user
         *        ID token is provided.
         * @param {UserIdToken} peerUserIdToken peer user ID token. May be null.
         * @param {Array.<ServiceToken>} peerServiceTokens initial set of peer service tokens.
         *        May be null.
         * @param {KeyExchangeData} keyExchangeData key exchange data. May be null.
         * @param {{result: function(MessageBuilder), error: function(Error)}}
         *        callback the callback that will receive this message builder
         *        or any thrown exceptions.
         * @throws MslException if a user ID token is not bound to its master
         *         token.
         */
        init: function init(ctx, recipient, messageId, capabilities, entityAuthData, masterToken, userIdToken, serviceTokens, peerMasterToken, peerUserIdToken, peerServiceTokens, keyExchangeData) {
            // Primary and peer token combinations will be verified when the
            // message header is constructed. So delay those checks in favor of
            // avoiding duplicate code.
            if (!ctx.isPeerToPeer() && (peerMasterToken || peerUserIdToken))
                throw new MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");

            // If key exchange data is provided and we are not in peer-to-peer mode
            // then its master token should be used for querying service tokens.
            var serviceMasterToken;
            if (keyExchangeData && !ctx.isPeerToPeer()) {
                serviceMasterToken = keyExchangeData.keyResponseData.masterToken;
            } else {
                serviceMasterToken = masterToken;
            }

            // Set the initial service tokens based on the MSL store and provided
            // service tokens.
            var _serviceTokens = {};
            var tokens = ctx.getMslStore().getServiceTokens(serviceMasterToken, userIdToken);
            tokens.forEach(function(token) {
                _serviceTokens[token.name] = token;
            }, this);
            if (serviceTokens) {
                serviceTokens.forEach(function(token) {
                    _serviceTokens[token.name] = token;
                }, this);
            }

            // Set the peer-to-peer data.
            var _peerMasterToken;
            var _peerUserIdToken;
            var _peerServiceTokens = {};
            if (ctx.isPeerToPeer()) {
                _peerMasterToken = peerMasterToken;
                _peerUserIdToken = peerUserIdToken;

                // If key exchange data is provided then its master token should
                // be used to query peer service tokens.
                var peerServiceMasterToken;
                if (keyExchangeData)
                    peerServiceMasterToken = keyExchangeData.keyResponseData.masterToken;
                else
                    peerServiceMasterToken = peerMasterToken;

                // Set the initial peer service tokens based on the MSL store and
                // provided peer service tokens.
                var peerTokens = ctx.getMslStore().getServiceTokens(peerServiceMasterToken, peerUserIdToken);
                peerTokens.forEach(function(peerToken) {
                    _peerServiceTokens[peerToken.name] = peerToken;
                }, this);
                if (peerServiceTokens) {
                    peerServiceTokens.forEach(function(peerToken) {
                        _peerServiceTokens[peerToken.name] = peerToken;
                    }, this);
                }
            }

            // Set the primary fields.
            var _ctx = ctx;
            var _recipient = recipient;
            var _messageId = messageId;
            var _capabilities = capabilities;
            var _entityAuthData = entityAuthData;
            var _masterToken = masterToken;
            var _userIdToken = userIdToken;
            var _keyExchangeData = keyExchangeData;

            // Set default field values.
            var _nonReplayable = false;
            var _renewable = false;
            var _handshake = false;
            var _userAuthData = null;
            var _keyRequestData = {};

            // The properties.
            var props = {
                // MSL context.
                /** @type {MslContext} */
                _ctx: { value: _ctx, writable: false, enumerable: false, configurable: false },

                // Private members.
                /** @type {EntityAuthenticationData} */
                _entityAuthData: { value: _entityAuthData, writable: false, enumerable: false, configurable: false },
                /** @type {MasterToken} */
                _masterToken: { value: _masterToken, writable: true, enumerable: false, configurable: false },
                /** @type {string} */
                _recipient: { value: _recipient, writable: false, enumerable: false, configurable: false },
                /** @type {number} */
                _messageId: { value: _messageId, writable: false, enumerable: false, configurable: false },
                /** @type {MessageCapabilities} */
                _capabilities: { value: _capabilities, writable: false, enumerable: false, configurable: false },
                /** @type {KeyExchangeData} */
                _keyExchangeData: { value: _keyExchangeData, writable: false, enumerable: false, configurable: false },

                /** @type {boolean} */
                _nonReplayable: { value: _nonReplayable, writable: true, enumerable: false, configurable: false },
                /** @type {boolean} */
                _handshake: { value: _handshake, writable: true, enumerable: false, configurable: false },

                /** @type {boolean} */
                _renewable: { value: _renewable, writable: true, enumerable: false, configurable: false },
                /** @type {KeyRequestData} */
                _keyRequestData:{ value: _keyRequestData, writable: false, enumerable: false, configurable: false },
                /** @type {UserAuthenticationData} */
                _userAuthData: { value: _userAuthData, writable: true, enumerable: false, configurable: false },
                /** @type {UserIdToken} */
                _userIdToken: { value: _userIdToken, writable: true, enumerable: false, configurable: false },
                /** @type {Object.<name,ServiceToken>} */
                _serviceTokens: { value: _serviceTokens, writable: false, enumerable: false, configurable: false },

                /** @type {MasterToken} */
                _peerMasterToken: { value: _peerMasterToken, writable: true, enumerable: false, configurable: false },
                /** @type {UserIdToken} */
                _peerUserIdToken: { value: _peerUserIdToken, writable: true, enumerable: false, configurable: false },
                /** @type {Object.<name,ServiceToken>} */
                _peerServiceTokens: { value: _peerServiceTokens, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {number} the message ID the builder will use.
         */
        getMessageId: function getMessageId() {
            return this._messageId;
        },

        /**
         * @return {MasterToken} the primary master token or null if the message will use entity
         *         authentication data.
         */
        getMasterToken: function getMasterToken() {
            return this._masterToken;
        },

        /**
         * @return {UserIdToken} the primary user ID token or null if the message will use user
         *         authentication data.
         */
        getUserIdToken: function getUserIdToken() {
            return this._userIdToken;
        },

        /**
         * @return {KeyExchangeData} the key exchange data or null if there is none.
         */
        getKeyExchangeData: function getKeyExchangeData() {
            return this._keyExchangeData;
        },

        /**
         * @return {boolean} true if the message builder will create a message capable of
         *        encrypting the header data.
         */
        willEncryptHeader: function willEncryptHeader() {
            return (this._masterToken || this._entityAuthData.scheme.encrypts);
        },

        /**
         * @return {boolean} true if the message builder will create a message capable of
         *        encrypting the payload data.
         */
        willEncryptPayloads: function willEncryptPayloads() {
            return (this._masterToken ||
                    (!this._ctx.isPeerToPeer() && this._keyExchangeData) ||
                    this._entityAuthData.scheme.encrypts);
        },

        /**
         * @return {boolean} true if the message builder will create a message capable of
         *         integrity protecting the header data.
         */
        willIntegrityProtectHeader: function willIntegrityProtectHeader() {
            return (this._masterToken || this._entityAuthData.scheme.protectsIntegrity);
        },

        /**
         * @return {boolean} true if the message builder will create a message capable of
         *         integrity protecting the payload data.
         */
        willIntegrityProtectPayloads: function willIntegrityProtectPayloads() {
            return (this._masterToken ||
                (!this._ctx.isPeerToPeer() && this._keyExchangeData) ||
                this._entityAuthData.scheme.protectsIntegrity);
        },

        /**
         * Construct the message header from the current message builder state.
         *
         * @param {{result: function(MessageHeader), error: function(Error)}}
         *        callback the callback that will receive the message header or
         *        any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the message.
         * @throws MslMasterTokenException if the header master token is not
         *         trusted and needs to be to accept this message header.
         * @throws MslEntityAuthException if there is an error with the entity
         *         authentication data.
         * @throws MslMessageException if the message is non-replayable but does
         *         not include a master token.
         * @throws MslException should not happen.
         */
        getHeader: function getHeader(callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                var response = (this._keyExchangeData) ? this._keyExchangeData.keyResponseData : null;
                var tokens = [];
                for (var name in this._serviceTokens)
                    tokens.push(this._serviceTokens[name]);
                var keyRequests = [];
                for (var key in this._keyRequestData)
                    keyRequests.push(this._keyRequestData[key]);
                var nonReplayableId;
                if (this._nonReplayable) {
                    if (!this._masterToken)
                        throw new MslMessageException(MslError.NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN);
                    nonReplayableId = this._ctx.getMslStore().getNonReplayableId(this._masterToken);
                } else {
                    nonReplayableId = null;
                }
                var headerData = new MessageHeader.HeaderData(this._recipient, this._messageId, nonReplayableId, this._renewable, this._handshake, this._capabilities, keyRequests, response, this._userAuthData, this._userIdToken, tokens);
                var peerTokens = [];
                for (var peerName in this._peerServiceTokens)
                    peerTokens.push(this._peerServiceTokens[peerName]);
                var peerData = new MessageHeader.HeaderPeerData(this._peerMasterToken, this._peerUserIdToken, peerTokens);
                MessageHeader.create(this._ctx, this._entityAuthData, this._masterToken, headerData, peerData, callback);
            }, self);
        },

        /**
         * @return {boolean} true if the message will be marked non-replayable.
         */
        isNonReplayable: function isNonReplayable() {
            return this._nonReplayable;
        },

        /**
         * Make the message non-replayable. If true this will also set the
         * handshake flag to false.
         *
         * @param {boolean} nonReplayable true if the message should be non-replayable.
         * @return this.
         * @see #setHandshake(boolean)
         */
        setNonReplayable: function setNonReplayable(nonReplayable) {
            this._nonReplayable = nonReplayable;
            if (this._nonReplayable)
                this._handshake = false;
            return this;
        },

        /**
         * @return {boolean} true if the message will be marked renewable.
         */
        isRenewable: function isRenewable() {
            return this._renewable;
        },

        /**
         * Set the message renewable flag. If false this will also set the
         * handshake flag to false.
         *
         * @param {boolean} renewable true if the message is renewable.
         * @return {MessageBuilder} this.
         */
        setRenewable: function setRenewable(renewable) {
            this._renewable = renewable;
            if (!this._renewable)
                this._handshake = false;
            return this;
        },

        /**
         * @return {boolean} true if the message will be marked as a handshake message.
         */
        isHandshake: function isHandshake() {
            return this._handshake;
        },

        /**
         * Set the message handshake flag. If true this will also set the non-
         * replayable flag to false and the renewable flag to true.
         *
         * @param {boolean} handshake true if the message is a handshake message.
         * @return {MessageBuilder} this.
         * @see #setNonReplayable(boolean)
         * @see #setRenewable(boolean)
         */
        setHandshake: function setHandshake(handshake) {
            this._handshake = handshake;
            if (this._handshake) {
                this._nonReplayable = false;
                this._renewable = true;
            }
            return this;
        },

        /**
         * <p>Set or change the master token and user ID token. This will overwrite
         * any existing tokens. If the user ID token is not null then any existing
         * user authentication data will be removed.</p>
         *
         * <p>Changing these tokens may result in invalidation of existing service
         * tokens. Those service tokens will be removed from the message being
         * built.</p>
         *
         * <p>This is a special method for the {@link MslControl} class that assumes
         * the builder does not have key response data in trusted network mode.</p>
         *
         * @param {MasterToken} masterToken the master token.
         * @param {UserIdToken} userIdToken the user ID token. May be null.
         */
        setAuthTokens: function setAuthTokens(masterToken, userIdToken) {
            // Make sure the assumptions hold. Otherwise a bad message could be
            // built.
            if (userIdToken && !userIdToken.isBoundTo(masterToken))
                throw new MslInternalException("User ID token must be bound to master token.");
            // In trusted network mode key exchange data should only exist if this
            // is a server response. In which case this method should not be
            // getting called.
            if (this._keyExchangeData && !this._ctx.isPeerToPeer())
                throw new MslInternalException("Attempt to set message builder master token when key exchange data exists as a trusted network server.");

            // Load the stored service tokens.
            var storedTokens;
            try {
                storedTokens = this._ctx.getMslStore().getServiceTokens(masterToken, userIdToken);
            } catch (e) {
                // This should never happen because we did not provide a user ID
                // token.
                if (e instanceof MslException)
                    throw new MslInternalException("Invalid master token and user ID token combination despite checking above.", e);
                throw e;
            }

            // Remove any service tokens that will no longer be bound.
            var tokens = [];
            for (var name in this._serviceTokens)
                tokens.push(this._serviceTokens[name]);
            tokens.forEach(function(token) {
                if (token.isUserIdTokenBound() && !token.isBoundTo(userIdToken) ||
                    token.isMasterTokenBound() && !token.isBoundTo(masterToken))
                {
                    delete this._serviceTokens[token.name];
                }
            }, this);

            // Add any service tokens based on the MSL store replacing ones already
            // set as they may be newer. The application will have a chance to
            // manage the service tokens before the message is constructed and
            // sent.
            storedTokens.forEach(function(token) {
                this._serviceTokens[token.name] = token;
            }, this);

            // Set the new authentication tokens.
            this._masterToken = masterToken;
            this._userIdToken = userIdToken;
        },

        /**
         * <p>Set the user authentication data of the message.</p>
         *
         * <p>This will overwrite any existing user authentication data.</p>
         *
         * @param {UserAuthenticationData} userAuthData user authentication data to set. May be null.
         * @return {MessageBuilder} this.
         */
        setUserAuthenticationData: function setUserAuthenticationData(userAuthData) {
            this._userAuthData = userAuthData;
            return this;
        },

        /**
         * <p>Set the remote user of the message. This will create a user ID
         * token in trusted network mode or peer user ID token in peer-to-peer mode.</p>
         *
         * <p>Adding a new user ID token will not impact the service tokens; it is
         * assumed that no service tokens exist that are bound to the newly created
         * user ID token.</p>
         *
         * <p>This is a special method for the {@link MslControl} class that assumes
         * the builder does not already have a user ID token for the remote user
         * and does have a master token that the new user ID token can be bound
         * against.</p>
         *
         * @param {MslUser} user remote user.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true on completion or any thrown
         *        exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslException if there is an error creating the user ID token.
         */
        setUser: function setUser(user, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Make sure the assumptions hold. Otherwise a bad message could be
                // built.
                if (!this._ctx.isPeerToPeer() && this._userIdToken != null ||
                        this._ctx.isPeerToPeer() && this._peerUserIdToken != null)
                {
                    throw new MslInternalException("User ID token or peer user ID token already exists for the remote user.");
                }

                // If key exchange data is provided then its master token should be
                // used for the new user ID token and for querying service tokens.
                var uitMasterToken;
                if (this._keyExchangeData) {
                    uitMasterToken = this._keyExchangeData.keyResponseData.masterToken;
                } else {
                    uitMasterToken = (!this._ctx.isPeerToPeer()) ? this._masterToken : this._peerMasterToken;
                }

                // Make sure we have a master token to create the user for.
                if (!uitMasterToken)
                    throw new MslInternalException("User ID token or peer user ID token cannot be created because no corresponding master token exists.");

                // Create the new user ID token.
                var factory = this._ctx.getTokenFactory();
                factory.createUserIdToken(this._ctx, user, uitMasterToken, {
                    result: function(userIdToken) {
                        AsyncExecutor(callback, function() {
                            // Set the new user ID token.
                            if (!this._ctx.isPeerToPeer()) {
                                this._userIdToken = userIdToken;
                                this._userAuthData = null;
                            } else {
                                this._peerUserIdToken = userIdToken;
                            }

                            // Success.
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Add key request data to the message.
         *
         * @param {KeyRequestData} keyRequestData key request data to add.
         * @return {MessageBuilder} this.
         */
        addKeyRequestData: function addKeyRequestData(keyRequestData) {
            this._keyRequestData[keyRequestData.uniqueKey()] = keyRequestData;
            return this;
        },

        /**
         * Remove key request data from the message.
         *
         * @param {KeyRequestData} keyRequestData key request data to remove.
         * @return {MessageBuilder} this.
         */
        removeKeyRequestData: function removeKeyRequestData(keyRequestData) {
            delete this._keyRequestData[keyRequestData.uniqueKey()];
            return this;
        },

        /**
         * <p>Add a service token to the message. This will overwrite any service
         * token with the same name.</p>
         *
         * <p>Adding a service token with empty data indicates the recipient should
         * delete the service token.</p>
         *
         * @param {ServiceToken} serviceToken service token to add.
         * @return {MessageBuilder} this.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the primary master token or primary user ID token of the
         *         message being built.
         */
        addServiceToken: function addServiceToken(serviceToken) {
            // If key exchange data is provided and we are not in peer-to-peer mode
            // then its master token should be used for querying service tokens.
            var serviceMasterToken;
            if (this._keyExchangeData && !this._ctx.isPeerToPeer()) {
                serviceMasterToken = this._keyExchangeData.keyResponseData.masterToken;
            } else {
                serviceMasterToken = this._masterToken;
            }

            // Make sure the service token is properly bound.
            if (serviceToken.isMasterTokenBound() && !serviceToken.isBoundTo(serviceMasterToken))
                throw new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st " + serviceToken + "; mt " + serviceMasterToken).setMasterToken(serviceMasterToken);
            if (serviceToken.isUserIdTokenBound() && !serviceToken.isBoundTo(this._userIdToken))
                throw new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st " + serviceToken + "; uit " + this._userIdToken).setMasterToken(serviceMasterToken).setUserIdToken(this._userIdToken);

            // Add the service token.
            this._serviceTokens[serviceToken.name] = serviceToken;
            return this;
        },

        /**
         * <p>Add a service token to the message if a service token with the same
         * name does not already exist.</p>
         *
         * <p>Adding a service token with empty data indicates the recipient should
         * delete the service token.</p>
         *
         * @param {ServiceToken} serviceToken service token to add.
         * @return {MessageBuilder} this.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the master token or user ID token of the message being
         *         built.
         */
        addServiceTokenIfAbsent: function addServiceTokenIfAbsent(serviceToken) {
            if (!this._serviceTokens[serviceToken.name])
                this.addServiceToken(serviceToken);
            return this;
        },

        /**
         * <p>Exclude a service token from the message.</p>
         *
         * <p>The service token will not be sent in the built message. This is not
         * the same as requesting the remote entity delete a service token.</p>
         *
         * @param {string} name service token name.
         * @return {MessageBuilder} this.
         */
        excludeServiceToken: function excludeServiceToken(name) {
            delete this._serviceTokens[name];
            return this;
        },

        /**
         * <p>Mark a service token for deletion, if it exists. Otherwise this
         * method does nothing.</p>
         *
         * <p>The service token will be sent in the built message with an empty
         * value. This is not the same as requesting that a service token be
         * excluded from the message.</p>
         *
         * @param {string} name service token name.
         * @param {{result: function(MessageBuilder), error: function(Error)}}
         *        callback the callback that will receive this message builder
         *        upon completion or any thrown exceptions.
         */
        deleteServiceToken: function deleteServiceToken(name, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Do nothing if the original token does not exist.
                var originalToken = this._serviceTokens[name];
                if (!originalToken)
                    return this;

                // Rebuild the original token with empty service data.
                var masterToken = originalToken.isMasterTokenBound() ? this._masterToken : null;
                var userIdToken = originalToken.isUserIdTokenBound() ? this._userIdToken : null;
                ServiceToken.create(this._ctx, name, EMPTY_DATA, masterToken, userIdToken, false, null, new NullCryptoContext(), {
                    result: function(token) {
                        AsyncExecutor(callback, function() {
                            return this.addServiceToken(token);
                        }, self);
                    },
                    error: function(e) {
                        if (e instanceof MslException)
                            e = new MslInternalException("Failed to create and add empty service token to message.", e);
                        callback.error(e);
                    }
                });
            }, self);
        },

        /**
         * @return {Array.<ServiceToken>} the unmodifiable set of service tokens that will be included in
         *         the built message.
         */
        getServiceTokens: function getServiceTokens() {
            var tokens = [];
            for (var name in this._serviceTokens)
                tokens.push(this._serviceTokens[name]);
            return tokens;
        },

        /**
         * @return {MasterToken} the peer master token or null if there is none.
         */
        getPeerMasterToken: function getPeerMasterToken() {
            return this._peerMasterToken;
        },

        /**
         * @return {UserIdToken} the peer user ID token or null if there is none.
         */
        getPeerUserIdToken: function getPeerUserIdToken() {
            return this._peerUserIdToken;
        },

        /**
         * <p>Set the peer master token and peer user ID token of the message. This
         * will overwrite any existing peer master token or peer user ID token.</p>
         *
         * <p>Changing these tokens may result in invalidation of existing peer
         * service tokens. Those peer service tokens will be removed from the
         * message being built.</p>
         *
         * @param {MasterToken} masterToken peer master token to set. May be null.
         * @param {UserIdToken} userIdToken peer user ID token to set. May be null.
         * @return {MessageBuilder} this.
         * @throws MslMessageException if the peer user ID token is not bound to
         *         the peer master token.
         */
        setPeerAuthTokens: function setPeerAuthTokens(masterToken, userIdToken) {
            if (!this._ctx.isPeerToPeer())
                throw new MslInternalException("Cannot set peer master token or peer user ID token when not in peer-to-peer mode.");
            if (userIdToken && !masterToken)
                throw new MslInternalException("Peer master token cannot be null when setting peer user ID token.");
            if (userIdToken && !userIdToken.isBoundTo(masterToken))
                throw new MslMessageException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit " + userIdToken + "; mt " + masterToken).setMasterToken(masterToken).setUserIdToken(userIdToken);

            // Load the stored peer service tokens.
            var storedTokens;
            try {
                storedTokens = this._ctx.getMslStore().getServiceTokens(masterToken, userIdToken);
            } catch (e) {
                // The checks above should have prevented any invalid master token,
                // user ID token combinations.
                if (e instanceof MslException)
                    throw new MslInternalException("Invalid peer master token and user ID token combination despite proper check.", e);
                throw e;
            }

            // Remove any peer service tokens that will no longer be bound.
            var names = Object.keys(this._peerServiceTokens);
            names.forEach(function(name) {
                var token = this._peerServiceTokens[name];
                if (token.isUserIdTokenBound() && !token.isBoundTo(userIdToken)) {
                    delete this._peerServiceTokens[name];
                    return;
                }
                if (token.isMasterTokenBound() && !token.isBoundTo(masterToken)) {
                    delete this._peerServiceTokens[name];
                    return;
                }
            }, this);

            // Add any peer service tokens based on the MSL store if they are not
            // already set (as a set one may be newer than the stored one).
            storedTokens.forEach(function(token) {
                var name = token.name;
                if (!this._peerServiceTokens[name])
                    this._peerServiceTokens[name] = token;
            }, this);

            // Set the new peer authentication tokens.
            this._peerUserIdToken = userIdToken;
            this._peerMasterToken = masterToken;
            return this;
        },

        /**
         * <p>Add a peer service token to the message. This will overwrite any peer
         * service token with the same name.</p>
         *
         * <p>Adding a service token with empty data indicates the recipient should
         * delete the service token.</p>
         *
         * @param {ServiceToken} serviceToken service token to add.
         * @return {MessageBuilder} this.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the peer master token or peer user ID token of the message
         *         being built.
         */
        addPeerServiceToken: function addPeerServiceToken(serviceToken) {
            if (!this._ctx.isPeerToPeer())
                throw new MslInternalException("Cannot set peer service tokens when not in peer-to-peer mode.");
            if (serviceToken.isMasterTokenBound() && !serviceToken.isBoundTo(this._peerMasterToken))
                throw new MslMessageException(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH, "st " + serviceToken + "; mt " + this._peerMasterToken).setMasterToken(this._peerMasterToken);
            if (serviceToken.isUserIdTokenBound() && !serviceToken.isBoundTo(this._peerUserIdToken))
                throw new MslMessageException(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH, "st " + serviceToken + "; uit " + this._peerUserIdToken).setMasterToken(this._peerMasterToken).setUserIdToken(this._peerUserIdToken);

            // Add the peer service token.
            this._peerServiceTokens[serviceToken.name] = serviceToken;
            return this;
        },

        /**
         * <p>Add a peer service token to the message if a peer service token with
         * the same name does not already exist.</p>
         *
         * <p>Adding a service token with empty data indicates the recipient should
         * delete the service token.</p>
         *
         * @param {ServiceToken} serviceToken service token to add.
         * @return {MessageBuilder} this.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the peer master token or peer user ID token of the message
         *         being built.
         */
        addPeerServiceTokenIfAbsent: function addPeerServiceTokenIfAbsent(serviceToken) {
            if (!this._peerServiceTokens[serviceToken.name])
                this.addPeerServiceToken(serviceToken);
            return this;
        },

        /**
         * <p>Exclude a peer service token from the message.</p>
         *
         * <p>The service token will not be sent in the built message. This is not
         * the same as requesting the remote entity delete a service token.</p>
         *
         * @param {string} name service token name.
         * @return {MessageBuilder} this.
         */
        excludePeerServiceToken: function excludePeerServiceToken(name) {
            delete this._peerServiceTokens[name];
            return this;
        },

        /**
         * <p>Mark a peer service token for deletion, if it exists. Otherwise this
         * method does nothing.</p>
         *
         * <p>The service token will be sent in the built message with an empty
         * value. This is not the same as requesting that a service token be
         * excluded from the message.</p>
         *
         * @param {string} name service token name.
         * @param {{result: function(MessageBuilder), error: function(Error)}}
         *        callback the callback that will receive this message builder
         *        upon completion or any thrown exceptions.
         */
        deletePeerServiceToken: function deletePeerServiceToken(name, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Do nothing if the original token does not exist.
                var originalToken = this._peerServiceTokens[name];
                if (!originalToken)
                    return this;

                // Rebuild the original token with empty service data.
                var peerMasterToken = originalToken.isMasterTokenBound() ? this._peerMasterToken : null;
                var peerUserIdToken = originalToken.isUserIdTokenBound() ? this._peerUserIdToken : null;
                ServiceToken.create(this._ctx, name, EMPTY_DATA, peerMasterToken, peerUserIdToken, false, null, new NullCryptoContext(), {
                    result: function(token) {
                        AsyncExecutor(callback, function() {
                            return this.addPeerServiceToken(token);
                        }, self);
                    },
                    error: function(e) {
                        if (e instanceof MslException)
                            e = new MslInternalException("Failed to create and add empty peer service token to message.", e);
                        callback.error(e);
                    }
                });
            }, self);
        },

        /**
         * @return {Array.<ServiceToken>} the unmodifiable set of peer service tokens that will be included in
         *         the built message.
         */
        getPeerServiceTokens: function getPeerServiceTokens() {
            var tokens = [];
            for (var name in this._peerServiceTokens)
                tokens.push(this._peerServiceTokens[name]);
            return tokens;
        },
    });
    
    // Exports.
    module.exports.incrementMessageId = MessageBuilder$incrementMessageId;
    module.exports.decrementMessageId = MessageBuilder$decrementMessageId;
    module.exports.createRequest = MessageBuilder$createRequest;
    module.exports.createResponse = MessageBuilder$createResponse;
    module.exports.createErrorResponse = MessageBuilder$createErrorResponse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageBuilder'));
