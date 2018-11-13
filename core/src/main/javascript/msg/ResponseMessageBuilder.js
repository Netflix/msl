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
 * <p>A message builder provides methods for building messages.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var MslConstants = require('../MslConstants.js');
    var MslInternalException = require('../MslInternalException.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslKeyExchangeException = require('../MslKeyExchangeException.js');
    var MslError = require('../MslError.js');
    var MslException = require('../MslException.js');
    var MslUserAuthException = require('../MslUserAuthException.js');
    var MessageCapabilities = require('../msg/MessageCapabilities.js');
    var ErrorHeader = require('../msg/ErrorHeader.js');
    var Class = require('../util/Class.js');
    var MslMessageException = require('../MslMessageException.js');
    var MessageBuilder = require('../msg/MessageBuilder.js');
    var MessageHeader = require('../msg/MessageHeader.js');
    var ServiceToken = require('../tokens/ServiceToken.js');
    var NullCryptoContext = require('../crypto/NullCryptoContext.js');
    var MslUtils = require('../util/MslUtils.js');

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
    };

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
            var tokenFactory = ctx.getTokenFactory();

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
                    factory.authenticate(ctx, masterToken.identity, userAuthData, null, {
                        result: function(user) {
                            tokenFactory.createUserIdToken(ctx, user, masterToken, callback);
                        },
                        error: callback.error,
                    });
                } else {
                    tokenFactory.createUserIdToken(ctx, user, masterToken, callback);
                }
                return;
            }

            // Otherwise return the header's user ID token (may be null).
            return userIdToken;
        });
    }

    var ResponseMessageBuilder = module.exports = MessageBuilder.extend({

        /**
         * Create a new message builder that will craft a new message in response
         * to another message. The constructed message may be used as a request.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageHeader} requestHeader message header to respond to.
         * @param {{result: function(ResponseMessageBuilder), error: function(Error)}}
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
        init: function init(ctx, requestHeader, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                var masterToken = requestHeader.masterToken;
                var entityAuthData = requestHeader.entityAuthenticationData;
                var userIdToken = requestHeader.userIdToken;
                var userAuthData = requestHeader.userAuthenticationData;

                // The response message ID must be equal to the request message ID + 1.
                var requestMessageId = requestHeader.messageId;
                var messageId = MessageBuilder.incrementMessageId(requestMessageId);

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
                                                        this.initializeMessageBuilder(ctx, messageId, capabilities, entityAuthData, peerMasterToken, peerUserIdToken, peerServiceTokens, masterToken, userIdToken, serviceTokens, keyExchangeData);
                                                        return this;
                                                    } else {
                                                        var localMasterToken = (keyResponseData) ? keyResponseData.masterToken : masterToken;
                                                        this.initializeMessageBuilder(ctx, messageId, capabilities, entityAuthData, localMasterToken, userIdToken, serviceTokens, null, null, null, keyExchangeData);
                                                        return this;
                                                    }
                                                }, self);
                                            },
                                            error: handleError,
                                        });
                                    }, self);
                                },
                                error: handleError,
                            });
                        }, self);
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
                    }, self);
                }
            }, self);
        }
    });

    /**
     * Create a new message builder that will craft a new message in response
     * to another message. The constructed message may be used as a request.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MessageHeader} requestHeader message header to respond to.
     * @param {{result: function(ResponseMessageBuilder), error: function(Error)}}
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
    var ResponseMessageBuilder$create = function ResponseMessageBuilder$create(ctx, requestHeader, callback) {
        new ResponseMessageBuilder(ctx, requestHeader, callback);
    };

    // Exports.
    module.exports.create = ResponseMessageBuilder$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('ResponseMessageBuilder'));
