/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
 * <p>If a master token exists, the header data chunks will be encrypted and
 * verified using the master token. If no master token exists, the header data
 * will be verified and encrypted based on the entity authentication
 * scheme.</p>
 *
 * <p>If peer tokens exist, the message recipient is expected to use the peer
 * master token to secure its response and send the peer user ID token and peer
 * service tokens back in the header data. The request's tokens should be
 * included as the response's peer tokens.</p>
 *
 * <p>If key response data exists, it applies to the token set the receiving
 * entity uses to identify itself. In a trusted services network the key
 * response data applies to the primary tokens. In a peer-to-peer network the
 * key response data applies to the peer tokens.</p>
 *
 * <p>The header data is represented as
 * {@code
 * headerdata = {
 *   "#mandatory" : [ "messageid", "renewable", "handshake" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "nonreplayableid" : "int64(0,2^53^)",
 *   "renewable" : "boolean",
 *   "handshake" : "boolean",
 *   "capabilities" : capabilities,
 *   "keyrequestdata" : [ keyrequestdata ],
 *   "keyresponsedata" : keyresponsedata,
 *   "userauthdata" : userauthdata,
 *   "useridtoken" : useridtoken,
 *   "servicetokens" : [ servicetoken ],
 *   "peermastertoken" : mastertoken,
 *   "peeruseridtoken" : useridtoken,
 *   "peerservicetokens" : [ servicetoken ]
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code nonreplayableid} is the non-replayable ID</li>
 * <li>{@code renewable} indicates if the master token and user ID are renewable</li>
 * <li>{@code handshake} indicates a handshake message</li>
 * <li>{@code capabilities} lists the sender's message capabilities</li>
 * <li>{@code keyrequestdata} is session key request data</li>
 * <li>{@code keyresponsedata} is the session key response data</li>
 * <li>{@code userauthdata} is the user authentication data</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * <li>{@code servicetokens} are the service tokens</li>
 * <li>{@code peermastertoken} is the peer master token</li>
 * <li>{@code peeruseridtoken} is the peer user ID token</li>
 * <li>{@code peerservicetokens} are the peer service tokens</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
	var MslMasterTokenException = require('../MslMasterTokenException.js');
	var MslError = require('../MslError.js');
	var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');
	var MslEntityAuthException = require('../MslEntityAuthException.js');
	var MslEncodable = require('../io/MslEncodable.js');
	var MslEncoderUtils = require('../io/MslEncoderUtils.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslConstants = require('../MslConstants.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var Header = require('../msg/Header.js');
	var UserAuthenticationData = require('../userauth/UserAuthenticationData.js');
	var ServiceToken = require('../tokens/ServiceToken.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var UserIdToken = require('../tokens/UserIdToken.js');
	var KeyRequestData = require('../keyx/KeyRequestData.js');
	var KeyResponseData = require('../keyx/KeyResponseData.js');
	var MslMessageException = require('../MslMessageException.js');
	var MslException = require('../MslException.js');
	var Base64 = require('../util/Base64.js');
	var MessageCapabilities = require('../msg/MessageCapabilities.js');
	var MslUserAuthException = require('../MslUserAuthException.js');
	
    /** Milliseconds per second. */
    var MILLISECONDS_PER_SECOND = 1000;
    
    // Message header data.
    /**
     * Key sender.
     * @const
     * @type {string}
     */
    var KEY_SENDER = "sender";
    /**
     * Key timestamp.
     * @const
     * @type {number}
     */
    var KEY_TIMESTAMP = "timestamp";
    /**
     * Key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * Key non-replayable ID.
     * @const
     * @type {string}
     */
    var KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    /**
     * Key non-replayable flag.
     * @const
     * @type {string}
     */
    var KEY_NON_REPLAYABLE = "nonreplayable";
    /**
     * Key renewable flag.
     * @const
     * @type {string}
     */
    var KEY_RENEWABLE = "renewable";
    /**
     * Key handshake flag.
     * @const
     * @type {string}
     */
    var KEY_HANDSHAKE = "handshake";
    /**
     * Key capabilities.
     * @const
     * @type {string}
     */
    var KEY_CAPABILITIES = "capabilities";
    /**
     * Key key exchange request.
     * @const
     * @type {string}
     */
    var KEY_KEY_REQUEST_DATA = "keyrequestdata";
    /**
     * Key key exchange response.
     * @const
     * @type {string}
     */
    var KEY_KEY_RESPONSE_DATA = "keyresponsedata";
    /**
     * Key user authentication data.
     * @const
     * @type {string}
     */
    var KEY_USER_AUTHENTICATION_DATA = "userauthdata";
    /**
     * Key user ID token.
     * @const
     * @type {string}
     */
    var KEY_USER_ID_TOKEN = "useridtoken";
    /**
     * Key service tokens.
     * @const
     * @type {string}
     */
    var KEY_SERVICE_TOKENS = "servicetokens";

    // Message header peer data.
    /**
     * Key peer master token.
     * @const
     * @type {string}
     */
    var KEY_PEER_MASTER_TOKEN = "peermastertoken";
    /**
     * Key peer user ID token.
     * @const
     * @type {string}
     */
    var KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
    /**
     * Key peer service tokens.
     * @const
     * @type {string}
     */
    var KEY_PEER_SERVICE_TOKENS = "peerservicetokens";

    /**
     * Container struct for message header data.
     */
    var HeaderData = Class.create({
        /**
         * @param {number} messageId the message ID.
         * @param {?number} nonReplayableId the message's non-replayable ID. May be null.
         * @param {boolean} renewable the message's renewable flag.
         * @param {boolean} handshake the message's handshake flag.
         * @param {MessageCapabilities} capabilities the sender's message capabilities.
         * @param {?Array.<KeyRequestData>} keyRequestData session key request data. May be null or
         *        empty.
         * @param {?KeyResponseData} keyResponseData session key response data. May be null.
         * @param {?UserAuthenticationData} userAuthData the user authentication data. May be null if a
         *        user ID token is provided or there is no user authentication
         *        for this message.
         * @param {?UserIdToken} userIdToken the user ID token. May be null if user
         *        authentication data is provided or there is no user
         *        authentication for this message.
         * @param {?Array.<ServiceToken>} serviceTokens the service tokens. May be null or empty.
         */
        init: function init(messageId, nonReplayableId,
            renewable, handshake,
            capabilities,
            keyRequestData, keyResponseData,
            userAuthData, userIdToken,
            serviceTokens)
        {
            // The properties.
            var props = {
                messageId: { value: messageId, writable: false, configurable: false },
                nonReplayableId: { value: nonReplayableId, writable: false, configurable: false },
                renewable: { value: renewable, writable: false, configurable: false },
                handshake: { value: handshake, writable: false, configurable: false },
                capabilities: { value: capabilities, writable: false, configurable: false },
                keyRequestData: { value: keyRequestData, writable: false, configurable: false },
                keyResponseData: { value: keyResponseData, writable: false, configurable: false },
                userAuthData: { value: userAuthData, writable: false, configurable: false },
                userIdToken: { value: userIdToken, writable: false, configurable: false },
                serviceTokens: { value: serviceTokens, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    });

    /**
     * Container struct for header peer data.
     */
    var HeaderPeerData = Class.create({
        /**
         * @param {MasterToken} peerMasterToken peer master token. May be null.
         * @param {UserIdToken} peerUserIdToken peer user ID token. May be null if there is
         *        no user authentication for the peer.
         * @param {Array.<ServiceToken>} peerServiceTokens peer service tokens. May be empty.
         */
        init: function init(peerMasterToken, peerUserIdToken, peerServiceTokens) {
            // The properties.
            var props = {
                peerMasterToken: { value: peerMasterToken, writable: false, configurable: false },
                peerUserIdToken: { value: peerUserIdToken, writable: false, configurable: false },
                peerServiceTokens: { value: peerServiceTokens, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    });

    /**
     * Create a new token data container object.
     *
     * @param {MslUser} user MSL user.
     * @param {number} timestampSeconds message timestamp in seconds since the epoch.
     * @param {ICryptoContext} messageCryptoContext message crypto context.
     * @param {MslObject} headerdata header data.
     * @constructor
     */
    function CreationData(user, timestampSeconds, messageCryptoContext, headerdata, plaintext, signature, verified) {
        this.user = user;
        this.timestampSeconds = timestampSeconds;
        this.messageCryptoContext = messageCryptoContext;
        this.headerdata = headerdata;
    }

    /**
     * Return a properties configuration for the provided property values.
     *
     * @param {MslContext} ctx
     * 
     * @param {EntityAuthenticationData} entityAuthData
     * @param {MasterToken} masterToken
     * @param {MslObject} headerdata
     * 
     * @param {number} timestampSeconds
     * @param {number} messageId
     * @param {number} nonReplayableId
     * @param {boolean} renewable
     * @param {boolean} handshake
     * @param {MessageCapabilities} capabilities
     * @param {Array.<KeyRequestData>} keyRequestData
     * @param {KeyResponseData} keyResponseData
     * @param {UserAuthenticationData} userAuthData
     * @param {UserIdToken} userIdToken
     * @param {Array.<ServiceToken>} serviceTokens
     * 
     * @param {MasterToken} peerMasterToken
     * @param {UserIdToken} peerUserIdToken
     * @param {Array.<ServiceToken>} peerServiceTokens
     * 
     * @param {MslUser} user
     * 
     * @param {ICryptoContext} messageCryptoContext
     * 
     * @return {object} the properties configuration.
     */
    function buildProperties(ctx, entityAuthData, masterToken, headerdata,
        timestampSeconds, messageId, nonReplayableId,
        renewable, handshake,
        capabilities, keyRequestData, keyResponseData,
        userAuthData, userIdToken,
        serviceTokens,
        peerMasterToken, peerUserIdToken, peerServiceTokens,
        user, messageCryptoContext)
    {
        // The properties.
        return {
            /**
             * Returns the entity authentication data. May be null if the entity has
             * already been authenticated and is using a master token instead.
             * @type {?EntityAuthenticationData}
             */
            entityAuthenticationData: { value: entityAuthData, writable: false, configurable: false },
            /**
             * Returns the primary master token identifying the entity and containing
             * the session keys. May be null if the entity has not been authenticated.
             * @type {?MasterToken}
             */
            masterToken: { value: masterToken, writable: false, configurable: false },
            /**
             * Header data.
             * @type {MslObject}
             */
            headerdata: { value: headerdata, writable: false, enumerable: false, configurable: false },
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
             * Non-replayable ID.
             * @type {?number}
             */
            nonReplayableId: { value: nonReplayableId, writable: false, configurable: false },
            /**
             * Renewable.
             * @type {boolean}
             */
            renewable: { value: renewable, writable: false, enumerable: false, configurable: false },
            /**
             * Handshake message.
             * @type {boolean}
             */
            handshake: { value: handshake, writable: false, enumerable: false, configurable: false },
            /**
             * Message capabilities.
             * @type {?MessageCapabilities}
             */
            messageCapabilities: { value: capabilities, writable: false, configurable: false },
            /**
             * Key request data.
             * @type {Array.<KeyRequestData>}
             */
            keyRequestData: { value: keyRequestData, writable: false, configurable: false },
            /**
             * Key response data.
             * @type {?KeyResponseData}
             */
            keyResponseData: { value: keyResponseData, writable: false, configurable: false },
            /**
             * Returns the user authentication data. May be null if the user has
             * already been authenticated and is using a user ID token or if there is
             * no user authentication requested.
             * @type {?UserAuthenticationData}
             */
            userAuthenticationData: { value: userAuthData, writable: false, configurable: false },
            /**
             * Returns the primary user ID token identifying the user. May be null if
             * the user has not been authenticated.
             * @type {?UserIdToken}
             */
            userIdToken: { value: userIdToken, writable: false, configurable: false },
            /**
             * Service tokens (immutable).
             * @type {Array.<ServiceToken>}
             */
            serviceTokens: { value: serviceTokens, writable: false, configurable: false },
            /**
             * Returns the master token that should be used by an entity responding to
             * this message. Will be null if the responding entity should use its own
             * entity authentication data or the primary master token.
             * @type {?MasterToken}
             */
            peerMasterToken: { value: peerMasterToken, writable: false, configurable: false },
            /**
             * Returns the user ID token that must be used by an entity responding to
             * this message if an peer master token is provided. May be null if peer
             * user authentication has not occurred. Will be null if there is no peer
             * master token.
             * @type {?UserIdToken}
             */
            peerUserIdToken: { value: peerUserIdToken, writable: false, configurable: false },
            /**
             * Returns the service tokens that must be used by an entity responding to
             * this message. May be null if the responding entity should use the
             * primary service tokens.
             * @type {?Array.<ServiceToken>}
             */
            peerServiceTokens: { value: peerServiceTokens, writable: false, configurable: false },
            /**
             * Returns the user if the user has been authenticated or a user ID
             * token was provided.
             * 
             * @return the user. May be null.
             * @type {?MslUser}
             */
            user: { value: user, writable: false, configurable: false },
            /**
             * Returns the crypto context that was used to process the header data.
             * This crypto context should also be used to process the payload data if
             * no key response data is included in the message.
             *
             * @return the header data crypto context.
             * @see #isEncrypting()
             * @type {ICryptoContext}
             */
            cryptoContext: { value: messageCryptoContext, writable: false, configurable: false },
            /**
             * Cached encodings.
             * @type {Object<MslEncoderFormat,Uint8Array>}
             */
            encodings: { value: {}, writable: false, enumerable: false, configurable: false },
        };
    }

    /**
     * Returns the crypto context that should be used for this message header.
     *
     * @param {MslContext} ctx MSL context.
     * @param {?EntityAuthenticationData} entityAuthData the entity
     *        authentication data. May be null if a master token is provided.
     * @param {MasterToken} masterToken the master token. May be null if
     *        entity authentication data is provided.
     * @return {ICryptoContext} the message crypto context.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    function getMessageCryptoContext(ctx, entityAuthData, masterToken) {
        if (masterToken) {
            // Use a stored master token crypto context if we have one.
            var cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);

            // If there was no stored crypto context try making one from
            // the master token. We can only do this if we can open up the
            // master token.
            if (!cachedCryptoContext) {
                if (!masterToken.isVerified() || !masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                return new SessionCryptoContext(ctx, masterToken);
            } else {
                return cachedCryptoContext;
            }
        } else {
            var scheme = entityAuthData.scheme;
            var factory = ctx.getEntityAuthenticationFactory(scheme);
            if (!factory)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name);
            return factory.getCryptoContext(ctx, entityAuthData);
        }
    }

    var MessageHeader = module.exports = MslEncodable.extend({
        /**
         * <p>Construct a new message header with the provided message data.</p>
         *
         * <p>Headers are encrypted and signed. If a master token is provided, it
         * will be used for this purpose. Otherwise the crypto context appropriate
         * for the entity authentication scheme will be used. N.B. Either the
         * entity authentication data or the master token must be provided.</p>
         *
         * <p>Peer tokens are only processed if operating in peer-to-peer mode.</p>
         *
         * @param {MslContext} ctx MSL context.
         * @param {EntityAuthenticationData} entityAuthData the entity authentication data. May be null if a
         *        master token is provided.
         * @param {MaterToken} masterToken the master token. May be null if entity
         *        authentication data is provided.
         * @param {HeaderData} headerData message header data container.
         * @param {HeaderPeerData} peerData message header peer data container.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(MessageHeader), error: function(Error)}}
         *        callback the callback functions that will receive the message
         *        header or any thrown exceptions.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the message.
         * @throws MslMasterTokenException if the header master token is not
         *         trusted and needs to be to accept this message header.
         * @throws MslEntityAuthException if there is an error with the entity
         *         authentication data.
         * @throws MslMessageException if no entity authentication data or master
         *         token is provided.
         */
        init: function init(ctx, entityAuthData, masterToken, headerData, peerData, creationData, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (creationData) {
                    // Ignore the sender.
                    prepare(null);
                } else {
                    // Older MSL stacks expect the sender if a master token is being used.
                    //
                    // If the local entity does not know its entity identity, then use the
                    // empty string. This will work except for the case where the old MSL
                    // stack is receiving a message for which it is also the issuer of the
                    // master token. That scenario will continue to fail.
                    if (masterToken) {
                        ctx.getEntityAuthenticationData(null, {
                            result: function(ead) {
                                AsyncExecutor(callback, function() {
                                    var localIdentity = ead.getIdentity();
                                    var sender = (localIdentity) ? localIdentity : "";
                                    prepare(sender);
                                }, self);
                            },
                            error: callback.error,
                        });
                    } else {
                        prepare(null);
                    }
                }
            }, self);

            function prepare(sender) {
                AsyncExecutor(callback, function() {
                    // Message ID must be within range.
                    if (headerData.messageId < 0 || headerData.messageId > MslConstants.MAX_LONG_VALUE)
                        throw new MslInternalException("Message ID " + headerData.messageId + " is out of range.");
    
                    // Message entity must be provided.
                    if (!entityAuthData && !masterToken)
                        throw new MslInternalException("Message entity authentication data or master token must be provided.");
                    
                    // Do not allow user authentication data to be included if the message
                    // will not be encrypted.
                    var encrypted;
                    if (masterToken) {
                        encrypted = true;
                    } else {
                        var scheme = entityAuthData.scheme;
                        encrypted = scheme.encrypts;
                    }
                    if (!encrypted && headerData.userAuthData)
                        throw new MslInternalException("User authentication data cannot be included if the message is not encrypted.");
                    
                    entityAuthData = (!masterToken) ? entityAuthData : null;
                    var nonReplayableId = headerData.nonReplayableId;
                    var renewable = headerData.renewable;
                    var handshake = headerData.handshake;
                    var capabilities = headerData.capabilities;
                    var messageId = headerData.messageId;
                    var keyRequestData = (headerData.keyRequestData) ? headerData.keyRequestData : [];
                    var keyResponseData = headerData.keyResponseData;
                    var userAuthData = headerData.userAuthData;
                    var userIdToken = headerData.userIdToken;
                    var serviceTokens = (headerData.serviceTokens) ? headerData.serviceTokens : [];
                    var peerMasterToken, peerUserIdToken, peerServiceTokens;
                    if (ctx.isPeerToPeer()) {
                        peerMasterToken = peerData.peerMasterToken;
                        peerUserIdToken = peerData.peerUserIdToken;
                        peerServiceTokens = (peerData.peerServiceTokens) ? peerData.peerServiceTokens : [];
                    } else {
                        peerMasterToken = null;
                        peerUserIdToken = null;
                        peerServiceTokens = [];
                    }
    
                    // Grab token verification master tokens.
                    var tokenVerificationMasterToken, peerTokenVerificationMasterToken;
                    if (keyResponseData) {
                        // The key response data is used for token verification in a
                        // trusted services network and peer token verification in a peer-
                        // to-peer network.
                        if (!ctx.isPeerToPeer()) {
                            tokenVerificationMasterToken = keyResponseData.masterToken;
                            peerTokenVerificationMasterToken = peerMasterToken;
                        } else {
                            tokenVerificationMasterToken = masterToken;
                            peerTokenVerificationMasterToken = keyResponseData.masterToken;
                        }
                    } else {
                        tokenVerificationMasterToken = masterToken;
                        peerTokenVerificationMasterToken = peerMasterToken;
                    }
    
                    // Check token combinations.
                    if (userIdToken && (!tokenVerificationMasterToken || !userIdToken.isBoundTo(tokenVerificationMasterToken)))
                        throw new MslInternalException("User ID token must be bound to a master token.");
                    if (peerUserIdToken && (!peerTokenVerificationMasterToken || !peerUserIdToken.isBoundTo(peerTokenVerificationMasterToken)))
                        throw new MslInternalException("Peer user ID token must be bound to a peer master token.");
    
                    // All service tokens must be unbound or if bound, bound to the
                    // provided tokens.
                    serviceTokens.forEach(function(serviceToken) {
                        if (serviceToken.isMasterTokenBound() && (!tokenVerificationMasterToken || !serviceToken.isBoundTo(tokenVerificationMasterToken)))
                            throw new MslInternalException("Master token bound service tokens must be bound to the provided master token.");
                        if (serviceToken.isUserIdTokenBound() && (!userIdToken || !serviceToken.isBoundTo(userIdToken)))
                            throw new MslInternalException("User ID token bound service tokens must be bound to the provided user ID token.");
                    }, this);
                    peerServiceTokens.forEach(function(peerServiceToken) {
                        if (peerServiceToken.isMasterTokenBound() && (!peerTokenVerificationMasterToken || !peerServiceToken.isBoundTo(peerTokenVerificationMasterToken)))
                            throw new MslInternalException("Master token bound peer service tokens must be bound to the provided peer master token.");
                        if (peerServiceToken.isUserIdTokenBound() && (!peerUserIdToken || !peerServiceToken.isBoundTo(peerUserIdToken)))
                            throw new MslInternalException("User ID token bound peer service tokens must be bound to the provided peer user ID token.");
                    }, this);

                    var encoder = ctx.getMslEncoderFactory();
                    var formats = (capabilities) ? capabilities.encoderFormats : null;
                    var format = encoder.getPreferredFormat(formats);
                    MslEncoderUtils.createArray(ctx, format, keyRequestData, {
                        result: function(maKeyRequestData) {
                            MslEncoderUtils.createArray(ctx, format, serviceTokens, {
                                result: function(maServiceTokens) {
                                    MslEncoderUtils.createArray(ctx, format, peerServiceTokens, {
                                        result: function(maPeerServiceTokens) {
                                            construct(maKeyRequestData, maServiceTokens, maPeerServiceTokens);
                                        },
                                        error: function(e) {
                                            AsyncExecutor(callback, function() {
                                                if (e instanceof MslEncoderException) {
                                                    throw new MslEncodingException(MslError.MSL_ENCODE_ERROR, "headerdata", e)
                                                        .setMasterToken(masterToken)
                                                        .setEntityAuthenticationData(entityAuthData)
                                                        .setUserIdToken(userIdToken)
                                                        .setUserAuthenticationData(userAuthData)
                                                        .setMessageId(messageId);
                                                }
                                                throw e;
                                            }, self);
                                        }
                                    });
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslEncoderException) {
                                            throw new MslEncodingException(MslError.MSL_ENCODE_ERROR, "headerdata", e)
                                                .setMasterToken(masterToken)
                                                .setEntityAuthenticationData(entityAuthData)
                                                .setUserIdToken(userIdToken)
                                                .setUserAuthenticationData(userAuthData)
                                                .setMessageId(messageId);
                                        }
                                        throw e;
                                    }, self);
                                }
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslEncoderException) {
                                    throw new MslEncodingException(MslError.MSL_ENCODE_ERROR, "headerdata", e)
                                        .setMasterToken(masterToken)
                                        .setEntityAuthenticationData(entityAuthData)
                                        .setUserIdToken(userIdToken)
                                        .setUserAuthenticationData(userAuthData)
                                        .setMessageId(messageId);
                                }
                                throw e;
                            }, self);
                        }
                    });
                
                    function construct(maKeyRequestData, maServiceTokens, maPeerServiceTokens) {
                        AsyncExecutor(callback, function() {
                            // Create the header data.
                            var user, timestampSeconds, headerdata, messageCryptoContext;
                            if (!creationData) {
                                // Grab the user.
                                user = (userIdToken) ? userIdToken.user : null;
                                
                                // Set the creation timestamp.
                                timestampSeconds = parseInt(ctx.getTime() / MILLISECONDS_PER_SECOND);
            
                                // Construct the header data.
                                try {
                                    headerdata = encoder.createObject();
                                    if (typeof sender === 'string') headerdata.put(KEY_SENDER, sender);
                                    headerdata.put(KEY_TIMESTAMP, timestampSeconds);
                                    headerdata.put(KEY_MESSAGE_ID, messageId);
                                    headerdata.put(KEY_NON_REPLAYABLE, (typeof nonReplayableId === 'number'));
                                    if (typeof nonReplayableId === 'number') headerdata.put(KEY_NON_REPLAYABLE_ID, nonReplayableId);
                                    headerdata.put(KEY_RENEWABLE, renewable);
                                    headerdata.put(KEY_HANDSHAKE, handshake);
                                    if (capabilities) headerdata.put(KEY_CAPABILITIES, capabilities);
                                    // FIXME
                                    if (keyRequestData.length > 0) headerdata.put(KEY_KEY_REQUEST_DATA, maKeyRequestData);
                                    if (keyResponseData) headerdata.put(KEY_KEY_RESPONSE_DATA, keyResponseData);
                                    if (userAuthData) headerdata.put(KEY_USER_AUTHENTICATION_DATA, userAuthData);
                                    if (userIdToken) headerdata.put(KEY_USER_ID_TOKEN, userIdToken);
                                    // FIXME
                                    if (serviceTokens.length > 0) headerdata.put(KEY_SERVICE_TOKENS, maServiceTokens);
                                    if (peerMasterToken) headerdata.put(KEY_PEER_MASTER_TOKEN, peerMasterToken);
                                    if (peerUserIdToken) headerdata.put(KEY_PEER_USER_ID_TOKEN, peerUserIdToken);
                                    // FIXME
                                    if (peerServiceTokens.length > 0) headerdata.put(KEY_PEER_SERVICE_TOKENS, maPeerServiceTokens);
                                } catch (e) {
                                    if (e instanceof MslEncoderException) {
                                        throw new MslEncodingException(MslError.MSL_ENCODE_ERROR, "headerdata", e)
                                            .setMasterToken(masterToken)
                                            .setEntityAuthenticationData(entityAuthData)
                                            .setUserIdToken(peerUserIdToken)
                                            .setUserAuthenticationData(userAuthData)
                                            .setMessageId(messageId);
                                    }
                                    throw e;
                                }
            
                                // Get the correct crypto context.
                                try {
                                    messageCryptoContext = getMessageCryptoContext(ctx, entityAuthData, masterToken);
                                } catch (e) {
                                    if (e instanceof MslException) {
                                        e.setMasterToken(masterToken);
                                        e.setEntityAuthenticationData(entityAuthData);
                                        e.setUserIdToken(userIdToken);
                                        e.setUserAuthenticationData(userAuthData);
                                        e.setMessageId(messageId);
                                    }
                                    throw e;
                                }
                            } else {
                                user = creationData.user;
                                timestampSeconds = creationData.timestampSeconds;
                                headerdata = creationData.headerdata;
                                messageCryptoContext = creationData.messageCryptoContext;
                            }
                            
                            // The properties.
                            var props = buildProperties(ctx, entityAuthData, masterToken, headerdata,
                                timestampSeconds, messageId, nonReplayableId,
                                renewable, handshake,
                                capabilities, keyRequestData, keyResponseData,
                                userAuthData, userIdToken,
                                serviceTokens,
                                peerMasterToken, peerUserIdToken, peerServiceTokens,
                                user, messageCryptoContext);
                            Object.defineProperties(this, props);
                            return this;
                        }, self);
                    }
                }, self);
            }
        },

        /**
        * @return {Date} gets the timestamp.
        */
        get timestamp() {
            return new Date(this.timestampSeconds * MILLISECONDS_PER_SECOND);
        },

        /**
         * @return {boolean} true if the message header crypto context provides encryption.
         * @see #getCryptoContext()
         */
        isEncrypting: function isEncrypting() {
            return this.masterToken || this.entityAuthenticationData.scheme.encrypts;
        },

        /**
         * @return {boolean} true if the message renewable flag is set.
         */
        isRenewable: function isRenewable() {
            return this.renewable;
        },
        
        /**
         * @return {boolean} true if the message handshake flag is set.
         */
        isHandshake: function isHandshake() {
            return this.handshake;
        },
        
        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // Encrypt and sign the headerdata.
                encoder.encodeObject(this.headerdata, format, {
                	result: function(plaintext) {
                		AsyncExecutor(callback, function() {
			                this.cryptoContext.encrypt(plaintext, encoder, format, {
			                    result: function(ciphertext) {
			                        AsyncExecutor(callback, function() {
			                            this.cryptoContext.sign(ciphertext, encoder, format, {
			                                result: function(signature) {
			                                    AsyncExecutor(callback, function() {
			                                        // Create the encoding.
			                                        var header = encoder.createObject();
			                                        if (this.masterToken)
			                                            header.put(Header.KEY_MASTER_TOKEN, this.masterToken);
			                                        else
			                                            header.put(Header.KEY_ENTITY_AUTHENTICATION_DATA, this.entityAuthenticationData);
			                                        header.put(Header.KEY_HEADERDATA, ciphertext);
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
                								AsyncExecutor(callback, function() {
                									if (e instanceof MslCryptoException)
                										e = new MslEncoderException("Error signing the header data.", e);
                									throw e;
                								}, self);
			                                },
			                            });
			                        }, self);
			                    },
			                    error: function(e) {
                					AsyncExecutor(callback, function() {
				                        if (e instanceof MslCryptoException)
				                            e = new MslEncoderException("Error encrypting the header data.", e);
				                        throw e;
                					}, self);
			                    },
			                });
                		}, self);
                	},
                	error: callback.error, 
                });
            }, self);
        },
    });

    /**
     * <p>Construct a new message header with the provided message data.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is provided, it
     * will be used for this purpose. Otherwise the crypto context appropriate
     * for the entity authentication scheme will be used. N.B. Either the
     * entity authentication data or the master token must be provided.</p>
     *
     * <p>Peer tokens are only processed if operating in peer-to-peer mode.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {EntityAuthenticationData} entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param {MaterToken} masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param {HeaderData} headerData message header data container.
     * @param {HeaderPeerData} peerData message header peer data container.
     * @param {{result: function(MessageHeader), error: function(Error)}}
     *        callback the callback functions that will receive the message
     *        header or any thrown exceptions.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the message.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     * @throws MslMessageException if no entity authentication data or master
     *         token is provided.
     */
    var MessageHeader$create = function MessageHeader$create(ctx, entityAuthData, masterToken, headerData, peerData, callback) {
        new MessageHeader(ctx, entityAuthData, masterToken, headerData, peerData, null, callback);
    };

    /**
     * @param {MslContext} ctx MSL context.
     * @param {?MslObject} keyResponseDataMo key response data MSL object.
     * @param {{result: function(?KeyResponseData), error: function(Error)}}
     *        callback the callback that will receive the key response data or
     *        any thrown exceptions.
     */
    function getKeyResponseData(ctx, keyResponseDataMo, callback) {
        AsyncExecutor(callback, function() {
            if (keyResponseDataMo) {
                KeyResponseData.parse(ctx, keyResponseDataMo, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {?MslObject} userIdTokenMo user ID token MSL object.
     * @param {MasterToken} masterToken master token.
     * @param {{result: function(?UserIdToken), error: function(Error)}} callback
     *        the callback that will receive the user ID token or any thrown
     *        exceptions.
     */
    function getUserIdToken(ctx, userIdTokenMo, masterToken, callback) {
        AsyncExecutor(callback, function() {
            if (userIdTokenMo) {
                UserIdToken.parse(ctx, userIdTokenMo, masterToken, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken master token.
     * @param {?MslObject} userAuthDataMo user authentication data MSL object.
     * @param {{result: function(?UserAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the user authentication
     *        data or any thrown exceptions.
     */
    function getUserAuthData(ctx, masterToken, userAuthDataMo, callback) {
        AsyncExecutor(callback, function() {
            if (userAuthDataMo) {
                UserAuthenticationData.parse(ctx, masterToken, userAuthDataMo, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {MslArray} tokensMa MSL array of service token MSL objects.
     * @param {?MasterToken} masterToken master token.
     * @param {?UserIdToken} userIdToken user ID token.
     * @param {Object.<string,ICryptoContext>} cryptoContexts service token
     *        crypto contexts.
     * @param {MslObject} headerdata header data.
     * @param {{result: function(Array.<ServiceToken>), error: function(Error)}}
     *        callback the callback that will receive the service tokens or any
     *        thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         array or objects.
     */
    function getServiceTokens(ctx, tokensMa, masterToken, userIdToken, cryptoContexts, headerdata, callback) {
        var serviceTokensMap = {};
        
        function addServiceToken(tokensMa, index, callback) {
            AsyncExecutor(callback, function() {
                if (index >= tokensMa.size()) {
                    var serviceTokens = [];
                    for (var key in serviceTokensMap)
                        serviceTokens.push(serviceTokensMap[key]);
                    return serviceTokens;
                }

                var tokenMo;
                try {
                    var encoder = ctx.getMslEncoderFactory();
                    tokenMo = tokensMa.getMslObject(index, encoder);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata, e);
                    throw e;
                }
                ServiceToken.parse(ctx, tokenMo, masterToken, userIdToken, cryptoContexts, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            serviceTokensMap[serviceToken.uniqueKey()] = serviceToken;
                            addServiceToken(tokensMa, index + 1, callback);
                        });
                    },
                    error: callback.error,
                });
            });
        }

        AsyncExecutor(callback, function() {
            if (tokensMa) {
                addServiceToken(tokensMa, 0, callback);
            } else {
                return [];
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} headerdata header data MSL object.
     * @param {?KeyResponseData} keyResponseData key response data.
     * @param {Object.<string,ICryptoContext>} cryptoContexts service token
     *        crypto contexts.
     * @param {{result: function({peerMasterToken: MasterToken, peerUserIdToken: UserIdToken, peerServiceTokens: Array.<ServiceToken>}), error: function(Error)}}
     *        callback the callback to receive the peer tokens or any thrown
     *        exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         object.
     */
    function getPeerToPeerTokens(ctx, headerdata, keyResponseData, cryptoContexts, callback) {
        function getPeerMasterToken(ctx, headerdataMo, callback) {
            AsyncExecutor(callback, function() {
                try {
                    if (!headerdataMo.has(KEY_PEER_MASTER_TOKEN))
                        return null;
                    var encoder = ctx.getMslEncoderFactory();
                    var peerMasterTokenMo = headerdataMo.getMslObject(KEY_PEER_MASTER_TOKEN, encoder);
                    MasterToken.parse(ctx, peerMasterTokenMo, callback);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdataMo, e);
                    throw e;
                }
            });
        }

        function getPeerUserIdToken(ctx, headerdataMo, masterToken, callback) {
            AsyncExecutor(callback, function() {
                try {
                    if (!headerdataMo.has(KEY_PEER_USER_ID_TOKEN))
                        return null;
                    var encoder = ctx.getMslEncoderFactory();
                    var peerUserIdTokenMo = headerdataMo.getMslObject(KEY_PEER_USER_ID_TOKEN, encoder);
                    UserIdToken.parse(ctx, peerUserIdTokenMo, masterToken, callback);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdataMo, e);
                    throw e;
                }
            });
        }
        
        function getPeerServiceTokens(ctx, headerdataMo, peerMasterToken, peerUserIdToken, cryptoContexts, callback) {
        	AsyncExecutor(callback, function() {
        		try {
        			if (!headerdata.has(KEY_PEER_SERVICE_TOKENS))
        				return [];
        			var tokens = headerdata.getMslArray(KEY_PEER_SERVICE_TOKENS);
                    getServiceTokens(ctx, tokens, peerMasterToken, peerUserIdToken, cryptoContexts, headerdataMo, callback);
        		} catch (e) {
        			if (e instanceof MslEncoderException)
        				throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdataMo, e);
        			throw e;
        		}
        	});
        }

        AsyncExecutor(callback, function() {
            if (!ctx.isPeerToPeer()) {
                return {
                    peerMasterToken: null,
                    peerUserIdToken: null,
                    peerServiceTokens: [],
                };
            }

            // Pull peer master token.
            getPeerMasterToken(ctx, headerdata, {
                result: function(peerMasterToken) {
                    AsyncExecutor(callback, function() {
                        // The key response data master token is used for peer token
                        // verification if in peer-to-peer mode.
                        var peerVerificationMasterToken = (keyResponseData)
                            ? keyResponseData.masterToken
                            : peerMasterToken;

                        // Pull peer user ID token. User ID tokens are always
                        // authenticated by a master token.
                        getPeerUserIdToken(ctx, headerdata, peerVerificationMasterToken, {
                            result: function(peerUserIdToken) {
                            	// Peer service tokens are authenticated by the peer master
                            	// token if it exists or by the application crypto context.
                            	getPeerServiceTokens(ctx, headerdata, peerVerificationMasterToken, peerUserIdToken, cryptoContexts, {
                            		result: function(peerServiceTokens) {
                            			AsyncExecutor(callback, function() {
                            				return {
                            					peerMasterToken: peerMasterToken,
                            					peerUserIdToken: peerUserIdToken,
                            					peerServiceTokens: peerServiceTokens,
                            				};
                            			});
                            		},
                            		error: function(e) {
                            			AsyncExecutor(callback, function() {
                            				if (e instanceof MslException) {
                            					e.setMasterToken(peerVerificationMasterToken);
                            					e.setUserIdToken(peerUserIdToken);
                            				}
                            				throw e;
                            			});
                            		}
                            	});
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setMasterToken(peerVerificationMasterToken);
                                    throw e;
                                });
                            }
                        });
                    });
                },
                error: callback.error,
            });
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} headerdata header data MSL object.
     * @param {string} headerdataJson header data JSON string.
     * @param {{result: function(Array.<KeyRequestData>}, error: function(Error)}}
     *        callback the callback to receive the key request data or any
     *        thrown exceptions.
     */
    function getKeyRequestData(ctx, headerdata, callback) {
        var keyRequestData = [];

        function addKeyRequestData(keyRequestDataMa, index) {
            AsyncExecutor(callback, function() {
                if (index >= keyRequestDataMa.size())
                    return keyRequestData;
                
                var encoder = ctx.getMslEncoderFactory();
                var keyRequestDataMo = keyRequestDataMa.getMslObject(index, encoder);
                KeyRequestData.parse(ctx, keyRequestDataMo, {
                    result: function(data) {
                        AsyncExecutor(callback, function() {
                            keyRequestData.push(data);
                            addKeyRequestData(keyRequestDataMa, index + 1);
                        });
                    },
                    error: callback.error,
                });
            });
        }

        AsyncExecutor(callback, function() {
            try {
                if (!headerdata.has(KEY_KEY_REQUEST_DATA))
                    return [];
                var keyRequestDataMa = headerdata.getMslArray(KEY_KEY_REQUEST_DATA);
                addKeyRequestData(keyRequestDataMa, 0);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata, e);
                throw e;
            }
        });
    }

    /**
     * <p>Construct a new message from the provided JSON object.</p>
     *
     * <p>Headers are encrypted and signed. If a master token is found, it will
     * be used for this purpose. Otherwise the crypto context appropriate for
     * the entity authentication scheme will be used. Either the master token
     * or entity authentication data must be found.</p>
     *
     * <p>If user authentication data is included user authentication will be
     * performed. If a user ID token is included then its user information is
     * considered to be trusted.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explicitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {Uint8Array} headerdataBytes encoded header data.
     * @param {EntityAuthenticationData} entityAuthData the entity authentication data. May be null if a
     *        master token is provided.
     * @param {MasterToken} masterToken the master token. May be null if entity
     *        authentication data is provided.
     * @param {Uint8Array} signature the header signature.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @param {{result: function(MessageHeader), error: function(Error)}}
     *        callback the callback functions that will receive the message
     *        header or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the key exchange crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data or there is an error with the entity
     *         authentication data.
     * @throws MslKeyExchangeException if unable to create the key request data
     *         or key response data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data or authenticate the user.
     * @throws MslMasterTokenException if the header master token is not
     *         trusted and needs to be to accept this message header.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data.
     * @throws MslException if a token is improperly bound to another token.
     */
    var MessageHeader$parse = function MessageHeader$parse(ctx, headerdataBytes, entityAuthData, masterToken, signature, cryptoContexts, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            entityAuthData = (!masterToken) ? entityAuthData : null;
            if (!entityAuthData && !masterToken)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

            // Create the correct message crypto context.
            var messageCryptoContext;
            try {
                messageCryptoContext = getMessageCryptoContext(ctx, entityAuthData, masterToken);
            } catch (e) {
                if (e instanceof MslException) {
                    e.setMasterToken(masterToken);
                    e.setEntityAuthenticationData(entityAuthData);
                }
                throw e;
            }
            
            // Verify and decrypt the header data.
            messageCryptoContext.verify(headerdataBytes, signature, encoder, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (!verified) {
                            if (masterToken)
                                throw new MslCryptoException(MslError.MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED);
                            else
                                throw new MslCryptoException(MslError.MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED);
                        }
                        messageCryptoContext.decrypt(headerdataBytes, encoder, {
                            result: function(plaintext) {
                                reconstructHeader(messageCryptoContext, plaintext);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslCryptoException || e instanceof MslEntityAuthException) {
                                        e.setMasterToken(masterToken);
                                        e.setEntityAuthenticationData(entityAuthData);
                                    }
                                    throw e;
                                });
                            },
                        });
                    });
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        if (e instanceof MslCryptoException || e instanceof MslEntityAuthException) {
                            e.setMasterToken(masterToken);
                            e.setEntityAuthenticationData(entityAuthData);
                        }
                        throw e;
                    });
                },
            });
        });

        function reconstructHeader(messageCryptoContext, plaintext) {
            AsyncExecutor(callback, function() {
                var encoder = ctx.getMslEncoderFactory();
                
                var headerdata, messageId;
                try {
                    headerdata = encoder.parseObject(plaintext);
    
                    // Pull the message ID first because any error responses need to
                    // use it.
                    messageId = headerdata.getLong(KEY_MESSAGE_ID);
                    if (messageId < 0 || messageId > MslConstants.MAX_LONG_VALUE)
                        throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "headerdata " + headerdata).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + Base64.encode(plaintext), e).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData);
                    throw e;
                }

                var timestamp;
                var keyResponseDataMo, userIdTokenMo, userAuthDataMo, tokensMa;
                try {
                    timestamp = (headerdata.has(KEY_TIMESTAMP)) ? headerdata.getLong(KEY_TIMESTAMP) : null;
                
                    // Pull headerdata MSL objects.
                    keyResponseDataMo = (headerdata.has(KEY_KEY_RESPONSE_DATA)) 
                        ? headerdata.getMslObject(KEY_KEY_RESPONSE_DATA, encoder)
                        : null;
                    userIdTokenMo = (headerdata.has(KEY_USER_ID_TOKEN))
                        ? headerdata.getMslObject(KEY_USER_ID_TOKEN, encoder)
                        : null;
                    userAuthDataMo = (headerdata.has(KEY_USER_AUTHENTICATION_DATA))
                        ? headerdata.getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder)
                        : null;
                    tokensMa = (headerdata.has(KEY_SERVICE_TOKENS))
                        ? headerdata.getMslArray(KEY_SERVICE_TOKENS)
                        : null;
                } catch (e) {
                    if (e instanceof MslEncoderException)
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata, e).setMasterToken(masterToken).setEntityAuthenticationData(entityAuthData).setMessageId(messageId);
                    throw e;
                }

                // Change the callback so we can add the message Id to
                // any thrown exceptions.
                var originalCallback = callback;
                callback = {
                    result: originalCallback.result,
                    error: function(e) {
                        if (e instanceof MslException) {
                            e.setMasterToken(masterToken);
                            e.setEntityAuthenticationData(entityAuthData);
                            e.setMessageId(messageId);
                        }
                        originalCallback.error(e);
                    }
                };
                
                reconstructObjects(messageCryptoContext, headerdata, messageId, timestamp, keyResponseDataMo, userIdTokenMo, userAuthDataMo, tokensMa, callback);
            });
        }
        
        function reconstructObjects(messageCryptoContext, headerdata, messageId, timestamp, keyResponseDataMo, userIdTokenMo, userAuthDataMo, tokensMa, callback) {
            AsyncExecutor(callback, function() {
                var encoder = ctx.getMslEncoderFactory();
                
                // Grab primary token verification master token.
                getKeyResponseData(ctx, keyResponseDataMo, {
                    result: function(keyResponseData) {
                        AsyncExecutor(callback, function() {
                            // The key response data master token is used for token
                            // verification in a trusted services network. Otherwise it
                            // will be used for peer token verification, which is handled
                            // below.
                            var tokenVerificationMasterToken = (!ctx.isPeerToPeer() && keyResponseData)
                                ? keyResponseData.masterToken
                                : masterToken;

                            // User ID tokens are always authenticated by a master token.
                            getUserIdToken(ctx, userIdTokenMo, tokenVerificationMasterToken, {
                                result: function(userIdToken) {
                                    AsyncExecutor(callback, function() {
                                        // Pull user authentication data.
                                        getUserAuthData(ctx, tokenVerificationMasterToken, userAuthDataMo, {
                                            result: function(userAuthData) {
                                                AsyncExecutor(callback, function() {
                                                    // Identify the user if any.
                                                    var user;
                                                    if (userAuthData) {
                                                        // Reject unencrypted messages containing user authentication data.
                                                        var encrypted = (masterToken) ? true : entityAuthData.scheme.encrypts;
                                                        if (!encrypted)
                                                            throw new MslMessageException(MslError.UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);
                                                        
                                                        // Verify the user authentication data.
                                                        var scheme = userAuthData.scheme;
                                                        var factory = ctx.getUserAuthenticationFactory(scheme);
                                                        if (!factory)
                                                            throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);
                                                        var identity = (masterToken) ? masterToken.identity : entityAuthData.getIdentity();
                                                        factory.authenticate(ctx, identity, userAuthData, userIdToken, {
                                                            result: function(user) {
                                                                // Service tokens are authenticated by the master token if it
                                                                // exists or by the application crypto context.
                                                                getServiceTokens(ctx, tokensMa, tokenVerificationMasterToken, userIdToken, cryptoContexts, headerdata, {
                                                                    result: function(serviceTokens) {
                                                                        buildHeader(messageCryptoContext, headerdata, messageId, timestamp, keyResponseData, userIdToken, userAuthData, user, serviceTokens, callback);
                                                                    },
                                                                    error: callback.error,
                                                                });
                                                            },
                                                            error: callback.error,
                                                        });
                                                        return;
                                                    } else if (userIdToken) {
                                                        user = userIdToken.user;
                                                    } else {
                                                        user = null;
                                                    }

                                                    // Service tokens are authenticated by the master token if it
                                                    // exists or by the application crypto context.
                                                    getServiceTokens(ctx, tokensMa, tokenVerificationMasterToken, userIdToken, cryptoContexts, headerdata, {
                                                        result: function(serviceTokens) {
                                                            buildHeader(messageCryptoContext, headerdata, messageId, timestamp, keyResponseData, userIdToken, userAuthData, user, serviceTokens, callback);
                                                        },
                                                        error: callback.error,
                                                    });
                                                });
                                            },
                                            error: callback.error,
                                        });
                                    });
                                },
                                error: callback.error,
                            });
                        });
                    },
                    error: callback.error,
                });
            });
        }
        
        function buildHeader(messageCryptoContext, headerdata, messageId, timestamp, keyResponseData, userIdToken, userAuthData, user, serviceTokens, callback) {
            AsyncExecutor(callback, function() {
                var encoder = ctx.getMslEncoderFactory();
                
                var nonReplayableId, renewable, handshake, capabilities;
                try {
                    nonReplayableId = (headerdata.has(KEY_NON_REPLAYABLE_ID)) ? headerdata.getLong(KEY_NON_REPLAYABLE_ID) : null;
                    renewable = headerdata.getBoolean(KEY_RENEWABLE);
                    // FIXME: Make handshake required once all MSL stacks are updated.
                    handshake = (headerdata.has(KEY_HANDSHAKE)) ? headerdata.getBoolean(KEY_HANDSHAKE) : false;

                    // Verify values.
                    if (nonReplayableId < 0 || nonReplayableId > MslConstants.MAX_LONG_VALUE)
                        throw new MslMessageException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "headerdata " + headerdata.toString());

                    // Pull message capabilities.
                    capabilities = null;
                    if (headerdata.has(KEY_CAPABILITIES)) {
                        var capabilitiesMo = headerdata.getMslObject(KEY_CAPABILITIES, encoder);
                        capabilities = MessageCapabilities.parse(capabilitiesMo);
                    }
                } catch (e) {
                    if (e instanceof MslEncoderException) {
                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "headerdata " + headerdata.toString(), e)
	                        .setMasterToken(masterToken)
	                        .setEntityAuthenticationData(entityAuthData)
	                        .setUserIdToken(userIdToken)
	                        .setUserAuthenticationData(userAuthData)
	                        .setMessageId(messageId);
                    }
                    throw e;
                }

                // Pull key request data containers.
                getKeyRequestData(ctx, headerdata, {
                    result: function(keyRequestData) {
                        // Get peer-to-peer tokens.
                        getPeerToPeerTokens(ctx, headerdata, keyResponseData, cryptoContexts, {
                            result: function(result) {
                                AsyncExecutor(callback, function() {
                                    var peerMasterToken = result.peerMasterToken;
                                    var peerUserIdToken = result.peerUserIdToken;
                                    var peerServiceTokens = result.peerServiceTokens;

                                    // Return new message header.
                                    var headerData = new HeaderData(messageId, nonReplayableId, renewable, handshake, capabilities,
                                            keyRequestData, keyResponseData, userAuthData, userIdToken,
                                            serviceTokens);
                                    var headerPeerData = new HeaderPeerData(peerMasterToken, peerUserIdToken, peerServiceTokens);
                                    var creationData = new CreationData(user, timestamp, messageCryptoContext, headerdata);
                                    new MessageHeader(ctx, entityAuthData, masterToken, headerData, headerPeerData, creationData, callback);
                                });
                            },
                            error: callback.error,
                        });
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException) {
                                e.setUserIdToken(userIdToken);
                                e.setUserAuthenticationData(userAuthData);
                            }
                            throw e;
                        });
                    },
                });
            });
        }
    };
    
    // Exports.
    module.exports.create = MessageHeader$create;
    module.exports.parse = MessageHeader$parse;
    module.exports.HeaderData = HeaderData;
    module.exports.HeaderPeerData = HeaderPeerData;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MessageHeader'));
