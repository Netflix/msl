/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
 * verified using the master token. The sender will also be included. If no
 * master token exists, the header data will be verified and encrypted based on
 * the entity authentication scheme.</p>
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
 *   "sender" : "string",
 *   "recipient" : "string",
 *   "messageid" : "int64(0,2^53^)",
 *   "nonreplayableid" : "int64(0,2^53^)",
 *   "nonreplayable" : "boolean",
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
 * <li>{@code sender} is the sender entity identity</li>
 * <li>{@code recipient} is the intended recipient's entity identity</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code nonreplayableid} is the non-replayable ID</li>
 * <li>{@code nonreplayable} indicates if the message is nonreplayable</li>
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
var MessageHeader;
var MessageHeader$create;
var MessageHeader$parse;
var MessageHeader$HeaderData;
var MessageHeader$HeaderPeerData;

(function() {
    // Message header data.
    /**
     * JSON key sender.
     * @const
     * @type {string}
     */
    var KEY_SENDER = "sender";
    /**
     * JSON key recipient.
     * @const
     * @type {string}
     */
    var KEY_RECIPIENT = "recipient";
    /**
     * JSON key message ID.
     * @const
     * @type {string}
     */
    var KEY_MESSAGE_ID = "messageid";
    /**
     * JSON key non-replayable ID.
     * @const
     * @type {string}
     */
    var KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    /**
     * JSON key non-replayable flag.
     * @const
     * @type {string}
     */
    var KEY_NON_REPLAYABLE = "nonreplayable";
    /**
     * JSON key renewable flag.
     * @const
     * @type {string}
     */
    var KEY_RENEWABLE = "renewable";
    /**
     * JSON key handshake flag.
     * @const
     * @type {string}
     */
    var KEY_HANDSHAKE = "handshake";
    /**
     * JSON key capabilities.
     * @const
     * @type {string}
     */
    var KEY_CAPABILITIES = "capabilities";
    /**
     * JSON key key exchange request.
     * @const
     * @type {string}
     */
    var KEY_KEY_REQUEST_DATA = "keyrequestdata";
    /**
     * JSON key key exchange response.
     * @const
     * @type {string}
     */
    var KEY_KEY_RESPONSE_DATA = "keyresponsedata";
    /**
     * JSON key user authentication data.
     * @const
     * @type {string}
     */
    var KEY_USER_AUTHENTICATION_DATA = "userauthdata";
    /**
     * JSON key user ID token.
     * @const
     * @type {string}
     */
    var KEY_USER_ID_TOKEN = "useridtoken";
    /**
     * JSON key service tokens.
     * @const
     * @type {string}
     */
    var KEY_SERVICE_TOKENS = "servicetokens";

    // Message header peer data.
    /**
     * JSON key peer master token.
     * @const
     * @type {string}
     */
    var KEY_PEER_MASTER_TOKEN = "peermastertoken";
    /**
     * JSON key peer user ID token.
     * @const
     * @type {string}
     */
    var KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
    /**
     * JSON key peer service tokens.
     * @const
     * @type {string}
     */
    var KEY_PEER_SERVICE_TOKENS = "peerservicetokens";

    /**
     * Container struct for message header data.
     */
    var HeaderData = MessageHeader$HeaderData = util.Class.create({
        /**
         * @param {?string} recipient the message recipient's entity identity. May be
         *        null.
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
        init: function init(recipient, messageId, nonReplayableId,
            renewable, handshake,
            capabilities,
            keyRequestData, keyResponseData,
            userAuthData, userIdToken,
            serviceTokens)
        {
            // The properties.
            var props = {
                recipient: { value: recipient, writable: false, configurable: false },
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
    var HeaderPeerData = MessageHeader$HeaderPeerData = util.Class.create({
        /**
         * @param {MasterToken} peerMasterToken peer master token. May be null.
         * @param {UserIdToken} peerUserIdToken peer user ID token. May be null if there is
         *        no user authentication for the peer.
         * @param {Array.<ServiceToken>} peerServiceTokens peer service tokens. May be empty.
         */
        init: function init(peerMasterToken, peerUserIdToken,
            peerServiceTokens)
        {
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
     * @param {string} sender message sender.
     * @param {ICryptoContext} messageCryptoContext message crypto context.
     * @param {Uint8Array} headerdata raw header data.
     * @param {Uint8Array} plaintext decrypted header data.
     * @param {Uint8Array} signature raw signature.
     * @param {boolean} verified true if the headerdata was verified.
     * @param {number} legacy non-replayable boolean.
     * @constructor
     */
    function CreationData(user, sender, messageCryptoContext, headerdata, plaintext, signature, verified, nonReplayable) {
        this.user = user;
        this.sender = sender;
        this.messageCryptoContext = messageCryptoContext;
        this.headerdata = headerdata;
        this.plaintext = plaintext;
        this.signature = signature;
        this.verified = verified;
        this.nonReplayable = nonReplayable;
    };

    /**
     * Return a properties configuration for the provided property values.
     *
     * @param {MslContext} ctx
     * @param {ICryptoContext} messageCryptoContext
     * @param {MslUser} user
     * @param {EntityAuthenticationData} entityAuthData
     * @param {MasterToken} masterToken
     * @param {string} sender
     * @param {string} recipient
     * @param {number} messageId
     * @param {Array.<KeyRequestData>} keyRequestData
     * @param {KeyResponseData} keyResponseData
     * @param {UserAuthenticationData} userAuthData
     * @param {UserIdToken} userIdToken
     * @param {Array.<ServiceToken>} serviceTokens
     * @param {MasterToken} peerMasterToken
     * @param {UserIdToken} peerUserIdToken
     * @param {Array.<ServiceToken>} peerServiceTokens
     * @param {number} nonReplayableId
     * @param {boolean} nonReplayable
     * @param {boolean} renewable
     * @param {MessageCapabilities} capabilities
     * @param {Uint8Array} headerdata
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} signature
     * @param {boolean} verified
     * @return {object} the properties configuration.
     */
    function buildProperties(ctx, messageCryptoContext, user,
            entityAuthData, masterToken, sender, recipient, messageId,
            keyRequestData, keyResponseData,
            userAuthData, userIdToken, serviceTokens,
            peerMasterToken, peerUserIdToken, peerServiceTokens,
            nonReplayableId, nonReplayable, renewable, handshake, capabilities,
            headerdata, plaintext, signature, verified)
    {
        // The properties.
        return {
            /**
             * Returns the crypto context that was used to process the header data.
             * This crypto context should also be used to process the payload data if
             * no key response data is included in the message.
             *
             * @return the header data crypto context.
             * @see #isEncrypting()
             */
            cryptoContext: { value: messageCryptoContext, writable: false, configurable: false },
            /**
             * Returns the user if the user has been authenticated or a user ID
             * token was provided.
             */
            user: { value: user, writable: false, configurable: false },
            /**
             * Returns the entity authentication data. May be null if the entity has
             * already been authenticated and is using a master token instead.
             */
            entityAuthenticationData: { value: entityAuthData, writable: false, configurable: false },
            /**
             * Returns the primary master token identifying the entity and containing
             * the session keys. May be null if the entity has not been authenticated.
             */
            masterToken: { value: masterToken, writable: false, configurable: false },
            sender: { value: sender, writable: false, configurable: false },
            recipient: { value: recipient, writable: false, configurable: false },
            messageId: { value: messageId, writable: false, configurable: false },
            nonReplayableId: { value: nonReplayableId, writable: false, configurable: false },
            keyRequestData: { value: keyRequestData, writable: false, configurable: false },
            keyResponseData: { value: keyResponseData, writable: false, configurable: false },
            /**
             * Returns the user authentication data. May be null if the user has
             * already been authenticated and is using a user ID token or if there is
             * no user authentication requested.
             */
            userAuthenticationData: { value: userAuthData, writable: false, configurable: false },
            /**
             * Returns the primary user ID token identifying the user. May be null if
             * the user has not been authenticated.
             */
            userIdToken: { value: userIdToken, writable: false, configurable: false },
            serviceTokens: { value: serviceTokens, writable: false, configurable: false },
            /**
             * Returns the master token that should be used by an entity responding to
             * this message. Will be null if the responding entity should use its own
             * entity authentication data or the primary master token.
             */
            peerMasterToken: { value: peerMasterToken, writable: false, configurable: false },
            /**
             * Returns the user ID token that must be used by an entity responding to
             * this message if an peer master token is provided. May be null if peer
             * user authentication has not occurred. Will be null if there is no peer
             * master token.
             */
            peerUserIdToken: { value: peerUserIdToken, writable: false, configurable: false },
            /**
             * Returns the service tokens that must be used by an entity responding to
             * this message. May be null if the responding entity should use the
             * primary service tokens.
             */
            peerServiceTokens: { value: peerServiceTokens, writable: false, configurable: false },
            /** Message capabilities. */
            messageCapabilities: { value: capabilities, writable: false, configurable: false },
            // Private properties.
            nonReplayable: { value: nonReplayable, writable: false, enumerable: false, configurable: false },
            renewable: { value: renewable, writable: false, enumerable: false, configurable: false },
            handshake: { value: handshake, writable: false, enumerable: false, configurable: false },
            headerdata: { value: headerdata, writable: false, enumerable: false, configurable: false },
            plaintext: { value: plaintext, writable: false, enumerable: false, configurable: false },
            signature: { value: signature, writable: false, enumerable: false, configurable: false },
            verified: { value: verified, writable: false, enumerable: false, configurable: false },
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
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme);
            return factory.getCryptoContext(ctx, entityAuthData);
        }
    }

    MessageHeader = util.Class.create({
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
                    construct(creationData.sender);
                } else {
                    if (masterToken) {
                        ctx.getEntityAuthenticationData(null, {
                            result: function(ead) {
                                var sender = ead.getIdentity();
                                construct(sender);
                            },
                            error: callback.error,
                        });
                    } else {
                        construct(null);
                    }
                }
            }, self);

            function construct(sender) {
                AsyncExecutor(callback, function() {
                    entityAuthData = (!masterToken) ? entityAuthData : null;
                    var nonReplayableId = headerData.nonReplayableId;
                    var nonReplayable = false;
                    var renewable = headerData.renewable;
                    var handshake = headerData.handshake;
                    var capabilities = headerData.capabilities;
                    var recipient = headerData.recipient;
                    var messageId = headerData.messageId;
                    var keyRequestData = (headerData.keyRequestData) ? headerData.keyRequestData : new Array();
                    var keyResponseData = headerData.keyResponseData;
                    var userAuthData = headerData.userAuthData;
                    var userIdToken = headerData.userIdToken;
                    var serviceTokens = (headerData.serviceTokens) ? headerData.serviceTokens : new Array();
                    var peerMasterToken, peerUserIdToken, peerServiceTokens;
                    if (ctx.isPeerToPeer()) {
                        peerMasterToken = peerData.peerMasterToken;
                        peerUserIdToken = peerData.peerUserIdToken;
                        peerServiceTokens = (peerData.peerServiceTokens) ? peerData.peerServiceTokens : new Array();
                    } else {
                        peerMasterToken = null;
                        peerUserIdToken = null;
                        peerServiceTokens = new Array();
                    }

                    // Message ID must be within range.
                    if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                        throw new MslInternalException("Message ID " + messageId + " is out of range.");

                    // Message entity must be provided.
                    if (!entityAuthData && !masterToken)
                        throw new MslInternalException("Message entity authentication data or master token must be provided.");

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

                    // Create the header data.
                    if (!creationData) {
                        // Grab the user.
                        var user = (userIdToken) ? userIdToken.user : null;

                        // Construct the JSON.
                        var headerJO = {};
                        if (sender) headerJO[KEY_SENDER] = sender;
                        if (recipient) headerJO[KEY_RECIPIENT] = recipient;
                        headerJO[KEY_MESSAGE_ID] = messageId;
                        headerJO[KEY_NON_REPLAYABLE] = nonReplayable;
                        if (typeof nonReplayableId === 'number') headerJO[KEY_NON_REPLAYABLE_ID] = nonReplayableId;
                        headerJO[KEY_RENEWABLE] = renewable;
                        headerJO[KEY_HANDSHAKE] = handshake;
                        if (capabilities) headerJO[KEY_CAPABILITIES] = capabilities;
                        if (keyRequestData.length > 0) headerJO[KEY_KEY_REQUEST_DATA] = keyRequestData;
                        if (keyResponseData) headerJO[KEY_KEY_RESPONSE_DATA] = keyResponseData;
                        if (userAuthData) headerJO[KEY_USER_AUTHENTICATION_DATA] = userAuthData;
                        if (userIdToken) headerJO[KEY_USER_ID_TOKEN] = userIdToken;
                        if (serviceTokens.length > 0) headerJO[KEY_SERVICE_TOKENS] = serviceTokens;
                        if (peerMasterToken) headerJO[KEY_PEER_MASTER_TOKEN] = peerMasterToken;
                        if (peerUserIdToken) headerJO[KEY_PEER_USER_ID_TOKEN] = peerUserIdToken;
                        if (peerServiceTokens.length > 0) headerJO[KEY_PEER_SERVICE_TOKENS] = peerServiceTokens;

                        // Get the correct crypto context.
                        var messageCryptoContext;
                        try {
                            messageCryptoContext = getMessageCryptoContext(ctx, entityAuthData, masterToken);
                        } catch (e) {
                            if (e instanceof MslException) {
                                e.setEntity(masterToken);
                                e.setEntity(entityAuthData);
                                e.setUser(userIdToken);
                                e.setUser(userAuthData);
                                e.setMessageId(messageId);
                            }
                            throw e;
                        }

                        // Encrypt and sign the header data.
                        var plaintext = textEncoding$getBytes(JSON.stringify(headerJO), MslConstants$DEFAULT_CHARSET);
                        messageCryptoContext.encrypt(plaintext, {
                            result: function(headerdata) {
                                AsyncExecutor(callback, function() {
                                    messageCryptoContext.sign(headerdata, {
                                        result: function(signature) {
                                            AsyncExecutor(callback, function() {
                                                var props = buildProperties(ctx, messageCryptoContext, user, entityAuthData,
                                                    masterToken, sender, recipient, messageId, keyRequestData, keyResponseData,
                                                    userAuthData, userIdToken, serviceTokens,
                                                    peerMasterToken, peerUserIdToken, peerServiceTokens,
                                                    nonReplayableId, nonReplayable, renewable, handshake, capabilities,
                                                    headerdata, plaintext, signature, true);
                                                Object.defineProperties(this, props);
                                                return this;
                                            }, self);
                                        },
                                        error: function(e) {
                                            AsyncExecutor(callback, function() {
                                                if (e instanceof MslException) {
                                                    e.setEntity(masterToken);
                                                    e.setEntity(entityAuthData);
                                                    e.setUser(userIdToken);
                                                    e.setUser(userAuthData);
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
                                        e.setEntity(masterToken);
                                        e.setEntity(entityAuthData);
                                        e.setUser(userIdToken);
                                        e.setUser(userAuthData);
                                        e.setMessageId(messageId);
                                    }
                                    throw e;
                                }, self);
                            }
                        });
                    } else {
                        var user = creationData.user;
                        var messageCryptoContext = creationData.messageCryptoContext;
                        var headerdata = creationData.headerdata;
                        var plaintext = creationData.plaintext;
                        var signature = creationData.signature;
                        var verified = creationData.verified;
                        nonReplayable = creationData.nonReplayable;

                        var props = buildProperties(ctx, messageCryptoContext, user, entityAuthData,
                            masterToken, sender, recipient, messageId, keyRequestData, keyResponseData,
                            userAuthData, userIdToken, serviceTokens,
                            peerMasterToken, peerUserIdToken, peerServiceTokens,
                            nonReplayableId, nonReplayable, renewable, handshake, capabilities,
                            headerdata, plaintext, signature, verified);
                        Object.defineProperties(this, props);
                        return this;
                    }
                }, self);
            }
        },

        /**
         * <p>Returns true if the header data has been decrypted and parsed. If
         * this method returns false then the other methods that return the header
         * data will return {@code null}, {@code false}, or empty collections
         * instead of the actual header data.</p>
         * 
         * @return {boolean} true if the decrypted content is available. (Implies verified.)
         */
        isDecrypted: function isDecrypted() {
            return (this.plaintext) ? true : false;
        },

        /**
         * @return {boolean} true if the token has been verified.
         */
        isVerified: function isVerified() {
            return this.verified;
        },

        /**
         * @return {boolean} true if the message header crypto context provides encryption.
         * @see #getCryptoContext()
         */
        isEncrypting: function isEncrypting() {
            return this.masterToken || this.entityAuthenticationData.scheme.encrypts;
        },

        /**
         * @return {boolean} true if the message non-replayable flag is set.
         */
        isNonReplayable: function isNonReplayable() {
            return this.nonReplayable;
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
        toJSON: function toJSON() {
            var jsonObj = {};
            if (this.masterToken)
                jsonObj[Header$KEY_MASTER_TOKEN] = this.masterToken;
            else
                jsonObj[Header$KEY_ENTITY_AUTHENTICATION_DATA] = this.entityAuthenticationData;
            jsonObj[Header$KEY_HEADERDATA] = base64$encode(this.headerdata);
            jsonObj[Header$KEY_SIGNATURE] = base64$encode(this.signature);
            return jsonObj;
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
    MessageHeader$create = function MessageHeader$create(ctx, entityAuthData, masterToken, headerData, peerData, callback) {
        new MessageHeader(ctx, entityAuthData, masterToken, headerData, peerData, null, callback);
    };

    /**
     * @param {MslContext} ctx MSL context.
     * @param {?object} keyResponseDataJo key response data JSON object.
     * @param {{result: function(?KeyResponseData), error: function(Error)}}
     *        callback the callback that will receive the key response data or
     *        any thrown exceptions.
     */
    function getKeyResponseData(ctx, keyResponseDataJo, callback) {
        AsyncExecutor(callback, function() {
            if (keyResponseDataJo) {
                KeyResponseData$parse(ctx, keyResponseDataJo, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {?object} userIdTokenJo user ID token JSON object.
     * @param {MasterToken} masterToken master token.
     * @param {{result: function(?UserIdToken), error: function(Error)}} callback
     *        the callback that will receive the user ID token or any thrown
     *        exceptions.
     */
    function getUserIdToken(ctx, userIdTokenJo, masterToken, callback) {
        AsyncExecutor(callback, function() {
            if (userIdTokenJo) {
                UserIdToken$parse(ctx, userIdTokenJo, masterToken, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken master token.
     * @param {?object} userAuthDataJo user authentication data JSON object.
     * @param {{result: function(?UserAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the user authentication
     *        data or any thrown exceptions.
     */
    function getUserAuthData(ctx, masterToken, userAuthDataJo, callback) {
        AsyncExecutor(callback, function() {
            if (userAuthDataJo) {
                UserAuthenticationData$parse(ctx, masterToken, userAuthDataJo, callback);
            } else {
                return null;
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {Array.<Object>} tokensJA JSON array of service token JSON objects.
     * @param {?MasterToken} masterToken master token.
     * @param {?UserIdToken} userIdToken user ID token.
     * @param {Object.<string,ICryptoContext>} cryptoContexts service token
     *        crypto contexts.
     * @param {string} headerdataJson header data JSON string.
     * @param {{result: function(Array.<ServiceToken>), error: function(Error)}}
     *        callback the callback that will receive the service tokens or any
     *        thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         array or objects.
     */
    function getServiceTokens(ctx, tokensJA, masterToken, userIdToken, cryptoContexts, headerdataJson, callback) {
        var serviceTokensMap = {};
        function addServiceToken(tokensJA, index, callback) {
            if (index >= tokensJA.length) {
                var serviceTokens = new Array();
                for (var key in serviceTokensMap)
                    serviceTokens.push(serviceTokensMap[key]);
                callback.result(serviceTokens);
                return;
            }

            var tokenJO = tokensJA[index];
            if (typeof tokenJO !== 'object')
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
            ServiceToken$parse(ctx, tokenJO, masterToken, userIdToken, cryptoContexts, {
                result: function(serviceToken) {
                    AsyncExecutor(callback, function() {
                        serviceTokensMap[serviceToken.uniqueKey()] = serviceToken;
                        addServiceToken(tokensJA, index + 1, callback);
                    });
                },
                error: function(e) { callback.error(e); }
            });
        }

        AsyncExecutor(callback, function() {
            if (tokensJA) {
                if (!(tokensJA instanceof Array))
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                addServiceToken(tokensJA, 0, callback);
            } else {
                return new Array();
            }
        });
    }

    /**
     * @param {MslContext} ctx MSL context.
     * @param {Object} headerdataJO header data JSON object.
     * @param {?KeyResponseData} keyResponseData key response data.
     * @param {Object.<string,ICryptoContext>} cryptoContexts service token
     *        crypto contexts.
     * @param {string} headerdataJson header data JSON string.
     * @param {{result: function({peerMasterToken: MasterToken, peerUserIdToken: UserIdToken, peerServiceTokens: Array.<ServiceToken>}), error: function(Error)}}
     *        callback the callback to receive the peer tokens or any thrown
     *        exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         object.
     */
    function getPeerToPeerTokens(ctx, headerdataJO, keyResponseData, cryptoContexts, headerdataJson, callback) {
        function getPeerMasterToken(ctx, headerdataJO, callback) {
            AsyncExecutor(callback, function() {
                var peerMasterTokenJO = headerdataJO[KEY_PEER_MASTER_TOKEN];
                if (peerMasterTokenJO && typeof peerMasterTokenJO !== 'object')
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                if (!peerMasterTokenJO)
                    return null;
                MasterToken$parse(ctx, peerMasterTokenJO, callback);
            });
        }

        function getPeerUserIdToken(ctx, headerdataJO, masterToken, callback) {
            AsyncExecutor(callback, function() {
                var peerUserIdTokenJO = headerdataJO[KEY_PEER_USER_ID_TOKEN];
                if (peerUserIdTokenJO && typeof peerUserIdTokenJO !== 'object')
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                if (!peerUserIdTokenJO)
                    return null;
                UserIdToken$parse(ctx, peerUserIdTokenJO, masterToken, callback);
            });
        }

        AsyncExecutor(callback, function() {
            if (!ctx.isPeerToPeer()) {
                return {
                    peerMasterToken: null,
                    peerUserIdToken: null,
                    peerServiceTokens: new Array(),
                };
            }

            // Pull peer master token.
            getPeerMasterToken(ctx, headerdataJO, {
                result: function(peerMasterToken) {
                    AsyncExecutor(callback, function() {
                        // The key response data master token is used for peer token
                        // verification if in peer-to-peer mode.
                        var peerVerificationMasterToken = (keyResponseData)
                            ? keyResponseData.masterToken
                            : peerMasterToken;

                        // Pull peer user ID token. User ID tokens are always
                        // authenticated by a master token.
                        getPeerUserIdToken(ctx, headerdataJO, peerVerificationMasterToken, {
                            result: function(peerUserIdToken) {
                                AsyncExecutor(callback, function() {
                                    // Peer service tokens are authenticated by the peer master
                                    // token if it exists or by the application crypto context.
                                    var peerServiceTokensJA = headerdataJO[KEY_PEER_SERVICE_TOKENS];
                                    getServiceTokens(ctx, peerServiceTokensJA, peerVerificationMasterToken, peerUserIdToken, cryptoContexts, headerdataJson, {
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
                                                    e.setEntity(peerVerificationMasterToken);
                                                    e.setUser(peerUserIdToken);
                                                }
                                                throw e;
                                            });
                                        }
                                    });
                                });
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setEntity(peerVerificationMasterToken);
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
     * @param {Object} headerdataJO header data JSON object.
     * @param {string} headerdataJson header data JSON string.
     * @param {{result: function(Array.<KeyRequestData>}, error: function(Error)}}
     *        callback the callback to receive the key request data or any
     *        thrown exceptions.
     */
    function getKeyRequestData(ctx, headerdataJO, headerdataJson, callback) {
        var keyRequestData = [];

        function addKeyRequestData(keyRequestDataJA, index) {
            AsyncExecutor(callback, function() {
                if (index >= keyRequestDataJA.length)
                    return keyRequestData;
                var keyRequestDataJO = keyRequestDataJA[index];
                KeyRequestData$parse(ctx, keyRequestDataJO, {
                    result: function(data) {
                        AsyncExecutor(callback, function() {
                            keyRequestData.push(data);
                            addKeyRequestData(keyRequestDataJA, index + 1);
                        });
                    },
                    error: function(e) {
                        callback.error(e);
                    }
                });
            });
        }

        AsyncExecutor(callback, function() {
            var keyRequestDataJA = headerdataJO[KEY_KEY_REQUEST_DATA];
            if (!keyRequestDataJA)
                return keyRequestData;
            if (!(keyRequestDataJA instanceof Array))
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
            addKeyRequestData(keyRequestDataJA, 0);
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
     * @param {string} headerdata header data JSON representation.
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
     *         authentication data or a master token or the header data is
     *         missing or the message ID is negative.
     * @throws MslException if a token is improperly bound to another token.
     */
    MessageHeader$parse = function MessageHeader$parse(ctx, headerdata, entityAuthData, masterToken, signature, cryptoContexts, callback) {
        AsyncExecutor(callback, function() {
            entityAuthData = (!masterToken) ? entityAuthData : null;
            if (!entityAuthData && !masterToken)
                throw new MslMessageException(MslError.MESSAGE_ENTITY_NOT_FOUND);

            // Reconstruct the headerdata.
            var headerdataString = headerdata;
            try {
                headerdata = base64$decode(headerdataString);
            } catch (e) {
                throw new MslMessageException(MslError.HEADER_DATA_INVALID, headerdataString, e);
            }
            if (!headerdata || headerdata.length == 0)
                throw new MslMessageException(MslError.HEADER_DATA_MISSING, headerdataString);

            // Create the correct message crypto context.
            var messageCryptoContext;
            try {
                messageCryptoContext = getMessageCryptoContext(ctx, entityAuthData, masterToken);
            } catch (e) {
                if (e instanceof MslException) {
                    e.setEntity(masterToken);
                    e.setEntity(entityAuthData);
                }
                throw e;
            }
            
            // Verify and decrypt the header data.
            messageCryptoContext.verify(headerdata, signature, {
                result: function(verified) {
                    AsyncExecutor(callback, function() {
                        if (verified) {
                            messageCryptoContext.decrypt(headerdata, {
                                result: function(plaintext) {
                                    AsyncExecutor(callback, function() {
                                        var headerdataJson = textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET);
                                        reconstructHeader(messageCryptoContext, headerdata, plaintext, signature, verified, headerdataJson);
                                    });
                                },
                                error: callback.error,
                            });
                        } else {
                            reconstructHeader(messageCryptoContext, null, null, signature, verified, null);
                        }
                    });
                },
                error: callback.error,
            });
        });

        function reconstructHeader(messageCryptoContext, headerdata, plaintext, signature, verified, headerdataJson) {
            AsyncExecutor(callback, function() {
                // If verification failed we cannot parse the plaintext.
                if (!plaintext) {
                    var headerData = new HeaderData(null, 1, null, false, false, null, [], null, null, null, []);
                    var headerPeerData = new HeaderPeerData(null, null, []);
                    var creationData = new CreationData(null, null, messageCryptoContext, headerdata, plaintext, signature, verified, false);
                    new MessageHeader(ctx, entityAuthData, masterToken, headerData, headerPeerData, creationData, callback);
                    return;
                }
                
                // Reconstruct header JSON object.
                var headerdataJO;
                try {
                    headerdataJO = JSON.parse(headerdataJson);
                } catch (e) {
                    if (e instanceof SyntaxError)
                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson, e).setEntity(masterToken).setEntity(entityAuthData);
                    throw e;
                }

                // Pull the message ID first because any error responses need to
                // use it.
                var messageId = parseInt(headerdataJO[KEY_MESSAGE_ID]);

                // Verify message ID.
                if (!messageId || messageId != messageId)
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData);
                if (messageId < 0 || messageId > MslConstants$MAX_LONG_VALUE)
                    throw new MslMessageException(MslError.MESSAGE_ID_OUT_OF_RANGE, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData);

                // If the message was sent with a master token pull the sender.
                var sender = (masterToken) ? headerdataJO[KEY_SENDER] : null;
                if (masterToken && (!sender || typeof sender !== 'string'))
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData).setMessageId(messageId);
                var recipient = (headerdataJO[KEY_RECIPIENT] !== 'undefined') ? headerdataJO[KEY_RECIPIENT] : null;
                if (recipient && typeof recipient !== 'string')
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData).setMessageId(messageId);

                // Pull and verify key response data.
                var keyResponseDataJo = headerdataJO[KEY_KEY_RESPONSE_DATA];
                if (keyResponseDataJo && typeof keyResponseDataJo !== 'object')
                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson).setEntity(masterToken).setEntity(entityAuthData).setMessageId(messageId);

                // Change the callback so we can add the message Id to
                // any thrown exceptions.
                var originalCallback = callback;
                callback = {
                        result: function(ret) { originalCallback.result(ret); },
                        error: function(e) {
                            if (e instanceof MslException) {
                                e.setEntity(masterToken);
                                e.setEntity(entityAuthData);
                                e.setMessageId(messageId);
                            }
                            originalCallback.error(e);
                        }
                };

                // Grab primary token verification master token.
                getKeyResponseData(ctx, keyResponseDataJo, {
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
                            var userIdTokenJo = headerdataJO[KEY_USER_ID_TOKEN];
                            if (userIdTokenJo && typeof userIdTokenJo !== 'object')
                                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                            getUserIdToken(ctx, userIdTokenJo, tokenVerificationMasterToken, {
                                result: function(userIdToken) {
                                    AsyncExecutor(callback, function() {
                                        // Pull user authentication data.
                                        var userAuthDataJo = headerdataJO[KEY_USER_AUTHENTICATION_DATA];
                                        if (userAuthDataJo && typeof userAuthDataJo !== 'object')
                                            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                                        getUserAuthData(ctx, tokenVerificationMasterToken, userAuthDataJo, {
                                            result: function(userAuthData) {
                                                AsyncExecutor(callback, function() {
                                                    // Verify the user authentication data.
                                                    var user;
                                                    if (userAuthData) {
                                                        var scheme = userAuthData.scheme;
                                                        var factory = ctx.getUserAuthenticationFactory(scheme);
                                                        if (!factory)
                                                            throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme).setUser(userIdToken).setUser(userAuthData);
                                                        var identity = (masterToken) ? masterToken.identity : entityAuthData.getIdentity();
                                                        user = factory.authenticate(ctx, identity, userAuthData, userIdToken);
                                                    } else if (userIdToken) {
                                                        user = userIdToken.user;
                                                    } else {
                                                        user = null;
                                                    }

                                                    // Service tokens are authenticated by the master token if it
                                                    // exists or by the application crypto context.
                                                    var tokensJA = headerdataJO[KEY_SERVICE_TOKENS];
                                                    getServiceTokens(ctx, tokensJA, tokenVerificationMasterToken, userIdToken, cryptoContexts, headerdataJson, {
                                                        result: function(serviceTokens) {
                                                            AsyncExecutor(callback, function() {
                                                                var nonReplayableId = (headerdataJO[KEY_NON_REPLAYABLE_ID] !== undefined) ? parseInt(headerdataJO[KEY_NON_REPLAYABLE_ID]) : null;
                                                                var nonReplayable = (headerdataJO[KEY_NON_REPLAYABLE] !== undefined) ? headerdataJO[KEY_NON_REPLAYABLE] : false;
                                                                var renewable = headerdataJO[KEY_RENEWABLE];
                                                                var handshake = (headerdataJO[KEY_HANDSHAKE] !== undefined) ? headerdataJO[KEY_HANDSHAKE] : false;

                                                                // Verify values.
                                                                if (nonReplayableId != nonReplayableId ||
                                                                        typeof nonReplayable !== 'boolean' ||
                                                                        typeof renewable !== 'boolean' ||
                                                                        typeof handshake !== 'boolean')
                                                                {
                                                                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                                                                }
                                                                if (nonReplayableId < 0 || nonReplayableId > MslConstants$MAX_LONG_VALUE)
                                                                    throw new MslMessageException(MslError.NONREPLAYABLE_ID_OUT_OF_RANGE, "headerdata " + headerdataJson);

                                                                // Pull message capabilities.
                                                                var capabilities = null;
                                                                var capabilitiesJO = headerdataJO[KEY_CAPABILITIES];
                                                                if (capabilitiesJO) {
                                                                    if (typeof capabilitiesJO !== 'object')
                                                                        throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "headerdata " + headerdataJson);
                                                                    capabilities = MessageCapabilities$parse(capabilitiesJO);
                                                                }

                                                                // Pull key request data containers.
                                                                getKeyRequestData(ctx, headerdataJO, headerdataJson, {
                                                                    result: function(keyRequestData) {
                                                                        // Get peer-to-peer tokens.
                                                                        getPeerToPeerTokens(ctx, headerdataJO, keyResponseData, cryptoContexts, headerdataJson, {
                                                                            result: function(result) {
                                                                                AsyncExecutor(callback, function() {
                                                                                    var peerMasterToken = result.peerMasterToken;
                                                                                    var peerUserIdToken = result.peerUserIdToken;
                                                                                    var peerServiceTokens = result.peerServiceTokens;

                                                                                    // Return new message header.
                                                                                    var headerData = new HeaderData(recipient, messageId, nonReplayableId, renewable, handshake, capabilities,
                                                                                            keyRequestData, keyResponseData, userAuthData, userIdToken,
                                                                                            serviceTokens);
                                                                                    var headerPeerData = new HeaderPeerData(peerMasterToken, peerUserIdToken, peerServiceTokens);
                                                                                    var creationData = new CreationData(user, sender, messageCryptoContext, headerdata, plaintext, signature, verified, nonReplayable);
                                                                                    new MessageHeader(ctx, entityAuthData, masterToken, headerData, headerPeerData, creationData, callback);
                                                                                });
                                                                            },
                                                                            error: callback.error,
                                                                        });
                                                                    },
                                                                    error: function(e) {
                                                                        AsyncExecutor(callback, function() {
                                                                            if (e instanceof MslException) {
                                                                                e.setUser(userIdToken);
                                                                                e.setUser(userAuthData);
                                                                            }
                                                                            throw e;
                                                                        });
                                                                    }
                                                                });
                                                            });
                                                        },
                                                        error: function(e) {
                                                            AsyncExecutor(callback, function() {
                                                                if (e instanceof MslException) {
                                                                    e.setEntity(tokenVerificationMasterToken);
                                                                    e.setUser(userIdToken);
                                                                    e.setUser(userAuthData);
                                                                }
                                                                throw e;
                                                            });
                                                        }
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
    };
})();
