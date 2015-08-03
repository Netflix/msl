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
 * <p>A message service token builder provides methods for intelligently
 * manipulating the primary and peer service tokens that will be included in a
 * message.</p>
 *
 * <p>There are two categories of service tokens: primary and peer.
 * <ul>
 * <li>Primary service tokens are associated with the primary master token and
 * peer user ID token, and are the only category of service token to appear in
 * trusted network mode. Primary service tokens are also used in peer-to-peer
 * mode.</li>
 * <li>Peer service tokens are associated with the peer master token and peer
 * user ID token and only used in peer-to-peer mode.</li>
 * </ul></p>
 *
 * <p>There are three levels of service token binding.
 * <ul>
 * <li>Unbound service tokens may be freely moved between entities and
 * users.</li>
 * <li>Master token bound service tokens must be accompanied by a master token
 * that they are bound to and will be rejected if sent with a different master
 * token or without a master token. This binds a service token to a specific
 * entity.</li>
 * <li>User ID token bound service tokens must be accompanied by a user ID
 * token that they are bound to and will be rejected if sent with a different
 * user or used without a user ID token. This binds a service token to a
 * specific user and by extension a specific entity.</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MessageServiceTokenBuilder;

(function() {
    "use strict";

    /**
     * <p>Select the appropriate crypto context for the named service token.</p>
     * 
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be returned. Otherwise the
     * default crypto context mapped from the empty string key will be returned.
     * If no explicit or default crypto context exists null will be
     * returned.</p>
     *
     * @param {string} name service token name.
     * @param {Object.<string,ICryptoContext>} cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @return the correct crypto context for the service token or null.
     */
    function selectCryptoContext(name, cryptoContexts) {
        if (cryptoContexts[name])
            return cryptoContexts[name];
        return cryptoContexts[""];
    }
    
    /**
     * Returns the master token that primary service tokens should be bound
     * against.
     * 
     * @param {MessageServiceTokenBuilder} stBuilder the message service token
     *        builder.
     * @return {MasterToken} the primary service token master token or {@code null} if there
     *         is none.
     */
    function getPrimaryMasterToken(stBuilder) {
        // If key exchange data is provided and we are not in peer-to-peer mode
        // then its master token will be used for creating service tokens.
        var keyExchangeData = stBuilder.builder.getKeyExchangeData();
        if (keyExchangeData && !stBuilder.ctx.isPeerToPeer()) {
            return keyExchangeData.keyResponseData.masterToken;
        } else {
            return stBuilder.builder.getMasterToken();
        }
    }

    MessageServiceTokenBuilder = util.Class.create({
        /**
         * Create a new message service token builder with the provided MSL and
         * message contexts and message builder.
         *
         * @param {MslContext} ctx MSL context.
         * @param {MessageContext} msgCtx message context.
         * @param {MessageBuilder} builder message builder for message being built.
         */
        init: function init(ctx, msgCtx, builder) {
            // The properties.
            var props = {
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                cryptoContexts: { value: msgCtx.getCryptoContexts(), writable: false, enumerable: false, configurable: false },
                builder: { value: builder, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Returns true if the message has a primary master token available for
         * adding master-bound primary service tokens.
         * 
         * @return {boolean} true if the message has a primary master token.
         */
        isPrimaryMasterTokenAvailable: function isPrimaryMasterTokenAvailable() {
            return (getPrimaryMasterToken(this)) ? true: false;
        },

        /**
         * @return {boolean} true if the message has a primary user ID token.
         */
        isPrimaryUserIdTokenAvailable: function isPrimaryUserIdTokenAvailable() {
            return (this.builder.getUserIdToken()) ? true : false;
        },

        /**
         * @return {boolean} true if the message has a peer master token.
         */
        isPeerMasterTokenAvailable: function isPeerMasterTokenAvailable() {
            return (this.builder.getPeerMasterToken()) ? true : false;
        },

        /**
         * @return {boolean} true if the message has a peer user ID token.
         */
        isPeerUserIdTokenAvailable: function isPeerUserIdTokenAvailable() {
            return (this.builder.getPeerUserIdToken()) ? true : false;
        },

        /**
         * @return {Array.<ServiceToken>} the unmodifiable set of primary service tokens that will be
         *         included in the built message.
         */
        getPrimaryServiceTokens: function getPrimaryServiceTokens() {
            return this.builder.getServiceTokens();
        },

        /**
         * @return {Array.<ServiceToken>} the unmodifiable set of peer service tokens that will be
         *         included in the built message.
         */
        getPeerServiceTokens: function getPeerServiceTokens() {
            return this.builder.getPeerServiceTokens();
        },
        
        /**
         * Adds a primary service token to the message, replacing any existing
         * primary service token with the same name.
         * 
         * @param {ServiceToken} serviceToken primary service token.
         * @return true if the service token was added, false if the service token
         *         is bound to a master token or user ID token and the message does
         *         not have the same token.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the primary master token or primary user ID token of the
         *         message being built.
         */
        addPrimaryServiceToken: function addPrimaryServiceToken(serviceToken) {
            try {
                this.builder.addServiceToken(serviceToken);
                return true;
            } catch (e) {
                if (e instanceof MslMessageException)
                    return false;
                throw e;
            }
        },
        
        /**
         * Adds a peer service token to the message, replacing any existing peer
         * service token with the same name.
         * 
         * @param {ServiceToken} serviceToken peer service token.
         * @return true if the service token was added, false if the service token
         *         is bound to a master token or user ID token and the message does
         *         not have the same token.
         * @throws MslMessageException if the service token serial numbers do not
         *         match the peer master token or peer user ID token of the message
         *         being built.
         */
        addPeerServiceToken: function addPeerServiceToken(serviceToken) {
            try {
                this.builder.addPeerServiceToken(serviceToken);
                return true;
            } catch (e) {
                if (e instanceof MslMessageException)
                    return false;
                throw e;
            }
        },

        /**
         * Adds a new unbound primary service token to the message, replacing any
         * existing primary service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token, or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addUnboundPrimaryServiceToken: function addUnboundPrimaryServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;

                // Add the service token.
                ServiceToken$create(this.ctx, name, data, null, null, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            try {
                                this.builder.addServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Adds a new unbound peer service token to the message, replacing any
         * existing peer service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token, or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addUnboundPeerServiceToken: function addUnboundPeerServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;
                ServiceToken$create(this.ctx, name, data, null, null, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            // Add the service token.
                            try {
                                this.builder.addPeerServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite being unbound.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Adds a new master token bound primary service token to the message,
         * replacing any existing primary service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token or the message does not have a master token, or
         *        any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addMasterBoundPrimaryServiceToken: function addMasterBoundPrimaryServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no master token.
                var masterToken = getPrimaryMasterToken(this);
                if (!masterToken)
                    return false;

                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;

                // Add the service token.
                ServiceToken$create(this.ctx, name, data, masterToken, null, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            try {
                                this.builder.addServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Adds a new master token bound peer service token to the message,
         * replacing any existing peer service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token or the message does not have a peer master
         *        token, or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addMasterBoundPeerServiceToken: function addMasterBoundPeerServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no master token.
                var masterToken = this.builder.getPeerMasterToken();
                if (!masterToken)
                    return false;

                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;

                // Add the service token.
                ServiceToken$create(this.ctx, name, data, masterToken, null, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            try {
                                this.builder.addPeerServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Adds a new user ID token bound primary service token to the message,
         * replacing any existing primary service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token or the message does not have a primary user ID
         *        token, or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addUserBoundPrimaryServiceToken: function addUserBoundPrimaryServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no master token.
                var masterToken = getPrimaryMasterToken(this);
                if (!masterToken)
                    return false;

                // Fail if there is no user ID token.
                var userIdToken = this.builder.getUserIdToken();
                if (!userIdToken)
                    return false;

                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;

                // Add the service token.
                ServiceToken$create(this.ctx, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            try {
                                this.builder.addServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * Adds a new user ID token bound peer service token to the message,
         * replacing any peer existing service token with the same name.
         *
         * @param {string} name service token name.
         * @param {Uint8Array} data service token data.
         * @param {boolean} encrypt true if the service token data should be encrypted.
         * @param {MslConstants$CompressionAlgorithm} compressionAlgo the compression algorithm. May be {@code null}
         *        for no compression.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token was added
         *        and false if there is no crypto context found for this
         *        service token or the message does not have a peer user ID
         *        token, or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslEncodingException if there is an error encoding the JSON
         *         data.
         * @throws MslException if there is an error compressing the data.
         */
        addUserBoundPeerServiceToken: function addUserBoundPeerServiceToken(name, data, encrypt, compressionAlgo, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Fail if there is no master token.
                var masterToken = this.builder.getPeerMasterToken();
                if (!masterToken)
                    return false;

                // Fail if there is no user ID token.
                var userIdToken = this.builder.getPeerUserIdToken();
                if (!userIdToken)
                    return false;

                // Fail if there is no crypto context.
                var cryptoContext = selectCryptoContext(name, this.cryptoContexts);
                if (!cryptoContext)
                    return false;

                // Add the service token.
                ServiceToken$create(this.ctx, name, data, masterToken, userIdToken, encrypt, compressionAlgo, cryptoContext, {
                    result: function(serviceToken) {
                        AsyncExecutor(callback, function() {
                            try {
                                this.builder.addPeerServiceToken(serviceToken);
                            } catch (e) {
                                if (e instanceof MslMessageException)
                                    throw new MslInternalException("Service token bound to incorrect authentication tokens despite setting correct master token and user ID token.", e);
                                throw e;
                            }
                            return true;
                        }, self);
                    },
                    error: function(e) { callback.error(e); }
                });
            }, self);
        },

        /**
         * <p>Exclude a primary service token from the message.</p>
         *
         * <p>The service token will not be sent in the built message. This is not
         * the same as requesting the remote entity delete a service token.</p>
         *
         * @param {string} name service token name.
         * @return {boolean} true if the service token was found and therefore removed.
         */
        excludePrimaryServiceToken: function excludePrimaryServiceToken(name) {
            // Exclude the service token if found.
            var serviceTokens = this.builder.getServiceTokens();
            for (var i = 0; i < serviceTokens.length; ++i) {
                var serviceToken = serviceTokens[i];
                if (serviceToken.name == name) {
                    this.builder.excludeServiceToken(name);
                    return true;
                }
            }

            // Not found.
            return false;
        },

        /**
         * <p>Exclude a peer service token from the message.</p>
         *
         * <p>The service token will not be sent in the built message. This is not
         * the same as requesting the remote entity delete a service token.</p>
         *
         * @param {string} name service token name.
         * @return {boolean} true if the peer service token was found and therefore removed.
         */
        excludePeerServiceToken: function excludePeerServiceToken(name) {
            // Exclude the service token if found.
            var peerServiceTokens = this.builder.getPeerServiceTokens();
            for (var i = 0; i < peerServiceTokens.length; ++i) {
                var serviceToken = peerServiceTokens[i];
                if (serviceToken.name == name) {
                    this.builder.excludePeerServiceToken(name);
                    return true;
                }
            }

            // Not found.
            return false;
        },

        /**
         * <p>Mark a primary service token for deletion, if it exists.</p>
         *
         * <p>The service token will be sent in the built message with an empty
         * value. This is not the same as requesting that a service token be
         * excluded from the message.</p>
         *
         * @param {string} name service token name.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the service token exists
         *        and was marked for deletion, or any thrown exceptions.
         */
        deletePrimaryServiceToken: function deletePrimaryServiceToken(name, callback) {
            AsyncExecutor(callback, function() {
                // Mark the service token for deletion if found.
                var serviceTokens = this.builder.getServiceTokens();
                for (var i = 0; i < serviceTokens.length; ++i) {
                    var serviceToken = serviceTokens[i];
                    if (serviceToken.name == name) {
                        this.builder.deleteServiceToken(name, {
                            result: function() { callback.result(true); },
                            error: function(e) { callback.error(e); }
                        });
                        return;
                    }
                }

                // Not found.
                return false;
            }, this);
        },

        /**
         * <p>Mark a peer service token for deletion, if it exists.</p>
         *
         * <p>The service token will be sent in the built message with an empty
         * value. This is not the same as requesting that a service token be
         * excluded from the message.</p>
         *
         * @param {string} name service token name.
         * @param {{result: function(boolean), error: function(Error)}} callback
         *        the callback will receive true if the peer service token
         *        exists and was marked for deletion, or any thrown exceptions.
         */
        deletePeerServiceToken: function deletePeerServiceToken(name, callback) {
            AsyncExecutor(callback, function() {
                // Mark the service token for deletion if found.
                var peerServiceTokens = this.builder.getPeerServiceTokens();
                for (var i = 0; i < peerServiceTokens.length; ++i) {
                    var serviceToken = peerServiceTokens[i];
                    if (serviceToken.name == name) {
                        this.builder.deletePeerServiceToken(name, {
                            result: function() { callback.result(true); },
                            error: function(e) { callback.error(e); }
                        });
                        return;
                    }
                }

                // Not found.
                return false;
            }, this);
        },
    });
})();
