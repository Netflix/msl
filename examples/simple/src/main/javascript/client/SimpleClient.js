/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

(function(require, module) {
    "use strict";

    var Class = require('msl-core/util/Class.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var EmailPasswordAuthenticationData = require('msl-core/userauth/EmailPasswordAuthenticationData.js');
    var KeyFormat = require('msl-core/crypto/KeyFormat.js');
    var MslCrypto = require('msl-core/crypto/MslCrypto.js');
    var MslIoException = require('msl-core/MslIoException.js');
    var Url = require('msl-core/io/Url.js');
    var WebCryptoAlgorithm = require('msl-core/crypto/WebCryptoAlgorithm.js');
    var WebCryptoUsage = require('msl-core/crypto/WebCryptoUsage.js');
    var Xhr = require('msl-core/io/Xhr.js');
    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var MslControl = require('msl-core/msg/MslControl.js');
    var PublicKey = require('msl-core/crypto/PublicKey.js');
    var RsaStore = require('msl-core/entityauth/RsaStore.js');

    var SimpleKeyxManager = require('./keyx/SimpleKeyxManager.js');
    var AdvancedRequestMessageContext = require('./msg/AdvancedRequestMessageContext.js');
    var SimpleRequestMessageContext = require('./msg/SimpleRequestMessageContext.js');
    var SimpleRequest = require('./msg/SimpleRequest.js');
    var SimpleMslContext = require('./util/SimpleMslContext.js');
    var SimpleConstants = require('./SimpleConstants.js');

    /**
     * <p>An example JavaScript MSL client that sends requests to the example
     * Java MSL server.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleClient = module.exports = Class.create({
        /**
         * <p>Create a new client.</p>
         *
         * @param {string} identity the client entity identity.
         * @param {?FilterStreamFactory} factory the filter stream factory to
         *        attach to the MSL control.
         * @param {result: function(SimpleClient), error: function(msgOrError)}
         *        callback the callback that will receive the created client or
         *        any thrown exceptions.
         */
        init: function init(identity, factory, callback) {
            var self = this;

            // Import the server RSA public key.
            PublicKey.import(SimpleConstants.RSA_PUBKEY_B64, WebCryptoAlgorithm.RSASSA_SHA256, WebCryptoUsage.VERIFY, KeyFormat.SPKI, {
                result: function(publicKey) {
                	AsyncExecutor(callback, function() {
	                    // Create the key manager.
	                	var mechanism = (MslCrypto.getWebCryptoVersion() == MslCrypto.WebCryptoVersion.LEGACY)
	                		? AsymmetricWrappedExchange.Mechanism.JWE_RSA
	                		: AsymmetricWrappedExchange.Mechanism.JWK_RSA;
	                    SimpleKeyxManager.create(mechanism, {
	                        result: function(keyxMgr) {
	                            AsyncExecutor(callback, function() {
	                                // Create the RSA key store.
	                                var rsaStore = new RsaStore();
	                                rsaStore.addPublicKey(SimpleConstants.SERVER_ID, publicKey);

	                                // Set up the MSL context.
	                                var ctx = new SimpleMslContext(identity, rsaStore, keyxMgr, callback.error);

	                                // Create the MSL control.
	                                var ctrl = new MslControl();
	                                ctrl.setFilterFactory(factory);

	                                // Set properties.
	                                var props = {
	                                    _keyxMgr: { value: keyxMgr, writable: false, enumerable: false, configurable: false },
	                                    _rsaStore: { value: rsaStore, writable: false, enumerable: false, configurable: false },
	                                    _identity: { value: identity, writable: true, enumerable: false, configurable: false },
	                                    _ctx: { value: ctx, writable: true, enumerable: false, configurable: false },
	                                    _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
	                                    _cancelFunc: { value: null, writable: true, enumerable: false, configurable: false },
	                                };
	                                Object.defineProperties(this, props);

	                                // Return the client.
	                                return this;
	                            }, self);
	                        },
	                        error: callback.error,
	                    });
                	}, self);
                },
                error: callback.error,
            });
        },

        /**
         * <p>Add an RSA public key to the RSA key store.</p>
         *
         * @param {string} identity the remote entity's identity (i.e. RSA key
         *        pair identity).
         * @param {PublicKey} key the RSA public key.
         */
        addRsaPublicKey: function addRsaPublicKey(identity, key) {
            this._rsaStore.addPublicKey(identity, key);
        },

        /**
         * <p>Reset all state data.</p>
         */
        reset: function reset() {
            var store = this._ctx.getMslStore();
            store.clearCryptoContexts();
            store.clearUserIdTokens();
            store.clearServiceTokens();
        },

        /**
         * <p>Set the entity identity. If the identity has not changed then
         * this method does nothing. If the identity has changed then all data
         * is reset and the new entity identity will be used.</p>
         *
         * @param {string} identity the new entity identity.
         * @param {function(msgOrError)}
         *        callback the callback that will any thrown exceptions.
         */
        setIdentity: function setIdentity(identity, callback) {
            if (this._identity != identity) {
                this._identity = identity;
                this._ctx = new SimpleMslContext(identity, this._rsaStore, this._keyxMgr, callback);
            }
        },

        /**
         * <p>Check if a specific user is "logged in", i.e. a user ID token
         * already exists for the user.</p>
         *
         * @param {string} userId the user ID to check.
         * @return {boolean} true if a user ID token exists.
         */
        isLoggedIn: function isLoggedIn(userId) {
            var store = this._ctx.getMslStore();
            var userIdToken = store.getUserIdToken(userId);
            return (userIdToken) ? true : false;
        },

        /**
         * <p>"Logout" a specific user, i.e. delete its user ID token.</p>
         */
        logout: function logout(userId) {
            var store = this._ctx.getMslStore();
            var userIdToken = store.getUserIdToken(userId);
            if (userIdToken)
                store.removeUserIdToken(userIdToken);
        },

        /**
         * <p>Send a request and receive the response.</p>
         *
         * @param {string} endpoint the HTTP endpoint to send the request to.
         * @param {?string} username username or {@code null} if the request is
         *        not associated with a user.
         * @param {?string} password user password or {@code null} if already
         *        logged in or unknown.
         * @param {SimpleRequest|AdvancedRequest} request the request to send.
         * @param {?MessageDebugContext} dbgCtx message debug context. May be
         *        {@code null}.
         * @param {result: function(MslChannel), error: function(Error)}
         *        callback the callback that will receive the established MSL
         *        channel, which may be {@code null} if cancelled or
         *        interrupted, or any thrown errors.
         */
        send: function send(endpoint, username, password, request, dbgCtx, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                // Build the message context.
                var userAuthData = (username && password)
                    ? new EmailPasswordAuthenticationData(username, password)
                    : null;
                var errorCallback = function errorCallback(msgOrError) {
                    if (typeof msgOrError === 'string')
                        callback.error(new Error(msgOrError));
                    else
                        callback.error(msgOrError);
                };

                // Simple or advanced request?
                var msgCtx;
                if (request instanceof SimpleRequest) {
                    msgCtx = new SimpleRequestMessageContext(username, userAuthData, request, this._keyxMgr, dbgCtx, errorCallback);
                } else {
                    msgCtx = new AdvancedRequestMessageContext(username, userAuthData, request, this._keyxMgr, dbgCtx, errorCallback);
                }

                // Create the URL instance.
                var xhr = new Xhr(endpoint);
                var url = new Url(xhr, SimpleConstants.TIMEOUT_MS);

                // Send the request.
                this._cancelFunc = this._ctrl.request(this._ctx, msgCtx, url, SimpleConstants.TIMEOUT_MS, {
                    result: function(channel) {
                        AsyncExecutor(callback, function() {
                            this._cancelFunc = null;
                            return channel;
                        }, self);
                    },
                    timeout: function() {
                        AsyncExecutor(callback, function() {
                            this._cancelFunc = null;
                            throw new MslIoException("Request timed out.");
                        }, self);
                    },
                    error: callback.error
                });
            }, self);
        },

        /**
         * <p>Cancel any outstanding request. This method does nothing if there
         * is no such request.</p>
         */
        cancel: function cancel() {
            this._cancelFunc.call();
        },
    });

    /**
     * <p>Create a new client.</p>
     *
     * @param {string} identity the client entity identity.
     * @param {?FilterStreamFactory} factory the filter stream factory to
     *        attach to the MSL control.
     * @param {result: function(SimpleClient), error: function(msgOrError)}
     *        callback the callback that will receive the created client or
     *        any thrown exceptions.
     */
    var SimpleClient$create = function SimpleClient$create(identity, factory, callback) {
        new SimpleClient(identity, factory, callback);
    };
    
    // Exports.
    module.exports.create = SimpleClient$create;
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleClient'));
