/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
var SimpleClient;
var SimpleClient$create;

(function() {
    "use strict";
    
    /**
     * <p>An HTTP location that is implemented using XMLHttpRequest.</p>
     */
    var Xhr = IHttpLocation.extend({
        /**
         * <p>Create a new XHR pointing at the specified endpoint.
         * 
         * @param {string} endpoint the url to send the request to.
         */
        init: function(endpoint) {
            // Set properties.
            var props = {
                _endpoint: { value: endpoint, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        getResponse: function getResponse(request, timeout, callback) {
            var self = this;
            
            InterruptibleExecutor(callback, function() {
                var xhr = new XMLHttpRequest();
                xhr.onload = function onload() {
                    callback.result({body: this.responseText});
                };
                xhr.open("POST", this._endpoint);
                xhr.timeout = timeout;
                xhr.send(request.body);
            }, self);
        },
    });

    /**
     * <p>An example JavaScript MSL client that sends requests to the example
     * Java MSL server.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    SimpleClient = util.Class.create({
        /**
         * <p>Create a new client.</p>
         *
         * @param {?FilterStreamFactory} factory the filter stream factory to
         *        attach to the MSL control.
         * @param {result: function(SimpleClient), error: function(Error)}
         *        callback the callback that will receive the created client or
         *        any thrown exceptions.
         */
        init: function init(factory, callback) {
            var self = this;
            
            // Import the server RSA public key.
            PublicKey$import(SimpleConstants.RSA_PUBKEY_B64, WebCryptoAlgorithm.RSASSA_SHA256, WebCryptoUsage.VERIFY, {
                result: function(publicKey) {
                	AsyncExecutor(callback, function() {
	                    // Create the key manager.
	                	var mechanism = (MslCrypto$getWebCryptoVersion() == MslCrypto$WebCryptoVersion.LEGACY)
	                		? AsymmetricWrappedExchange$Mechanism.JWE_RSA
	                		: AsymmetricWrappedExchange$Mechanism.JWK_RSA;
	                    SimpleKeyxManager$create(mechanism, {
	                        result: function(keyxMgr) {
	                            AsyncExecutor(callback, function() {
	                                // Create the RSA key store.
	                                var rsaStore = new RsaStore();
	                                rsaStore.addPublicKey(SimpleConstants.SERVER_ID, publicKey);
	
	                                // Set up the MSL context.
	                                var ctx = new SimpleMslContext(SimpleConstants.CLIENT_ID, rsaStore, keyxMgr, errorCallback);
	
	                                // Create the MSL control.
	                                var ctrl = new MslControl();
	                                ctrl.setFilterFactory(factory);
	
	                                // Set properties.
	                                var props = {
	                                    _keyxMgr: { value: keyxMgr, writable: false, enumerable: false, configurable: false },
	                                    _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
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
         * @param {SimpleRequest} request the request to send.
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
                var msgCtx = new SimpleRequestMessageContext(username, userAuthData, request, this._keyxMgr, dbgCtx, errorCallback);
                
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
     * @param {?FilterStreamFactory} factory the filter stream factory to
     *        attach to the MSL control.
     * @param {result: function(SimpleClient), error: function(Error)}
     *        callback the callback that will receive the created client or
     *        any thrown exceptions.
     */
    SimpleClient$create = function SimpleClient$create(factory, callback) {
        new SimpleClient(factory, callback);
    };
})();