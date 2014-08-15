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
     * <p>An example JavaScript MSL client that sends requests to the example
     * Java MSL server.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    SimpleClient = util.Class.create({
        /**
         * <p>Create a new client.</p>
         *
         * @param {function(String)} errorCallback generic error callback.
         * @param {result: function(SimpleClient), error: function(Error)}
         *        callback the callback that will receive the created client or
         *        any thrown exceptions.
         */
        init: function init(errorCallback, callback) {
            // Import the server RSA public key.
            PublicKey$import(SimpleConstants.RSA_PUBKEY_B64, WebCryptoAlgorithm.RSASSA_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                result: function(publicKey) {
                    AsyncExecutor(callback, function() {
                        // Create the RSA key store.
                        var rsaStore = new RsaStore();
                        rsaStore.addPublicKey(SimpleConstants.SERVER_ID, publicKey);

                        // Set up the MSL context.
                        var keyxMgr = new SimpleKeyxManager();
                        var ctx = new SimpleMslContext(SimpleConstants.CLIENT_ID, rsaStore, keyxMgr, errorCallback);

                        // Create the MSL control.
                        var ctrl = new MslControl();

                        // Set properties.
                        var props = {
                            _ctrl: { value: ctrl, writable: false, enumerable: false, configurable: false },
                            _ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                        };
                        Object.setProperties(this, props);

                        // Return the client.
                        return this;
                    }, this);
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
            store.removeUserIdToken(userId);
        },
    });

    /**
     * <p>Create a new client.</p>
     *
     * @param {function(String)} errorCallback generic error callback.
     * @param {result: function(SimpleClient), error: function(Error)}
     *        callback the callback that will receive the created client or
     *        any thrown exceptions.
     */
    SimpleClient$create = function SimpleClient$create(errorCallback, callback) {
        new SimpleClient(errorCallback, callback);
    };
})();