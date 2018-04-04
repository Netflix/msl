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

    var AsymmetricWrappedExchange = require('msl-core/keyx/AsymmetricWrappedExchange.js');
    var AsyncExecutor = require('msl-core/util/AsyncExecutor.js');
    var MessageContext = require('msl-core/msg/MessageContext.js');
    var MslConstants = require('msl-core/MslConstants.js');
    var TextEncoding = require('msl-core/util/TextEncoding.js');

    var SimpleRequest = require('../msg/SimpleRequest.js');
    var SimpleConstants = require('../SimpleConstants.js');

    // Shortcuts.
    var Mechanism = AsymmetricWrappedExchange.Mechanism;
    var RequestData = AsymmetricWrappedExchange.RequestData;
    var Type = SimpleRequest.Type;

    /**
     * <p>Example client message context for sending request messages.</p>
     *
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var SimpleRequestMessageContext = module.exports = MessageContext.extend({
        /**
         * <p>Create a new simple request message context.</p>
         *
         * @param {?string} requesting user ID. May be {@code null}.
         * @param {?UserAuthenticationData} requesting user authentication data.
         *        May be {@code null}.
         * @param {SimpleRequest} request the request.
         * @param {SimpleKeyxManager} keyxMgr key exchange manager.
         * @param {?MessageDebugContext} dbgCtx message debug context. May be
         *        {@code null}.
         * @param {function(string|Error)} errorCallback message error callback.
         */
        init: function init(userId, userAuthData, request, keyxMgr, dbgCtx, errorCallback) {
            // Set properties.
            var props = {
                _userId: { value: userId, writable: false, enumerable: false, configurable: false },
                _userAuthData: { value: userAuthData, writable: false, enumerable: false, configurable: false },
                _request: { value: request, writable: false, enumerable: false, configurable: false },
                _keyxMgr: { value: keyxMgr, writable: false, enumerable: false, configurable: false },
                _dbgCtx: { value: dbgCtx, writable: false, enumerable: false, configurable: false },
                _errorCallback: { value: errorCallback, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getCryptoContexts: function getCryptoContexts() {
            return {};
        },

        /** @inheritDoc */
        getRemoteEntityIdentity: function() {
            return SimpleConstants.SERVER_ID;
        },

        /** @inheritDoc */
        isEncrypted: function() {
            switch (this._request.type) {
                case Type.QUERY:
                case Type.QUIT:
                    return false;
                case Type.ECHO:
                case Type.LOG:
                case Type.USER_PROFILE:
                    /* falls through */
                default:
                    return true;
            }
        },

        /** @inheritDoc */
        isIntegrityProtected: function isIntegrityProtected() {
            return true;
        },

        /** @inheritDoc */
        isNonReplayable: function isNonReplayable() {
            return false;
        },

        /** @inheritDoc */
        isRequestingTokens: function() {
            if (this._request.type == Type.LOG)
                return true;
            return false;
        },

        /** @inheritDoc */
        getUserId: function() {
            return this._userId;
        },

        /** @inheritDoc */
        getUserAuthData: function(reauthCode, renewable, required, callback) {
            AsyncExecutor(callback, function() {
                if (!this._userId)
                    return null;

                // If new user authentication data is required then fail and
                // return null. Notify the application.
                if (reauthCode) {
                    this._errorCallback("New user authentication data is required: " + reauthCode + ".");
                    return null;
                }

                // Ignore the renewable flag. We never perform user
                // verification.
                //
                // Return any user authentication data we have.
                return this._userAuthData;
            }, this);
        },

        /** @inheritDoc */
        getUser: function getUser() {
            return null;
        },

        /** @inheritDoc */
        getKeyRequestData: function(callback) {
            AsyncExecutor(callback, function() {
            	var mechanism = this._keyxMgr.getMechanism();
                var keyPair = this._keyxMgr.getKeyPair();
                var request = new RequestData("keyPairId", mechanism, keyPair.publicKey, keyPair.privateKey);
                return [ request ];
            }, this);
        },

        /** @inheritDoc */
        updateServiceTokens: function updateServiceTokens(builder, handshake, callback) {
            callback.result(true);
        },

        /** @inheritDoc */
        write: function(output, timeout, callback) {
            AsyncExecutor(callback, function() {
                var json = JSON.stringify(this._request);
                var jsonBytes = TextEncoding.getBytes(json, MslConstants.DEFAULT_CHARSET);
                output.write(jsonBytes, 0, jsonBytes.length, timeout, {
                    result: function(numWritten) {
                        // Technically we should check that numWritten is equal
                        // to jsonBytes.length but we know that should never
                        // be false based on our current implementation. So
                        // just close the stream.
                        output.close(timeout, callback);
                    },
                    timeout: callback.timeout,
                    error: callback.error,
                });
            }, this);
        },

        /** @inheritDoc */
        getDebugContext: function getDebugContext() {
            return this._dbgCtx;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('SimpleRequestMessageContext'));
