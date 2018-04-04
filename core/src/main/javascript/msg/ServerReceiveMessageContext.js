/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
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
 * <p>A trusted services network message context used to receive client
 * messages suitable for use with
 * {@link MslControl#receive(com.netflix.msl.util.MslContext, MessageContext, java.io.InputStream, java.io.OutputStream, int)}.
 * Since this message context is only used for receiving messages, it cannot be
 * used to send application data back to the client and does not require
 * encryption or integrity protection.</p>
 * 
 * <p>The application may wish to override
 * {@link #updateServiceTokens(MessageServiceTokenBuilder, boolean)} to
 * modify any service tokens sent in handshake responses.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var PublicMessageContext = require('../msg/PublicMessageContext.js');
    
    var ServerReceiveMessageContext = module.exports = PublicMessageContext.extend({
        /**
         * <p>Create a new receive message context.</p>
         * 
         * @param {Object<string,ICryptoContext>} cryptoContexts service token crypto contexts. May be
         *        {@code null}.
         * @param {MessageDebugContext} dbgCtx optional message debug context. May be {@code null}.
         */
        init: function init(cryptoContexts, dbgCtx) {
            init.base.call(this);
            
            // Make a shallow copy of the crypto contexts.
            var contexts = {};
            if (cryptoContexts) {
                for (var name in cryptoContexts)
                    contexts[name] = cryptoContexts[name];
            }
            
            // The properties.
            var props = {
                cryptoContexts: { value: contexts, writable: true, enumerable: false, configurable: false },
                dbgCtx: { value: dbgCtx, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getCryptoContexts: function getCryptoContexts() {
            return {};
        },

        /** @inheritDoc */
        getRemoteEntityIdentity: function getRemoteEntityIdentity() {
            return null;
        },

        /** @inheritDoc */
        isRequestingTokens: function isRequestingTokens() {
            return false;
        },

        /** @inheritDoc */
        getUserId: function getUserId() {
            return null;
        },

        /** @inheritDoc */
        getUserAuthData: function getUserAuthData(reauthCode, renewable, required, callback) {
            callback.result(null);
        },

        /** @inheritDoc */
        getUser: function getUser() {
            return null;
        },

        /** @inheritDoc */
        getKeyRequestData: function getKeyRequestData(callback) {
            callback.result([]);
        },
        
        /** @inheritDoc */
        updateServiceTokens: function updateServiceTokens(builder, handshake, callback) {
            callback.result(true);
        },

        /** @inheritDoc */
        write: function write(output, timeout, callback) {
            callback.result(true);
        },

        /** @inheritDoc */
        getDebugContext: function getDebugContext() {
            return this.dbgCtx;
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('ServerReceiveMessageContext'));