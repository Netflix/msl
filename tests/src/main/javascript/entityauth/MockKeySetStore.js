/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
 * Test key set store.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var KeySetStore = require('msl-core/entityauth/KeySetStore.js');
    
    var MockKeySetStore = module.exports = KeySetStore.extend({
        /**
         * Create a new test key set store.
         */
        init: function init() {
            var keysets = {};

            // The properties.
            var props = {
                keysets: { value: keysets, writable: true, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Add a key set to the store.
         * 
         * @param {string} identity key set identity.
         * @param {SecretKey} encryptionKey the encryption key.
         * @param {SecretKey} hmacKey the HMAC key.
         * @param {SecretKey} wrappingKey the wrapping key.
         */
        addKeys: function addKeys(identity, encryptionKey, hmacKey, wrappingKey) {
            var keyset = new KeySetStore.KeySet(encryptionKey, hmacKey, wrappingKey);
            this.keysets[identity] = keyset;
        },

        /**
         * Remove all preshared key sets from the store.
         */
        clear: function clear() {
            this.keysets = {};
        },

        /** @inheritDoc */
        getKeys: function getKeys(identity) {
            return this.keysets[identity];
        },
    });
})(require, (typeof module !== 'undefined') ? module : mkmodule('MockKeySetStore'));