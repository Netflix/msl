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
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    
    /**
     * A set of encryption, HMAC, and wrapping keys.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    var KeySet = Class.create({
        /**
         * Create a new key set with the given keys.
         * 
         * @param {SecretKey} encryptionKey the encryption key.
         * @param {SecretKey} hmacKey the HMAC key.
         * @param {SecretKey} wrappingKey the wrapping key.
         */
        init: function init(encryptionKey, hmacKey, wrappingKey) {
            // The properties.
            var props = {
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
                wrappingKey: { value: wrappingKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    });

    /**
     * A key set store contains trusted key sets.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     * @interface
     */
    var KeySetStore = module.exports = Class.create({
        /**
         * Return the encryption, HMAC, and wrapping keys for the given identity.
         * 
         * @param {string} identity key set identity.
         * @return {KeySet} the keys set associated with the identity or null if not found.
         */
        getKeys: function(identity) {},
    });
    
    // Exports.
    module.exports.KeySet = KeySet;
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeySetStore'));
