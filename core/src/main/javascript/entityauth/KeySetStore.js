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
var KeySet;
var KeySetStore;

(function() {
    "use strict";
    
    /**
     * A set of encryption, HMAC, and wrapping keys.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     */
    KeySet = util.Class.create({
        /**
         * Create a new key set with the given keys.
         * 
         * @param {CipherKey} encryptionKey the encryption key.
         * @param {CipherKey} hmacKey the HMAC key.
         * @param {CipherKey} wrappingKey the wrapping key.
         */
        init: function init(encryptionKey, hmacKey, wrappingKey) {
            // The properties.
            var props = {
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
                wrappingKey: { value: wrappingKey, writable: false, configurable: false },
            }
        },
    });

    /**
     * A key set store contains trusted key sets.
     * 
     * @author Wesley Miaw <wmiaw@netflix.com>
     * @interface
     */
    KeySetStore = util.Class.create({
        /**
         * Return the encryption, HMAC, and wrapping keys for the given identity.
         * 
         * @param {string} identity key set identity.
         * @return {KeySet} the keys set associated with the identity or null if not found.
         */
        getKeys: function(identity) {},
    });
})();
