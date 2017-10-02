/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Key exchange schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify key exchange schemes.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var Class = require('../util/Class.js');
    
    /** Map of names onto schemes. */
    var schemes = {};
    
    var KeyExchangeScheme = module.exports = Class.create({
        /**
         * Define a key exchange scheme with the specified name.
         * 
         * @param {string} name the key exchange scheme name.
         */
        init: function init(name) {
            // The properties.
            var props = {
                name: { value: name, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
    
            // Add this scheme to the map.
            schemes[name] = this;
        },

        /** @inheritDoc */
        toString: function toString() {
            return this.name;
        },
    });
    
    Class.mixin(KeyExchangeScheme,
    /** @lends {KeyExchangeScheme} */
    ({
        /** Asymmetric key wrapped. */
        ASYMMETRIC_WRAPPED : new KeyExchangeScheme("ASYMMETRIC_WRAPPED"),
        /** Diffie-Hellman exchange (Netflix SHA-384 key derivation). */
        DIFFIE_HELLMAN : new KeyExchangeScheme("DIFFIE_HELLMAN"),
        /** JSON web encryption ladder exchange. */
        JWE_LADDER : new KeyExchangeScheme("JWE_LADDER"),
        /** JSON web key ladder exchange. */
        JWK_LADDER : new KeyExchangeScheme("JWK_LADDER"),
        /** Symmetric key wrapped. */
        SYMMETRIC_WRAPPED : new KeyExchangeScheme("SYMMETRIC_WRAPPED"),
    }));

    /**
     * @param {string} name the key exchange scheme name.
     * @return {?KeyExchangeScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    var KeyExchangeScheme$getScheme = function KeyExchangeScheme$getScheme(name) {
        return (schemes[name]) ? schemes[name] : null;
    };
    
    // Exports.
    Object.defineProperties(KeyExchangeScheme, {
        getScheme: { value: KeyExchangeScheme$getScheme, writable: false, enumerable: false, configurable: false },
    });
    Object.freeze(KeyExchangeScheme);
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyExchangeScheme'));