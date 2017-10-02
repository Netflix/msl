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
 * <p>Entity authentication schemes.</p>
 * 
 * <p>The scheme name is used to uniquely identify entity authentication
 * schemes.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var Class = require('../util/Class.js');
    
    /** Map of names onto schemes. */
    var schemes = {};
    
    var EntityAuthenticationScheme = module.exports = Class.create({
        /**
         * Define an entity authentication scheme with the specified name and
         * cryptographic properties.
         * 
         * @param {string} name the entity authentication scheme name.
         * @param {boolean} encrypts true if the scheme encrypts message data.
         * @param {boolean} protects true if the scheme protects message integrity.
         */
        init: function init(name, encrypts, protects) {
            // The properties.
            var props = {
                name: { value: name, writable: false, configurable: false },
                encrypts: { value: encrypts, writable: false, configurable: false },
                protectsIntegrity: { value: protects, writable: false, configurable: false },
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

    Class.mixin(EntityAuthenticationScheme,
    /** @lends {EntityAuthenticationScheme} */
    ({
        /** Pre-shared keys. */
        PSK : new EntityAuthenticationScheme("PSK", true, true),
        /** Pre-shared keys with entity profiles. */
        PSK_PROFILE : new EntityAuthenticationScheme("PSK_PROFILE", true, true),
        /** X.509 public/private key pair. */
        X509 : new EntityAuthenticationScheme("X509", false, true),
        /** RSA public/private key pair. */
        RSA : new EntityAuthenticationScheme("RSA", false, true),
        /** ECC public/private key pair. */
        ECC: new EntityAuthenticationScheme("ECC", false, true),
        /** Unauthenticated. */
        NONE : new EntityAuthenticationScheme("NONE", false, false),
        /** Unauthenticated suffixed. */
        NONE_SUFFIXED : new EntityAuthenticationScheme("NONE_SUFFIXED", false, false),
        /** Master token protected. */
        MT_PROTECTED : new EntityAuthenticationScheme("MT_PROTECTED", false, false),
        /** Provisioned. */
        PROVISIONED : new EntityAuthenticationScheme("PROVISIONED", false, false),
        /** ESN Migration. */
        MIGRATION : new EntityAuthenticationScheme("MIGRATION", false, false),
    }));

    /**
     * @param {string} name the entity authentication scheme name.
     * @return {?EntityAuthenticationScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    var EntityAuthenticationScheme$getScheme = function EntityAuthenticationScheme$getScheme(name) {
        return (schemes[name]) ? schemes[name] : null;
    };
    
    // Exports.
    Object.defineProperties(EntityAuthenticationScheme, {
        getScheme: { value: EntityAuthenticationScheme$getScheme, writable: false, enumerable: false, configurable: false },
    });
    Object.freeze(EntityAuthenticationScheme);
})(require, (typeof module !== 'undefined') ? module : mkmodule('EntityAuthenticationScheme'));
