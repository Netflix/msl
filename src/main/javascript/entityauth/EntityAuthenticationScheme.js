/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
var EntityAuthenticationScheme;
var EntityAuthenticationScheme$getScheme;

(function() {
    "use strict";
    
    /** Map of names onto schemes. */
    var schemes = {};
    
    /**
     * Define an entity authentication scheme with the specified name and
     * cryptographic properties.
     * 
     * @param {string} name the entity authentication scheme name.
     * @param {boolean} encrypts true if the scheme encrypts message data.
     * @param {boolean} protects true if the scheme protects message integrity.
     */
    EntityAuthenticationScheme = function EntityAuthenticationScheme(name, encrypts, protects) {
        // The properties.
        var props = {
            name: { value: name, writable: false, configurable: false },
            encrypts: { value: encrypts, writable: false, configurable: false },
            protectsIntegrity: { value: protects, writable: false, configurable: false },
        };
        Object.defineProperties(this, props);
        
        // Add this scheme to the map.
        schemes[name] = this;
    };

    util.Class.mixin(EntityAuthenticationScheme,
    /** @lends {EntityAuthenticationScheme} */
    ({
        /** Pre-shared keys. */
        PSK : new EntityAuthenticationScheme("PSK", true, true),
        /** X.509 public/private key pair. */
        X509 : new EntityAuthenticationScheme("X509", false, true),
        /** RSA public/private key pair. */
        RSA : new EntityAuthenticationScheme("RSA", false, true),
        /** Unauthenticated. */
        NONE : new EntityAuthenticationScheme("NONE", false, false),
    }));
    Object.freeze(EntityAuthenticationScheme);

    /**
     * @param {string} name the entity authentication scheme name.
     * @return {?EntityAuthenticationScheme} the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    EntityAuthenticationScheme$getScheme = function EntityAuthenticationScheme$getScheme(name) {
        return (schemes[name]) ? schemes[name] : null;
    };
})();