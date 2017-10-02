/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Unauthenticated suffixed entity authentication data. This form of
 * authentication is used by entities that cannot provide any form of entity
 * authentication, and wish to share a root identity across themselves. This
 * scheme may also be useful in cases where multiple MSL stacks need to execute
 * independently on a single entity.</p>
 * 
 * <p>A suffixed scheme can expose an entity to cloning attacks of the root
 * identity as the master token sequence number will now be tied to the
 * root and suffix pair. This is probably acceptable for unauthenticated
 * entities anyway as they have no credentials to provide as proof of their
 * claimed identity.</p>
 * 
 * <p>Unauthenticated suffixed entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "root", "suffix" ],
 *   "root" : "string",
 *   "suffix" : "string"
 * }} where:
 * <ul>
 * <li>{@code root} is the entity identity root</li>
 * <li>{@code suffix} is the entity identity suffix</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require("../util/AsyncExecutor.js");
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslEncodingException = require('../MslEncodingException.js');
    var MslError = require('../MslError.js');
    
    /**
     * Key entity root.
     * @const
     * @type {string}
     */
    var KEY_ROOT = "root";
    /**
     * Key entity suffix.
     * @const
     * @type {string}
     */
    var KEY_SUFFIX = "suffix";
    
    /**
     * Identity concatenation character.
     * @const
     * @type {string}
     */
    var CONCAT_CHAR = ".";
    
    var UnauthenticatedSuffixedAuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * Construct a new unauthenticated suffixed entity authentication data
         * instance from the specified entity identity root and suffix.
         * 
         * @param {string} root the entity identity root.
         * @param {string} suffix the entity identity suffix.
         */
        init: function init(root, suffix) {
            init.base.call(this, EntityAuthenticationScheme.NONE_SUFFIXED);
            
            // The properties.
            var props = {
                root: { value: root, writable: false, configurable: false },
                suffix: { value: suffix, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * <p>Returns the entity identity. This is equal to the root and suffix
         * strings joined with a period, e.g. {@code root.suffix}.</p>
         * 
         * @return the entity identity.
         */
        getIdentity: function getIdentity() {
            return this.root + CONCAT_CHAR + this.suffix;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_ROOT, this.root);
                mo.put(KEY_SUFFIX, this.suffix);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UnauthenticatedSuffixedAuthenticationData)) return false;
            return (equals.base.call(this, that) && this.root == that.root && this.suffix == that.suffix);
        },
    });
    
    /**
     * Construct a new unauthenticated suffixed entity authentication data
     * instance from the provided MSL object.
     * 
     * @param {MslObject} unauthSuffixedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     */
    var UnauthenticatedSuffixedAuthenticationData$parse = function UnauthenticatedSuffixedAuthenticationData$parse(unauthSuffixedAuthMo) {
        try {
            var root = unauthSuffixedAuthMo.getString(KEY_ROOT);
            var suffix = unauthSuffixedAuthMo.getString(KEY_SUFFIX);
            return new UnauthenticatedSuffixedAuthenticationData(root, suffix);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "Unauthenticated suffixed authdata" + unauthSuffixedAuthMo);
            throw e;
        }
    };
    
    // Exports.
    module.exports.parse = UnauthenticatedSuffixedAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('UnauthenticatedSuffixedAuthenticationData'));
