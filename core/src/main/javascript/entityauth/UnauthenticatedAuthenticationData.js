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
 * <p>Unauthenticated entity authentication data. This form of authentication
 * is used by entities that cannot provide any form of entity
 * authentication.</p>
 *
 * <p>Unauthenticated entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "identity" ],
 *   "identity" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
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
     * Key entity identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";

    var UnauthenticatedAuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new unauthenticated entity authentication data instance from
         * the specified entity identity.</p>
         *
         * @param {string} identity the entity identity.
         */
        init: function init(identity) {
            init.base.call(this, EntityAuthenticationScheme.NONE);
            // The properties.
            var props = {
                identity: { value: identity, writable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.identity;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_IDENTITY, this.identity);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UnauthenticatedAuthenticationData)) return false;
            return (equals.base.call(this, that) && this.identity == that.identity);
        },
    });

    /**
     * Construct a new Unauthenticated asymmetric keys authentication data instance from the
     * provided MSL object.
     *
     * @param {MslObject} unauthenticatedAuthMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    var UnauthenticatedAuthenticationData$parse = function UnauthenticatedAuthenticationData$parse(unauthenticatedAuthMo) {
        try {
            var identity = unauthenticatedAuthMo.getString(KEY_IDENTITY);
            return new UnauthenticatedAuthenticationData(identity);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "Unauthenticated authdata" + unauthenticatedAuthMo);
            throw e;
        }
    };
    
    // Exports.
    module.exports.parse = UnauthenticatedAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('UnauthenticatedAuthenticationData'));
