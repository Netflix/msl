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
 * <p>RSA asymmetric keys entity authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity", "pubkeyid" ],
 *   "identity" : "string",
 *   "pubkeyid" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * <li>{@code pubkeyid} is the identity of the RSA public key associated with this identity</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";

    var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslEncodingException = require('../MslEncodingException.js');
    var MslError = require('../MslError.js');

    /**
     * Key entity identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";
    /**
     * Key public key ID.
     * @const
     * @type {string}
     */
    var KEY_PUBKEY_ID = "pubkeyid";

    var RsaAuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new public key authentication data instance from the
         * specified entity identity and public key ID.</p>
         *
         * @param {string} identity the entity identity.
         * @param {string} pubkeyid the public key ID.
         */
        init: function init(identity, pubkeyid) {
            init.base.call(this, EntityAuthenticationScheme.RSA);

            // The properties.
            var props = {
                identity: { value: identity, writable: false, configurable: false },
                publicKeyId: { value: pubkeyid, writable: false, configurable: false },
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
                mo.put(KEY_PUBKEY_ID, this.publicKeyId);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof RsaAuthenticationData)) return false;
            return (equals.base.call(this, that) && this.identity == that.identity && this.publicKeyId == that.publicKeyId);
        },
    });

    /**
     * Construct a new RSA asymmetric keys authentication data instance from the
     * provided MSL object.
     *
     * @param {MslObject} rsaAuthMo the authentication data MSL object.
     * @return the authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    var RsaAuthenticationData$parse = function RsaAuthenticationData$parse(rsaAuthMo) {
        try {
            var identity = rsaAuthMo.getString(KEY_IDENTITY);
            var pubkeyid = rsaAuthMo.getString(KEY_PUBKEY_ID);
            return new RsaAuthenticationData(identity, pubkeyid);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "RSA authdata" + rsaAuthMo);
            throw e;
        }
    };
    
    // Exports.
    module.exports.parse = RsaAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('RsaAuthenticationData'));
