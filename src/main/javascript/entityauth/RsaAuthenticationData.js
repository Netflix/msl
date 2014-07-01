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
 * <p>RSA asymmetric keys entity authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity", "pubkeyid" ],
 *   "identity" : "string",
 *   "pubkeyid" : "string"
 * } where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * <li>{@code pubkeyid} is the identity of the RSA public key associated with this identity</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var RsaAuthenticationData;
var RsaAuthenticationData$parse;

(function() {
    /**
     * JSON key entity identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";
    /**
     * JSON key public key ID.
     * @const
     * @type {string}
     */
    var KEY_PUBKEY_ID = "pubkeyid";

    RsaAuthenticationData = EntityAuthenticationData.extend({
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
        getAuthData: function getAuthData() {
            var authdata = {};
            authdata[KEY_IDENTITY] = this.identity;
            authdata[KEY_PUBKEY_ID] = this.publicKeyId;
            return authdata;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof RsaAuthenticationData)) return false;
            return (equals.base.call(this, this, that) && this.identity == that.identity && this.publicKeyId == that.publicKeyId);
        },
    });

    /**
     * Construct a new RSA asymmetric keys authentication data instance from the
     * provided JSON object.
     *
     * @param {Object} rsaAuthJO the authentication data JSON object.
     * @return the authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    RsaAuthenticationData$parse = function RsaAuthenticationData$parse(rsaAuthJO) {
        var identity = rsaAuthJO[KEY_IDENTITY];
        var pubkeyid = rsaAuthJO[KEY_PUBKEY_ID];
        if (!identity || typeof identity !== 'string' ||
            !pubkeyid || typeof pubkeyid !== 'string')
        {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "RSA authdata" + JSON.stringify(rsaAuthJO));
        }
        return new RsaAuthenticationData(identity, pubkeyid);
    };
})();
