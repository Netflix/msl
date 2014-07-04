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
 * <p>Preshared keys entity authentication data.</p>
 *
 * <p>
 * {@code {
 *   "#mandatory" : [ "identity" ],
 *   "identity" : "string"
 * }} where:
 * <ul>
 * <li>{@code identity} is the entity identity</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var PresharedAuthenticationData;
var PresharedAuthenticationData$parse;

(function() {
    /**
     * JSON key entity identity.
     * @const
     * @type {string}
     */
    var KEY_IDENTITY = "identity";

    PresharedAuthenticationData = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new preshared keys authentication data instance from the
         * specified entity identity.</p>
         *
         * @param {string} identity the entity identity.
         * @extends {EntityAuthenticationData}
         */
        init: function init(identity) {
            init.base.call(this, EntityAuthenticationScheme.PSK);
            // The properties.
            var props = {
                identity: { value: identity, writable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.identity;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData() {
            var result = {};
            result[KEY_IDENTITY] = this.identity;
            return result;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof PresharedAuthenticationData)) return false;
            return (equals.base.call(this, this, that) && this.identity == that.identity);
        },
    });

    /**
     * Construct a new preshared keys authentication data instance from the
     * provided JSON object.
     *
     * @param presharedAuthJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     */
    PresharedAuthenticationData$parse = function PresharedAuthenticationData$parse(presharedAuthJO) {
        var identity = presharedAuthJO[KEY_IDENTITY];
        if (!identity)
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "psk authdata" + JSON.stringify(presharedAuthJO));
        return new PresharedAuthenticationData(identity);
    };
})();
