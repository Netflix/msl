/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
 * <p>Preshared keys profile entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "pskid", "profile" ],
 *   "pskid" : "string",
 *   "profile" : "string",
 * }} where:
 * <ul>
 * <li>{@code pskid} is the entity preshared keys identity</li>
 * <li>{@code profile} is the entity profile</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var PresharedProfileAuthenticationData;
var PresharedProfileAuthenticationData$parse;

(function() {
    "use strict";
    
    /**
     * JSON key entity preshared keys identity.
     * @const
     * @type {string}
     */
    var KEY_PSKID = "pskid";
    /**
     * JSON key entity profile.
     * @const
     * @type {string}
     */
    var KEY_PROFILE = "profile";
    
    /**
     * Identity concatenation character.
     * @const
     * @type {string}
     */
    var CONCAT_CHAR = "-";

    PresharedProfileAuthenticationData = EntityAuthenticationData.extend({
        /**
         * Construct a new preshared keys authentication data instance from the
         * specified entity preshared keys identity and profile.
         * 
         * @param {string} pskid the entity preshared keys identity.
         * @param {string} profile the entity profile.
         */
        init: function init(pskid, profile) {
            init.base.call(this, EntityAuthenticationScheme.PSK_PROFILE);
            
            // The properties.
            var props = {
                presharedKeysId: { value: pskid, writable: false, configurable: false },
                profile: { value: profile, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
    
        /**
         * <p>Returns the entity identity. This is equal to the preshared keys
         * identity and profile strings joined with a hyphen, e.g.
         * {@code pskid-profile}.</p>
         * 
         * @return {string} the entity identity.
         */
        getIdentity: function getIdentity() {
            return this.presharedKeysId + CONCAT_CHAR + this.profile;
        },
    
        /** @inheritDoc */
        getAuthData: function getAuthData() {
            var result = {};
            result[KEY_PSKID] = this.presharedKeysId;
            result[KEY_PROFILE] = this.profile;
            return result;
        },
    
        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof PresharedProfileAuthenticationData)) return false;
            return (equals.base.call(this, that) && this.presharedKeysId == that.presharedKeysId && this.profile == that.profile);
        },
    });

    /**
     * Construct a new preshared keys profile authentication data instance from
     * the provided JSON object.
     * 
     * @param {object} authJo the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     */
    PresharedProfileAuthenticationData$parse = function PresharedProfileAuthenticationData$parse(authJo) {
        var pskid = authJo[KEY_PSKID];
        var profile = authJo[KEY_PROFILE];
        if (typeof pskid !== 'string' || typeof profile !== 'string')
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "psk profile authdata " + JSON.stringify(authJo));
        return new PresharedProfileAuthenticationData(pskid, profile);
    };
})();