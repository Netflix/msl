/**
 * Copyright (c) 2012-2015 Netflix, Inc.  All rights reserved.
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
 * <p>The entity authentication data provides proof of entity identity.</p>
 *
 * <p>Specific entity authentication mechanisms should define their own entity
 * authentication data types.</p>
 *
 * <p>Entity authentication data is represented as
 * {@code
 * entityauthdata = {
 *   "#mandatory" : [ "scheme", "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the entity authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific entity authentication data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var EntityAuthenticationData;
var EntityAuthenticationData$parse;

(function() {
    /** JSON key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** JSON key entity authentication data. */
    var KEY_AUTHDATA = "authdata";

    EntityAuthenticationData = util.Class.create({
        /**
         * <p>Create a new entity authentication data object with the specified
         * entity authentication scheme.</p>
         *
         * @param {EntityAuthenticationScheme} scheme the entity authentication
         *        scheme.
         * @constructor
         * @interface
         */
        init: function init(scheme) {
            // The properties.
            var props = {
                scheme: { value: scheme, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {string} the entity identity.
         * @throws MslCryptoException if there is a crypto error accessing the
         *         entity identity.
         */
        getIdentity: function() {},

        /**
         * @return {Object} the authentication data JSON representation.
         * @throws MslEncodingException if there was an error constructing the
         *         JSON representation.
         */
        getAuthData: function() {},

        /**
         * @param {Object} that the object with which to compare.
         * @return {boolean} true if this object is equal to that object.
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof EntityAuthenticationData)) return false;
            return this.scheme == that.scheme;
        },

        /** @inheritDoc */
        toJSON: function toJSON() {
            var result = {};
            result[KEY_SCHEME] = this.scheme.name;
            result[KEY_AUTHDATA] = this.getAuthData();
            return result;
        },
    });

    /**
     * Construct a new entity authentication data instance of the correct type
     * from the provided JSON object.
     *
     * @param ctx {MslContext} MSL context.
     * @param entityAuthJO {Object} the JSON object.
     * @param {{result: function(EntityAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the entity authentication
     *        data or any thrown exceptions.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslCryptoException if there is an error creating the entity
     *         authentication data crypto.
     */
    EntityAuthenticationData$parse = function EntityAuthenticationData$parse(ctx, entityAuthJO, callback) {
        AsyncExecutor(callback, function() {
            var schemeName = entityAuthJO[KEY_SCHEME];
            var authdata = entityAuthJO[KEY_AUTHDATA];
    
            // Verify entity authentication data.
            if (typeof schemeName !== 'string' ||
                typeof authdata !== 'object')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "entityauthdata " + JSON.stringify(entityAuthJO));
            }
    
            // Verify entity authentication scheme.
            var scheme = ctx.getEntityAuthenticationScheme(schemeName);
            if (!scheme)
                throw new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME, schemeName);
    
            // Construct an instance of the concrete subclass.
            var factory = ctx.getEntityAuthenticationFactory(scheme);
            if (!factory)
                throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name);
            factory.createData(ctx, authdata, callback);
        });
    };
})();
