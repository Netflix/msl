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
 * <p>Key request data contains all the data needed to facilitate a exchange of
 * session keys with the requesting entity.</p>
 *
 * <p>Specific key exchange mechanisms should define their own key request data
 * types.</p>
 *
 * <p>Key request data is represented as
 * {@code
 * keyrequestdata = {
 *   "#mandatory" : [ "scheme", "keydata" ],
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var KeyRequestData;
var KeyRequestData$parse;

(function() {
    /**
     * JSON key key exchange scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * JSON key key request data.
     * @const
     * @type {string}
     */
    var KEY_KEYDATA = "keydata";

    KeyRequestData = util.Class.create({
        /**
         * Create a new key request data object with the specified key exchange
         * scheme.
         *
         * @param {KeyExchangeScheme} scheme the key exchange scheme.
         */
        init: function init(scheme) {
            // The properties.
            var props = {
                keyExchangeScheme: { value: scheme, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {object} the key data JSON representation.
         * @throws JSONException if there was an error constructing the JSON
         *         representation.
         */
        getKeydata: function() {},

        /** @inheritDoc */
        toJSON: function toJSON() {
            var result = {};
            result[KEY_SCHEME] = this.keyExchangeScheme.name;
            result[KEY_KEYDATA] = this.getKeydata();
            return result;
        },

        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a key request data
         *         with the same scheme.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof KeyRequestData)) return false;
            return this.keyExchangeScheme == that.keyExchangeScheme;
        },

        /**
         * @return {string} a string that uniquely identifies this key request
         *         data.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.keyExchangeScheme;
        },
    });

    /**
     * Construct a new key request data instance of the correct type from the
     * provided JSON object.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Object} keyRequestDataJO the JSON object.
     * @param {{result: function(KeyRequestData), error: function(Error)}}
     *        callback the callback will receive the key request data concrete
     *        instance or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException if there is an error verifying the key
     *         request data.
     * @throws MslEntityAuthException if the entity authentication data could
     *         not be created.
     * @throws MslKeyExchangeException if unable to create the key request
     *         data.
     */
    KeyRequestData$parse = function KeyRequestData$parse(ctx, keyRequestDataJO, callback) {
        AsyncExecutor(callback, function() {
            // Pull the key data.
            var schemeName = keyRequestDataJO[KEY_SCHEME];
            var keyDataJo = keyRequestDataJO[KEY_KEYDATA];

            // Verify key data.
            if (typeof schemeName !== 'string' ||
                typeof keyDataJo !== 'object')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keyrequestdata " + JSON.stringify(keyRequestDataJO));
            }

            // Verify scheme.
            var scheme = ctx.getKeyExchangeScheme(schemeName);
            if (!scheme)
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);

            // Construct an instance of the concrete subclass.
            var keyFactory = ctx.getKeyExchangeFactory(scheme);
            if (!keyFactory)
                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name);
            keyFactory.createRequestData(ctx, keyDataJo, callback);
        });
    };
})();
