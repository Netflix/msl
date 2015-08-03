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
 * <p>Key response data contains all the data needed to facilitate a exchange of
 * session keys from the responseor.</p>
 *
 * <p>Specific key exchange mechanisms should define their own key response data
 * types.</p>
 *
 * <p>Key response data is represented as
 * {@code
 * keyresponsedata = {
 *   "#mandatory" : [ "mastertoken", "scheme", "keydata" ],
 *   "mastertoken" : mastertoken,
 *   "scheme" : "string",
 *   "keydata" : object
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token associated with the session keys</li>
 * <li>{@code scheme} is the key exchange scheme</li>
 * <li>{@code keydata} is the scheme-specific key data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var KeyResponseData;
var KeyResponseData$parse;

(function() {
    /**
     * JSON key master token.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * JSON key key exchange scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * JSON key key data.
     * @const
     * @type {string}
     */
    var KEY_KEYDATA = "keydata";

    KeyResponseData = util.Class.create({
        /**
         * Create a new key response data object with the specified key exchange
         * scheme and associated master token.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {KeyExchangeScheme} scheme the key exchange scheme.
         */
        init: function init(masterToken, scheme) {
            // The properties.
            var props = {
                masterToken: { value: masterToken, writable: false, configurable: false },
                keyExchangeScheme: { value: scheme, wrtiable: false, configurable: false },
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
            result[KEY_MASTER_TOKEN] = this.masterToken;
            result[KEY_SCHEME] = this.keyExchangeScheme.name;
            result[KEY_KEYDATA] = this.getKeydata();
            return result;
        },

        /**
         * @param {?} that the reference object with which to compare.
         * @return {boolean} true if the other object is a key request data
         *         with the same master token and scheme.
         * @see #uniqueKey()
         */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof KeyResponseData)) return false;
            return this.masterToken.equals(that.masterToken) && this.keyExchangeScheme == that.keyExchangeScheme;
        },

        /**
         * @return {string} a string that uniquely identifies this key response
         *         data.
         * @see #equals(that)
         */
        uniqueKey: function uniqueKey() {
            return this.masterToken.uniqueKey() + ':' + this.keyExchangeScheme;
        },
    });

    /**
     * Construct a new key response data instance of the correct type from the
     * provided JSON object.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Object} keyResponseDataJO the JSON object.
     * @param {{result: function(KeyResponseData), error: function(Error)}}
     *        callback the callback that will receive the key response data
     *        concrete instances or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslKeyExchangeException if unable to create the key response
     *         data.
     * @throws MslCryptoException if there is an error verifying the they key
     *         response data.
     * @throws MslException if the key response master token expiration
     *         timestamp occurs before the renewal window.
     */
    KeyResponseData$parse = function KeyResponseData$parse(ctx, keyResponseDataJO, callback) {
        AsyncExecutor(callback, function() {
            // Pull the key data.
            var masterTokenJo = keyResponseDataJO[KEY_MASTER_TOKEN];
            var schemeName = keyResponseDataJO[KEY_SCHEME];
            var keyDataJo = keyResponseDataJO[KEY_KEYDATA];

            // Verify key data.
            if (typeof schemeName !== 'string' ||
                typeof masterTokenJo !== 'object' ||
                typeof keyDataJo !== 'object')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keyresponsedata " + JSON.stringify(keyResponseDataJO));
            }

            // Verify scheme.
            var scheme = KeyExchangeScheme$getScheme(schemeName);
            if (!scheme)
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);

            // Rebuild master token.
            MasterToken$parse(ctx, masterTokenJo, {
                result: function(masterToken) {
                    AsyncExecutor(callback, function() {
                        // Construct an instance of the concrete subclass.
                        var factory = ctx.getKeyExchangeFactory(scheme);
                        if (!factory)
                            throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name);
                        return factory.createResponseData(ctx, masterToken, keyDataJo);
                    });
                },
                error: function(err) { callback.error(err); }
            });
        });
    };
})();
