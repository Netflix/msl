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
 * <p>Key response data contains all the data needed to facilitate a exchange of
 * session keys from the responder.</p>
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
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var MslKeyExchangeException = require('../MslKeyExchangeException.js');
	var MslError = require('../MslError.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	
    /**
     * Key master token.
     * @const
     * @type {string}
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * Key key exchange scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * Key key data.
     * @const
     * @type {string}
     */
    var KEY_KEYDATA = "keydata";

    var KeyResponseData = module.exports = MslEncodable.extend({
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
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {MslEncoderFormat} format MSL encoder format.
         * @param {{result: function(MslObject), error: function(Error)}}
         *        callback the callback that will receive the key data MSL
         *        representation or any thrown exceptions.
         * @throws MslEncoderException if there was an error constructing the MSL
         *         representation.
         */
        getKeydata: function(encoder, format, callback) {},

        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            
            this.getKeydata(encoder, format, {
                result: function(keydata) {
                    AsyncExecutor(callback, function() {
                        var mo = encoder.createObject();
                        mo.put(KEY_MASTER_TOKEN, this.masterToken);
                        mo.put(KEY_SCHEME, this.keyExchangeScheme.name);
                        mo.put(KEY_KEYDATA, keydata);
                        encoder.encodeObject(mo, format, callback);
                    }, self);
                },
                error: callback.error,
            }, this);
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
     * provided MSL object.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} keyResponseDataMo the MSL object.
     * @param {{result: function(KeyResponseData), error: function(Error)}}
     *        callback the callback that will receive the key response data
     *        concrete instances or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if unable to create the key response
     *         data.
     * @throws MslCryptoException if there is an error verifying the they key
     *         response data.
     * @throws MslException if the key response master token expiration
     *         timestamp occurs before the renewal window.
     */
    var KeyResponseData$parse = function KeyResponseData$parse(ctx, keyResponseDataMo, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            try {
                // Pull the key data.
                var masterTokenMo = keyResponseDataMo.getMslObject(KEY_MASTER_TOKEN, encoder);
                var schemeName = keyResponseDataMo.getString(KEY_SCHEME);
                var scheme = ctx.getKeyExchangeScheme(schemeName);
                if (!scheme)
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);
                var keyData = keyResponseDataMo.getMslObject(KEY_KEYDATA, encoder);

                // Rebuild master token.
                MasterToken.parse(ctx, masterTokenMo, {
                    result: function(masterToken) {
                        AsyncExecutor(callback, function() {
                            // Construct an instance of the concrete subclass.
                            var factory = ctx.getKeyExchangeFactory(scheme);
                            if (!factory)
                                throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name);
                            factory.createResponseData(ctx, masterToken, keyData, callback);
                        });
                    },
                    error: callback.error,
                });
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keyresponsedata " + keyResponseDataMo, e);
                throw e;
            }
        });
    };
    
    // Exports.
    module.exports.parse = KeyResponseData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyResponseData'));
