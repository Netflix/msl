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
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslKeyExchangeException = require('../MslKeyExchangeException.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	
    /**
     * Key key exchange scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * Key key request data.
     * @const
     * @type {string}
     */
    var KEY_KEYDATA = "keydata";

    var KeyRequestData = module.exports = MslEncodable.extend({
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
     * provided MSL object.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} keyRequestDataMo the MSL object.
     * @param {{result: function(KeyRequestData), error: function(Error)}}
     *        callback the callback will receive the key request data concrete
     *        instance or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error verifying the key
     *         request data.
     * @throws MslEntityAuthException if the entity authentication data could
     *         not be created.
     * @throws MslKeyExchangeException if unable to create the key request
     *         data.
     */
    var KeyRequestData$parse = function KeyRequestData$parse(ctx, keyRequestDataMo, callback) {
        AsyncExecutor(callback, function() {
            try {
                // Pull the key data.
                var schemeName = keyRequestDataMo.getString(KEY_SCHEME);
                var scheme = ctx.getKeyExchangeScheme(schemeName);
                if (!scheme)
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_SCHEME, schemeName);
                var encoder = ctx.getMslEncoderFactory();
                var keyData = keyRequestDataMo.getMslObject(KEY_KEYDATA, encoder);

                // Construct an instance of the concrete subclass.
                var keyFactory = ctx.getKeyExchangeFactory(scheme);
                if (!keyFactory)
                    throw new MslKeyExchangeException(MslError.KEYX_FACTORY_NOT_FOUND, scheme.name);
                keyFactory.createRequestData(ctx, keyData, callback);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keyrequestdata " + keyRequestDataMo, e);
                throw e;
            }
        });
    };
    
    // Exports.
    module.exports.parse = KeyRequestData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('KeyRequestData'));
