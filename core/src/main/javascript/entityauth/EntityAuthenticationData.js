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
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslEntityAuthException = require('../MslEntityAuthException.js');
	var MslError = require('../MslError.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	
    /** Key entity authentication scheme. */
    var KEY_SCHEME = "scheme";
    /** Key entity authentication data. */
    var KEY_AUTHDATA = "authdata";

    var EntityAuthenticationData = module.exports = MslEncodable.extend({
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
                /**
                 * Cached encodings.
                 * @type {Object.<MslEncoderFormat,Uint8Array>}
                 */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * @return {string} the entity identity. May be {@code null} if unknown.
         * @throws MslCryptoException if there is a crypto error accessing the
         *         entity identity.
         */
        getIdentity: function() {},

        /**
         * @param {MslEncoderFactory} encoder MSL encoder factory.
         * @param {MslEncoderFormat} format MSL encoder format.
         * @param {{result: function(MslObject), error: function(Error)}}
         *        callback the callback that will receive the authentication
         *        data MSL representation or any thrown exceptions.
         * @throws MslEncoderException if there was an error constructing the
         *         MSL object.
         */
        getAuthData: function(encoder, format, callback) {},

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
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
        	var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                // Get the authentication data.
                this.getAuthData(encoder, format, {
                    result: function(authdata) {
                        AsyncExecutor(callback, function() {
                            // Encode the entity authentication data.
                            var mo = encoder.createObject();
                            mo.put(KEY_SCHEME, this.scheme.name);
                            mo.put(KEY_AUTHDATA, authdata);
                            encoder.encodeObject(mo, format, {
                            	result: function(encoding) {
                            		AsyncExecutor(callback, function() {
                            			// Cache and return the encoding.
                            			this.encodings[format] = encoding;
                            			return encoding;
                            		}, self);
                            	},
                            	error: callback.error,
                            });
                        }, self);
                    },
                    error: callback.error,
                });
            }, self);
        },
    });

    /**
     * Construct a new entity authentication data instance of the correct type
     * from the provided MSL object.
     *
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} entityAuthMo the MSL object.
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
    var EntityAuthenticationData$parse = function EntityAuthenticationData$parse(ctx, entityAuthMo, callback) {
        AsyncExecutor(callback, function() {
            try {
                var schemeName = entityAuthMo.getString(KEY_SCHEME);
                var encoder = ctx.getMslEncoderFactory();
                var authdata = entityAuthMo.getMslObject(KEY_AUTHDATA, encoder);
        
                // Verify entity authentication scheme.
                var scheme = ctx.getEntityAuthenticationScheme(schemeName);
                if (!scheme)
                    throw new MslEntityAuthException(MslError.UNIDENTIFIED_ENTITYAUTH_SCHEME, schemeName);
        
                // Construct an instance of the concrete subclass.
                var factory = ctx.getEntityAuthenticationFactory(scheme);
                if (!factory)
                    throw new MslEntityAuthException(MslError.ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name);
                factory.createData(ctx, authdata, callback);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "entityauthdata " + entityAuthMo, e);
                throw e;
            }
        });
    };
    
    // Exports.
    module.exports.parse = EntityAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('EntityAuthenticationData'));
