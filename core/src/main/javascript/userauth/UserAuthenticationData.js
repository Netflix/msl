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
 * <p>The user authentication data provides proof of user identity.</p>
 *
 * <p>Specific user authentication mechanisms should define their own user
 * authentication data types.</p>
 *
 * <p>User authentication data is represented as
 * {@code
 * userauthdata = {
 *   "#mandatory" : [ "scheme"., "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where
 * <ul>
 * <li>{@code scheme} is the user authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific authentication data</li>
 * </ul></p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var MslEncodable = require('../io/MslEncodable.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslUserAuthException = require('../MslUserAuthException.js');
	var MslError = require('../MslError.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	
    /**
     * Key user authentication scheme.
     * @const
     * @type {string}
     */
    var KEY_SCHEME = "scheme";
    /**
     * Key user authentication data.
     * @const
     * @type {string}
     */
    var KEY_AUTHDATA = "authdata";

    var UserAuthenticationData = module.exports = MslEncodable.extend({
        /**
         * Create a new user authentication data object with the specified user
         * authentication scheme.
         *
         * @param {UserAuthenticationScheme} scheme the user authentication scheme.
         * @constructor
         * @interface
         */
        init: function init(scheme) {
            // The properties.
            var props = {
                /**
                 * User authentication scheme.
                 * @type {UserAuthenticationScheme}
                 */
                scheme: { value: scheme, writable: false, configurable: false },
                /**
                 * Cached encodings.
                 * @type {Object<MslEncoderFormat,Uint8Array>}
                 */
                encodings: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /**
         * Returns the scheme-specific user authentication data. This method is
         * expected to succeed unless there is an internal error.
         * 
         * @param {MslEncoderFactory} encoder the encoder factory.
         * @param {MslEncoderFormat} format the encoder format.
         * @param {{result: function(MslObject}, error: function(Error)}
         *        callback the callback that will receive the authentication
         *        data MSL object or any thrown exceptions.
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
            if (!(that instanceof UserAuthenticationData)) return false;
            return this.scheme == that.scheme;
        },
        
        /** @inheritDoc */
        toMslEncoding: function toMslEncoding(encoder, format, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                // Return any cached encoding.
                if (this.encodings[format])
                    return this.encodings[format];
                
                this.getAuthData(encoder, format, {
                    result: function(authdata) {
                        AsyncExecutor(callback, function() {
                            // Encode the user authentication data.
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
                            	error: callback.error
                            });
                        }, self);
                    },
                    error: callback.error,
                });
            }, self);
        },
    });

    /**
     * <p>Construct a new user authentication data instance of the correct type
     * from the provided MSL object.</p>
     * 
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     *
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken the master token associated with the user
     *        authentication data. May be {@code null}.
     * @param {MslObject} userAuthMo the MSL object.
     * @param {{result: function(UserAuthenticationData), error: function(Error)}}
     *        callback the callback functions that will receive the user
     *        authentication data or any thrown exceptions.
     * @return {UserAuthenticationData} the user authentication data concrete instance.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if there is an error instantiating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     */
    var UserAuthenticationData$parse = function UserAuthenticationData$parse(ctx, masterToken, userAuthMo, callback) {
        AsyncExecutor(callback, function() {
            try {
                // Pull the scheme.
                var schemeName = userAuthMo.getString(KEY_SCHEME);
                var scheme = ctx.getUserAuthenticationScheme(schemeName);
                if (!scheme)
                    throw new MslUserAuthException(MslError.UNIDENTIFIED_USERAUTH_SCHEME, schemeName);

                // Construct an instance of the concrete subclass.
                var factory = ctx.getUserAuthenticationFactory(scheme);
                if (!factory)
                    throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name);
                var encoder = ctx.getMslEncoderFactory();
                factory.createData(ctx, masterToken, userAuthMo.getMslObject(KEY_AUTHDATA, encoder), callback);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "userauthdata " + userAuthMo, e);
                throw e;
            }
        });
    };
    
    // Exports.
    module.exports.parse = UserAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('UserAuthenticationData'));
