/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
 * <p>Master token protected entity authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "authdata", "signature" ],
 *   "mastertoken" : mastertoken,
 *   "authdata" : "binary",
 *   "signature" : "binary",
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token used to protect the encapsulated authentication data</li>
 * <li>{@code authdata} is the ciphertext envelope containing the encapsulated authentication data</li>
 * <li>{@code signature} is the signature envelope verifying the encapsulated authentication data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
    "use strict";
    
    var EntityAuthenticationData = require('../entityauth/EntityAuthenticationData.js');
    var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
    var AsyncExecutor = require('../util/AsyncExecutor.js');
    var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');
    var MslMasterTokenException = require('../MslMasterTokenException.js');
    var MslEntityAuthException = require('../MslEntityAuthException.js');
    var MslError = require('../MslError.js');
    var MslCryptoException = require('../MslCryptoException.js');
    var MslEncoderException = require('../io/MslEncoderException.js');
    var MslEncodingException = require('../MslEncodingException.js');
    var MasterToken = require('../tokens/MasterToken.js');
    var MslException = require('../MslException.js');

    /**
     * Key master token.
     * @type {string}
     * @const
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * Key authentication data.
     * @type {string}
     * @const
     */
    var KEY_AUTHENTICATION_DATA = "authdata";
    /**
     * Key signature.
     * @type {string}
     * @const
     */
    var KEY_SIGNATURE = "signature";
    
    var MasterTokenProtectedAuthenticationData = module.exports = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new master token protected entity authentication data
         * instance using the provided master token and actual entity
         * authentication data.</p>
         * 
         * @param {MslContext} ctx MSL context.
         * @param {MasterToken} masterToken the master token.
         * @param {EntityAuthenticationData} authdata encapsulated authentication data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the encapsulated authentication data.
         * @throws MslEntityAuthException if the master token crypto context cannot
         *         be found in the MSL store and cannot be created.
         */
        init: function init(ctx, masterToken, authdata) {
            init.base.call(this, EntityAuthenticationScheme.MT_PROTECTED);

            // The properties.
            var props = {
                ctx: { value: ctx, writable: false, enumerable: false, configurable: false },
                masterToken: { value: masterToken, writable: false, enumerable: false, configurable: false },
                authdata: { value: authdata, writable: false, enumerable: false, configurable: false },
                /**
                 * Cached encoded objects.
                 * @type {Object.<MslEncoderFormat,MslObject>}
                 */
                objects: { value: {}, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.authdata.getIdentity();
        },

        /**
         * Return the encapsulated entity authentication data.
         * 
         * @return {EntityAuthenticationData} the encapsulated entity authentication data.
         */
        get encapsulatedAuthdata() {
            return this.authdata;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData(encoder, format, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Return any cached object.
                if (this.objects[format])
                    return this.objects[format];
                
                // Grab master token crypto context.
                var cryptoContext;
                try {
                    var cachedCryptoContext = this.ctx.getMslStore().getCryptoContext(this.masterToken);
                    if (cachedCryptoContext)
                        cryptoContext = cachedCryptoContext;
                    else
                        cryptoContext = new SessionCryptoContext(this.ctx, this.masterToken);
                } catch (e) {
                    if (e instanceof MslMasterTokenException)
                        throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED, e);
                    throw e;
                }
                
                // Encrypt and sign the authentication data.
                this.authdata.toMslEncoding(encoder, format, {
                    result: function(plaintext) {
                        cryptoContext.encrypt(plaintext, encoder, format, {
                            result: function(ciphertext) {
                                cryptoContext.sign(ciphertext, encoder, format, {
                                    result: function(signature) {
                                        AsyncExecutor(callback, function() {
                                            // Return the authentication data.
                                            var mo = encoder.createObject();
                                            mo.put(KEY_MASTER_TOKEN, this.masterToken);
                                            mo.put(KEY_AUTHENTICATION_DATA, ciphertext);
                                            mo.put(KEY_SIGNATURE, signature);

                                            // Cache and return the object.
                                            encoder.encodeObject(mo, format, {
                                            	result: function(encoded) {
                                            		AsyncExecutor(callback, function() {
	                                                    var decoded = encoder.parseObject(encoded);
	                                                    this.objects[format] = decoded;
	                                                    return decoded;
                                            		}, self);
                                            	},
                                            	error: callback.error,
                                            });
                                        }, self);
                                    },
                                    error: function(e) {
                                        if (e instanceof MslCryptoException)
                                            e = new MslEncoderException("Error encrypting and signing the authentication data.", e);
                                        callback.error(e);
                                    }
                                });
                            },
                            error: function(e) {
                                if (e instanceof MslCryptoException)
                                    e = new MslEncoderException("Error encrypting and signing the authentication data.", e);
                                callback.error(e);
                            },
                        });
                    },
                    error: callback.error,
                });
            }, self);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof MasterTokenProtectedAuthenticationData)) return false;
            return equals.base.call(this, that) &&
                this.masterToken.equals(that.masterToken) &&
                this.authdata.equals(that.authdata);
        },
    });

    /**
     * <p>Construct a new master token protected entity authentication data
     * instance using the provided master token and actual entity
     * authentication data.</p>
     * 
     * @param {MslContext} ctx MSL context.
     * @param {MasterToken} masterToken the master token.
     * @param {EntityAuthenticationData} authdata encapsulated authentication data.
     * @param {{result: function(MasterTokenProtectedAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the authentication
     *        data or any thrown exceptions.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the encapsulated authentication data.
     * @throws MslEntityAuthException if the master token crypto context cannot
     *         be found in the MSL store and cannot be created.
     */
    var MasterTokenProtectedAuthenticationData$create = function MasterTokenProtectedAuthenticationData$create(ctx, masterToken, authdata, callback) {
        AsyncExecutor(callback, function() {
            return new MasterTokenProtectedAuthenticationData(ctx, masterToken, authdata);
        });
    };

    /**
     * <p>Construct a new master token protected entity authentication data
     * instance from the provided JSON object.</p>
     * 
     * @param {MslContext} ctx MSL context.
     * @param {MslObject} authdataMo the authentication data JSON object.
     * @param {{result: function(MasterTokenProtectedAuthenticationData), error: function(Error)}}
     *        callback the callback that will receive the authentication
     *        data or any thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the encapsulated authentication data.
     * @throws MslEntityAuthException if the encapsulated authentication data
     *         or signature are invalid, if the master token is invalid, or if
     *         the master token crypto context cannot be found in the MSL store
     *         and cannot be created.
     */
    var MasterTokenProtectedAuthenticationData$parse = function MasterTokenProtectedAuthenticationData$parse(ctx, authdataMo, callback) {
        AsyncExecutor(callback, function() {
            var encoder = ctx.getMslEncoderFactory();
            
            // Extract authentication data fields.
            var ciphertext, signature, masterTokenMo;
            try {
                ciphertext = authdataMo.getBytes(KEY_AUTHENTICATION_DATA);
                signature = authdataMo.getBytes(KEY_SIGNATURE);
                masterTokenMo = authdataMo.getMslObject(KEY_MASTER_TOKEN, encoder);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "master token protected authdata");
                throw e;
            }
            
            // Reconstruct master token.
            MasterToken.parse(ctx, masterTokenMo, {
                result: function(masterToken) {
                    AsyncExecutor(callback, function() {
                        // Grab master token crypto context.
                        var cryptoContext;
                        try {
                            var cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
                            if (cachedCryptoContext)
                                cryptoContext = cachedCryptoContext;
                            else
                                cryptoContext = new SessionCryptoContext(ctx, masterToken);
                        } catch (e) {
                            if (e instanceof MslMasterTokenException)
                                throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_NOT_DECRYPTED, e);
                            throw e;
                        }
    
                        // Verify and decrypt the authentication data.
                        cryptoContext.verify(ciphertext, signature, encoder, {
                            result: function(verified) {
                                AsyncExecutor(callback, function() {
                                    if (!verified)
                                        throw new MslEntityAuthException(MslError.ENTITYAUTH_VERIFICATION_FAILED, "master token protected authdata " + authdataMo);
                                    cryptoContext.decrypt(ciphertext, encoder, {
                                        result: function(plaintext) {
                                            AsyncExecutor(callback, function() {
                                                var internalAuthdataMo;
                                                try {
                                                    internalAuthdataMo = encoder.parseObject(plaintext);
                                                } catch (e) {
                                                    if (e instanceof MslEncoderException)
                                                        throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "master token protected authdata " + authdataMo, e);
                                                    throw e;
                                                }
                                                EntityAuthenticationData.parse(ctx, internalAuthdataMo, {
                                                    result: function(internalAuthdata) {
                                                        AsyncExecutor(callback, function() {
                                                            return new MasterTokenProtectedAuthenticationData(ctx, masterToken, internalAuthdata);
                                                        });
                                                    },
                                                    error: callback.error,
                                                });
                                            });
                                        },
                                        error: callback.error,
                                    });
                                });
                            },
                            error: callback.error,
                        });
                    });
                },
                error: function(e) {
                    AsyncExecutor(callback, function() {
                        if (e instanceof MslException)
                            throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_INVALID, "master token protected authdata " + authdataMo, e);
                        throw e;
                    });
                }
            });
        });
    };
    
    // Exports.
    module.exports.create = MasterTokenProtectedAuthenticationData$create;
    module.exports.parse = MasterTokenProtectedAuthenticationData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('MasterTokenProtectedAuthenticationData'));