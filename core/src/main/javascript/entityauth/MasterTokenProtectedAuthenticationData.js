/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
 *   "authdata" : "base64",
 *   "signature" : "base64",
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token used to protect the encapsulated authentication data</li>
 * <li>{@code authdata} is the Base64-encoded ciphertext envelope containing the encapsulated authentication data</li>
 * <li>{@code signature} is the Base64-encoded signature envelope verifying the encapsulated authentication data</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MasterTokenProtectedAuthenticationData;
var MasterTokenProtectedAuthenticationData$create;
var MasterTokenProtectedAuthenticationData$parse;

(function() {
    "use strict";

    /**
     * JSON key master token.
     * @type {string}
     * @const
     */
    var KEY_MASTER_TOKEN = "mastertoken";
    /**
     * JSON key authentication data.
     * @type {string}
     * @const
     */
    var KEY_AUTHENTICATION_DATA = "authdata";
    /**
     * JSON key signature.
     * @type {string}
     * @const
     */
    var KEY_SIGNATURE = "signature";
    
    /**
     * Create a new master token protected authentication data container object.
     * 
     * @param {Uint8Array} ciphertext raw ciphertext.
     * @param {Uint8Array} signature raw signature.
     * @constructor
     */
    function CreationData(ciphertext, signature) {
        this.ciphertext = ciphertext;
        this.signature = signature;
    }
    
    MasterTokenProtectedAuthenticationData = EntityAuthenticationData.extend({
        /**
         * <p>Construct a new master token protected entity authentication data
         * instance using the provided master token and actual entity
         * authentication data.</p>
         * 
         * @param {MslContext} ctx MSL context.
         * @param {MasterToken} masterToken the master token.
         * @param {EntityAuthenticationData} authdata encapsulated authentication data.
         * @param {?CreationData} creationData optional creation data.
         * @param {{result: function(MasterTokenProtectedAuthenticationData), error: function(Error)}}
         *        callback the callback that will receive the authentication
         *        data or any thrown exceptions.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the encapsulated authentication data.
         * @throws MslEntityAuthException if the master token crypto context cannot
         *         be found in the MSL store and cannot be created.
         */
        init: function init(ctx, masterToken, authdata, creationData, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                init.base.call(this, EntityAuthenticationScheme.MT_PROTECTED);
                
                // Construct the authentication data.
                if (!creationData) {
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
                    
                    // Encrypt and sign the authentication data.
                    var plaintext = textEncoding$getBytes(JSON.stringify(authdata), MslConstants$DEFAULT_CHARSET);
                    cryptoContext.encrypt(plaintext, {
                        result: function(ciphertext) {
                            cryptoContext.sign(ciphertext, {
                                result: function(signature) {
                                    AsyncExecutor(callback, function() {
                                        // The properties.
                                        var props = {
                                            masterToken: { value: masterToken, writable: false, enumerable: false, configurable: false },
                                            authdata: { value: authdata, writable: false, enumerable: false, configurable: false },
                                            encapsulatedAuthdata: { value: authdata, writable: false, configurable: false },
                                            ciphertext: { value: ciphertext, writable: false, enumerable: false, configurable: false },
                                            signature: { value: signature, writable: false, enumerable: false, configurable: false },
                                        };
                                        Object.defineProperties(this, props);
                                        return this;
                                    }, self);
                                },
                                error: callback.error,
                            });
                        },
                        error: callback.error,
                    });
                } else {
                    var ciphertext = creationData.ciphertext;
                    var signature = creationData.signature;
                    
                    // The properties.
                    var props = {
                        masterToken: { value: masterToken, writable: false, enumerable: false, configurable: false },
                        authdata: { value: authdata, writable: false, enumerable: false, configurable: false },
                        encapsulatedAuthdata: { value: authdata, writable: false, configurable: false },
                        ciphertext: { value: ciphertext, writable: false, enumerable: false, configurable: false },
                        signature: { value: signature, writable: false, enumerable: false, configurable: false },
                    };
                    Object.defineProperties(this, props);
                    return this;
                }
            }, self);
        },
        
        /** @inheritDoc */
        getIdentity: function getIdentity() {
            return this.authdata.getIdentity();
        },

        /** @inheritDoc */
        getAuthData: function getAuthData() {
            var result = {};
            result[KEY_MASTER_TOKEN] = JSON.parse(JSON.stringify(this.masterToken));
            result[KEY_AUTHENTICATION_DATA] = base64$encode(this.ciphertext);
            result[KEY_SIGNATURE] = base64$encode(this.signature);
            return result;
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
    MasterTokenProtectedAuthenticationData$create = function MasterTokenProtectedAuthenticationData$create(ctx, masterToken, authdata, callback) {
        new MasterTokenProtectedAuthenticationData(ctx, masterToken, authdata, null, callback);
    }

    /**
     * <p>Construct a new master token protected entity authentication data
     * instance from the provided JSON object.</p>
     * 
     * @param {MslContext} ctx MSL context.
     * @param {object} authdataJO the authentication data JSON object.
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
    MasterTokenProtectedAuthenticationData$parse = function MasterTokenProtectedAuthenticationData$parse(ctx, authdataJO, callback) {
        AsyncExecutor(callback, function() {
            // Extract authentication data fields.
            var masterTokenJo = authdataJO[KEY_MASTER_TOKEN];
            var ciphertextB64 = authdataJO[KEY_AUTHENTICATION_DATA];
            var signatureB64 = authdataJO[KEY_SIGNATURE];
            if (typeof masterTokenJo !== 'object' ||
                typeof ciphertextB64 !== 'string' ||
                typeof signatureB64 !== 'string')
            {
                throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "master token protected authdata");
            }
            
            // Decode authentication data.
            var ciphertext, signature;
            try {
                ciphertext = base64$decode(ciphertextB64);
            } catch (e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_CIPHERTEXT_INVALID, "master token protected authdata " + JSON.stringify(authdataJO), e);
            }
            try {
                signature = base64$decode(signatureB64);
            } catch (e) {
                throw new MslEntityAuthException(MslError.ENTITYAUTH_SIGNATURE_INVALID, "master token protected authdata " + JSON.stringify(authdataJO), e);
            }
            
            // Reconstruct master token.
            MasterToken$parse(ctx, masterTokenJo, {
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
                        cryptoContext.verify(ciphertext, signature, {
                            result: function(verified) {
                                AsyncExecutor(callback, function() {
                                    if (!verified)
                                        throw new MslEntityAuthException(MslError.ENTITYAUTH_VERIFICATION_FAILED, "master token protected authdata " + JSON.stringify(authdataJO));
                                    cryptoContext.decrypt(ciphertext, {
                                        result: function(plaintext) {
                                            AsyncExecutor(callback, function() {
                                                var internalAuthdataJson;
                                                try {
                                                    internalAuthdataJson = textEncoding$getString(plaintext, MslConstants$DEFAULT_CHARSET);
                                                } catch (e) {
                                                    throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "master token protected authdata " + JSON.stringify(authdataJO), e);
                                                }
                                                var internalAuthdataJO = JSON.parse(internalAuthdataJson);
                                                EntityAuthenticationData$parse(ctx, internalAuthdataJO, {
                                                    result: function(internalAuthdata) {
                                                        var creationData = new CreationData(ciphertext, signature);
                                                        new MasterTokenProtectedAuthenticationData(ctx, masterToken, internalAuthdata, creationData, callback);
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
                            throw new MslEntityAuthException(MslError.ENTITYAUTH_MASTERTOKEN_INVALID, "master token protected authdata " + JSON.stringify(authdataJO), e);
                        throw e;
                    });
                }
            });
        });
    };
})();