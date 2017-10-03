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
 * <p>Diffie-Hellman key exchange.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var KeyRequestData = require('../keyx/KeyRequestData.js');
	var KeyExchangeScheme = require('../keyx/KeyExchangeScheme.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var Arrays = require('../util/Arrays.js');
	var MslKeyExchangeException = require('../MslKeyExchangeException.js');
	var MslError = require('../MslError.js');
	var PublicKey = require('../crypto/PublicKey.js');
	var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
	var WebCryptoUsage = require('../crypto/WebCryptoUsage.js');
	var KeyFormat = require('../crypto/KeyFormat.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var KeyResponseData = require('../keyx/KeyResponseData.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var MslInternalException = require('../MslInternalException.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var MslMasterTokenException = require('../MslMasterTokenException.js');
	var MslCrypto = require('../crypto/MslCrypto.js');
	var KeyExchangeFactory = require('../keyx/KeyExchangeFactory.js');
	var MslException = require('../MslException.js');
	var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');

	/**
     * Key Diffie-Hellman parameters ID.
     * @const
     * @type {string}
     */
    var KEY_PARAMETERS_ID = "parametersid";
    /**
     * Key Diffie-Hellman public key.
     * @const
     * @type {string}
     */
    var KEY_PUBLIC_KEY = "publickey";

    /**
     * <p>Diffie-Hellman key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "binary",
     * } where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the public key used to generate the shared secret</li>
     * </ul></p>
     *
     */
    var RequestData = KeyRequestData.extend({
        /**
         * Create a new Diffie-Hellman request data repository with the specified
         * parameters ID and public key. The private key is also required but
         * is not included in the request data.
         *
         * @param {string} parametersId the parameters ID.
         * @param {PublicKey} publicKey the public key Y-value.
         * @param {PrivateKey} privateKey the private key.
         */
        init: function init(parametersId, publicKey, privateKey) {
            init.base.call(this, KeyExchangeScheme.DIFFIE_HELLMAN);

            // The properties.
            var props = {
                parametersId: { value: parametersId, writable: false, configurable: false },
                publicKey: { value: publicKey, writable: false, configurable: false },
                privateKey: { value: privateKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_PARAMETERS_ID, this.parametersId);
                var publicKeyY = this.publicKey.getEncoded();
                mo.put(KEY_PUBLIC_KEY, correctNullBytes(publicKeyY));
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof RequestData)) return false;
            var privateKeysEqual =
                this.privateKey === that.privateKey ||
                (this.privateKey && that.privateKey &&
                    Arrays.equal(this.privateKey.getEncoded(), that.privateKey.getEncoded()));
            return equals.base.call(this, that) &&
                this.parametersId == that.parametersId &&
                Arrays.equal(this.publicKey.getEncoded(), that.publicKey.getEncoded()) &&
                privateKeysEqual;
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            var key = uniqueKey.base.call(this) + ':' + this.parametersId + ':' + Arrays.hashCode(this.publicKey.getEncoded());
            if (this.privateKey)
                key += ':' + Arrays.hashCode(this.privateKey.getEncoded());
            return key;
        },
    });

    /**
     * Create a new Diffie-Hellman request data repository from the provided
     * MSL object. The private key will be unknown.
     *
     * @param {MslObject} keyDataMo the JSON object.
     * @param {{result: function(RequestData), error: function(Error)}}
     *        callback the callback will receive the request data or any
     *        thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if the public key is invalid.
     */
    var RequestData$parse = function RequestData$parse(keyDataMo, callback) {
        AsyncExecutor(callback, function() {
            try {
                var parametersId = keyDataMo.getString(KEY_PARAMETERS_ID);
                var publicKeyY = keyDataMo.getBytes(KEY_PUBLIC_KEY);
                if (publicKeyY.length == 0)
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo);
                PublicKey.import(publicKeyY, WebCryptoAlgorithm.DIFFIE_HELLMAN, WebCryptoUsage.DERIVE_KEY, KeyFormat.SPKI, {
                    result: function(publicKey) {
                        var privateKey = null;
                        callback.result(new RequestData(parametersId, publicKey, privateKey));
                    },
                    error: function(e) {
                        callback.error(new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo, e));
                    }
                });
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
                throw e;
            }
        });
    };

    /**
     * <p>Diffie-Hellman key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "parametersid", "publickey" ],
     *   "parametersid" : "string",
     *   "publickey" : "binary",
     * } where:
     * <ul>
     * <li>{@code parametersid} identifies the Diffie-Hellman paramters to use</li>
     * <li>{@code publickey} the public key used to generate the shared secret</li>
     * </ul></p>
     */
    var ResponseData = KeyResponseData.extend({
        /**
         * Create a new Diffie-Hellman response data repository with the provided
         * master token, specified parameters ID and public key.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {string} parametersId the parameters ID.
         * @param {PublicKey} publicKey the public key Y-value.
         */
        init: function init(masterToken, parametersId, publicKey) {
            init.base.call(this, masterToken, KeyExchangeScheme.DIFFIE_HELLMAN);

            // The properties.
            var props = {
                parametersId: { value: parametersId, writable: false, configurable: false },
                publicKey: { value: publicKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_PARAMETERS_ID, this.parametersId);
                var publicKeyY = this.publicKey.getEncoded();
                mo.put(KEY_PUBLIC_KEY, correctNullBytes(publicKeyY));
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof ResponseData)) return false;
            return equals.base.call(this, that) &&
                this.parametersId == that.parametersId &&
                Arrays.equal(this.publicKey.getEncoded(), that.publicKey.getEncoded());
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.parametersId + ':' + Arrays.hashCode(this.publicKey.getEncoded());
        },
    });

    /**
     * Create a new Diffie-Hellman response data repository with the provided
     * master token from the provided MSL object.
     *
     * @param {MasterToken} masterToken the master token.
     * @param {MslObject} keyDataMo the MSL object.
     * @return {ResponseData} the response data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if the public key is invalid.
     */
    var ResponseData$parse = function ResponseData$parse(masterToken, keyDataMo, callback) {
        AsyncExecutor(callback, function() {
            try {
                var parametersId = keyDataMo.getString(KEY_PARAMETERS_ID);
                var publicKeyY = keyDataMo.getBytes(KEY_PUBLIC_KEY);
                if (publicKeyY.length == 0)
                    throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo);
                PublicKey.import(publicKeyY, WebCryptoAlgorithm.DIFFIE_HELLMAN, WebCryptoUsage.DERIVE_KEY, {
                    result: function(publicKey) {
                        AsyncExecutor(callback, function() {
                            return new ResponseData(masterToken, parametersId, publicKey);
                        });
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            throw new MslKeyExchangeException(MslError.KEYX_INVALID_PUBLIC_KEY, "keydata " + keyDataMo, e);
                        });
                    }
                });
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
                throw e;
            }
        });
    };
    
    /**
     * If the provided byte array begins with one and only one null byte this
     * function simply returns the original array. Otherwise a new array is
     * created that is a copy of the original array with exactly one null byte
     * in position zero, and this new array is returned.
     * 
     * @param {Uint8Array} b the original array.
     * @return {Uint8Array} the resulting byte array.
     */
    function correctNullBytes(b) {
        // Count the number of leading nulls.
        var leadingNulls = 0;
        for (var i = 0; i < b.length; ++i) {
            if (b[i] != 0x00)
                break;
            ++leadingNulls;
        }
        
        // If there is exactly one leading null, return the original array.
        if (leadingNulls == 1)
            return b;
        
        // Create a copy of the non-null bytes and prepend exactly one null
        // byte.
        var copyLength = b.length - leadingNulls;
        var result = new Uint8Array(copyLength + 1);
        result[0] = 0x00;
        result.set(b.subarray(leadingNulls), 1);
        return result;
    }

    var DiffieHellmanExchange = module.exports = KeyExchangeFactory.extend({
        /**
         * Create a new Diffie-Hellman key exchange factory.
         *
         * @param {DiffieHellmanParameters} paramSpecs Diffie-Hellman parameters.
         * @param {AuthenticationUtils} authutils authentication utilities.
         */
        init: function init(paramSpecs, authutils) {
            init.base.call(this, KeyExchangeScheme.DIFFIE_HELLMAN);

            // The properties.
            var props = {
                paramSpecs: { value: paramSpecs, writable: false, enumerable: false, configurable: false },
                authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        createRequestData: function createRequestData(ctx, keyRequestMo, callback) {
            RequestData$parse(keyRequestMo, callback);
        },

        /** @inheritDoc */
        createResponseData: function createResponseData(ctx, masterToken, keyDataMo, callback) {
            ResponseData$parse(masterToken, keyDataMo, callback);
        },

        /**
         * Derives the encryption and HMAC session keys from a Diffie-Hellman
         * shared secret.
         *
         * @param {PublicKey} publicKey Diffie-Hellman public key.
         * @param {PrivateKey} privateKey Diffie-Hellman private key.
         * @param {DhParameterSpec} params Diffie-Hellman parameter specification.
         * @param {{result: function({encryptionKey: SecretKey, hmacKey: SecretKey}), error: function(Error)}}
         *        callback the callback that will receive the session keys or any
         *        thrown exceptions.
         * @throws CryptoException if there is an error creating the session keys.
         */
        deriveSessionKeys: function deriveSessionKeys(publicKey, privateKey, params, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                // Compute Diffie-Hellman shared secret.
            	var bitlen = params.p.length * 8;
                var oncomplete = computeSha384;
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.DERIVEKEY_ERROR, "Error deriving Diffie-Hellman shared secret.", e));
                };
                MslCrypto['deriveBits']({
                    'name': WebCryptoAlgorithm.DIFFIE_HELLMAN['name'],
                    'public': publicKey.getEncoded(),
                }, privateKey, bitlen).then(oncomplete, onerror);
            }, self);
            
            function computeSha384(sharedSecret) {
                AsyncExecutor(callback, function() {
                    sharedSecret = correctNullBytes(sharedSecret);
                    var oncomplete = createKeys;
                    var onerror = function(e) {
                        callback.error(new MslCryptoException(MslError.DIGEST_ERROR, "Error computing SHA-384 of shared secret.", e));
                    };
                    MslCrypto['digest'](WebCryptoAlgorithm.SHA_384, sharedSecret).then(oncomplete, onerror);
                }, self);
            }
            
            function createKeys(hash) {
                AsyncExecutor(callback, function() {
                    var kcedata = new Uint8Array(hash, 0, 16);
                    var kchdata = new Uint8Array(hash, kcedata.length, 32);
                    this.importSessionKeys(kcedata, kchdata, callback);
                }, self);
            }
        },

        /** @inheritDoc */
        generateResponse: function generateResponse(ctx, format, keyRequestData, entityToken, callback) {
            var self = this;
            
            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + keyRequestData + " was not created by this factory.");
                var request = keyRequestData;

                var identity;
                if (entityToken instanceof MasterToken) {
                    // If the master token was not issued by the local entity then we
                    // should not be generating a key response for it.
                    if (!entityToken.isVerified())
                        throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, entityToken);
                    identity = entityToken.identity;
                    
                    // Verify the scheme is permitted.
                    if (!this.authutils.isSchemePermitted(identity, this.scheme))
                        throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ": " + this.scheme.name).setMasterToken(entityToken);
                } else {
                    identity = entityToken.getIdentity();
                    
                    // Verify the scheme is permitted.
                    if (!this.authutils.isSchemePermitted(identity, this.scheme))
                        throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ": " + this.scheme.name).setEntityAuthenticationData(entityToken);
                }

                // Load matching Diffie-Hellman parameter specification.
                var parametersId = request.parametersId;
                var params = this.paramSpecs.getParameterSpec(parametersId);
                if (!params)
                    throw new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID, parametersId).setMasterToken(entityToken);
                
                // Reconstitute request public key.
                var requestPublicKey = request.publicKey;

                // Generate public/private key pair.
                var oncomplete = function(keyPair) {
                    constructKeys(parametersId, params, requestPublicKey, keyPair.publicKey, keyPair.privateKey);
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.GENERATEKEY_ERROR, "Error generating Diffie-Hellman key pair.", e).setMasterToken(entityToken));
                };
                MslCrypto['generateKey']({
                    'name': WebCryptoAlgorithm.DIFFIE_HELLMAN,
                    'prime': params.p,
                    'generator': params.g
                }, false, WebCryptoUsage.DERIVE_KEY).then(oncomplete, onerror);
            }, self);

            // Construct encryption and HMAC keys.
            function constructKeys(parametersId, params, requestPublicKey, responsePublicKey, responsePrivateKey) {
                self.deriveSessionKeys(requestPublicKey, responsePrivateKey, params, {
                    result: function(sessionKeys) {
                        AsyncExecutor(callback, function() {
                            // Create the master token.
                            var tokenFactory = ctx.getTokenFactory();
                            if (entityToken instanceof MasterToken) {
                                tokenFactory.renewMasterToken(ctx, entityToken, sessionKeys.encryptionKey, sessionKeys.hmacKey, null, {
                                    result: function(masterToken) {
                                        AsyncExecutor(callback, function() {
                                            // Create crypto context.
                                            var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                            // Return the key exchange data.
                                            var keyResponseData = new ResponseData(masterToken, parametersId, responsePublicKey);
                                            return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext);
                                        }, self);
                                    },
                                    error: function(e) {
                                        AsyncExecutor(callback, function() {
                                            if (e instanceof MslException)
                                                e.setMasterToken(entityToken);
                                            throw e;
                                        }, self);
                                    }
                                });
                            } else {
                                tokenFactory.createMasterToken(ctx, entityToken, sessionKeys.encryptionKey, sessionKeys.hmacKey, null, {
                                    result: function(masterToken) {
                                        AsyncExecutor(callback, function() {
                                            // Create crypto context.
                                            var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                            // Return the key exchange data.
                                            var keyResponseData = new ResponseData(masterToken, parametersId, responsePublicKey);
                                            return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext);
                                        }, self);
                                    },
                                    error: function(e) {
                                        AsyncExecutor(callback, function() {
                                            if (e instanceof MslException)
                                                e.setEntityAuthenticationData(entityToken);
                                            throw e;
                                        }, self);
                                    }
                                });
                            }
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            throw new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, e).setMasterToken(entityToken);
                        }, self);
                    }
                });
            }
        },

        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(ctx, keyRequestData, keyResponseData, masterToken, callback) {
            var self = this;
            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + keyRequestData + " was not created by this factory.");
                var request = keyRequestData;
                if (!(keyResponseData instanceof ResponseData))
                    throw new MslInternalException("Key response data " + keyResponseData + " was not created by this factory.");
                var response = keyResponseData;

                // Verify response matches request.
                var requestParametersId = request.parametersId;
                var responseParametersId = response.parametersId;
                if (requestParametersId != responseParametersId)
                    throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestParametersId + "; response " + responseParametersId).setMasterToken(masterToken);

                // Reconstitute response public key.
                var privateKey = request.privateKey;
                if (!privateKey)
                    throw new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING, "request Diffie-Hellman private key").setMasterToken(masterToken);
                var params = this.paramSpecs.getParameterSpec(requestParametersId);
                if (!params)
                     throw new MslKeyExchangeException(MslError.UNKNOWN_KEYX_PARAMETERS_ID, requestParametersId).setMasterToken(masterToken);
                var publicKey = response.publicKey;

                // Create crypto context.
                ctx.getEntityAuthenticationData(null, {
                    result: function(entityAuthData) {
                        AsyncExecutor(callback, function() {
                            var identity = entityAuthData.identity;
                            var responseMasterToken = response.masterToken;
                            this.deriveSessionKeys(publicKey, privateKey, params, {
                                result: function(sessionKeys) {
                                    AsyncExecutor(callback, function() {
                                        return new SessionCryptoContext(ctx, responseMasterToken, identity, sessionKeys.encryptionKey, sessionKeys.hmacKey);
                                    }, self);
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (!(e instanceof MslException))
                                            e = new MslCryptoException(MslError.SESSION_KEY_CREATION_FAILURE, null, e).setMasterToken(masterToken);
                                        else
                                            e.setMasterToken(masterToken);
                                        throw e;
                                    }, self);
                                }
                            });
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException)
                                e.setMasterToken(masterToken);
                            throw e;
                        }, self);
                    }
                });
            }, self);
        },
    });
    
    // Exports.
    module.exports.RequestData = RequestData;
    module.exports.RequestData.parse = RequestData$parse;
    module.exports.ResponseData = ResponseData;
    module.exports.ResponseData.parse = ResponseData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('DiffieHellmanExchange'));
