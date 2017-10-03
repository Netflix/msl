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
 * <p>Asymmetric key wrapped key exchange.</p>
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
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var MslError = require('../MslError.js');
	var PublicKey = require('../crypto/PublicKey.js');
	var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
	var WebCryptoUsage = require('../crypto/WebCryptoUsage.js');
	var KeyFormat = require('../crypto/KeyFormat.js');
	var MslCryptoException = require('../MslCryptoException.js');
	var KeyResponseData = require('../keyx/KeyResponseData.js');
	var JsonWebEncryptionCryptoContext = require('../crypto/JsonWebEncryptionCryptoContext.js');
	var RsaCryptoContext = require('../crypto/RsaCryptoContext.js');
	var KeyExchangeFactory = require('../keyx/KeyExchangeFactory.js');
	var MslInternalException = require('../MslInternalException.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var MslMasterTokenException = require('../MslMasterTokenException.js');
	var MslException = require('../MslException.js');
	var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');

    /**
     * Asymmetric key wrapped mechanism.
     * @enum {string}
     */
    var Mechanism = {
        /** RSA-OAEP encrypt/decrypt */
        RSA: "RSA",
        /** ECIES */
        ECC: "ECC",
        /** JSON Web Encryption with RSA-OAEP */
        JWE_RSA: "JWE_RSA",
        /** JSON Web Encryption JSON Serialization with RSA-OAEP */
        JWEJS_RSA: "JWEJS_RSA",
        /** JSON Web Key with RSA-OAEP */
        JWK_RSA: "JWK_RSA",
        /** JSON Web Key with RSA-PKCS v1.5 */
        JWK_RSAES: "JWK_RSAES",
    };

    /**
     * Key key pair ID.
     * @const
     * @type {string}
     */
    var KEY_KEY_PAIR_ID = "keypairid";
    /**
     * Key mechanism.
     * @const
     * @type {string}
     */
    var KEY_MECHANISM = "mechanism";
    /**
     * Key public key.
     * @const
     * @type {string}
     */
    var KEY_PUBLIC_KEY = "publickey";
    /**
     * Key encrypted encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * Key encrypted HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";

    /**
     * <p>Asymmetric key wrapped key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "mechanism", "publickey" ],
     *   "keypairid" : "string",
     *   "mechanism" : "string",
     *   "publickey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code mechanism} the public key cryptographic mechanism of the key pair</li>
     * <li>{@code publickey} the public key used to wrap the session keys</li>
     * </ul></p>
     */
    var RequestData = KeyRequestData.extend({
        /**
         * Create a new asymmetric key wrapped key request data instance with
         * the specified key pair ID and public key. The private key is also
         * required but is not included in the request data.
         *
         * @param {string} keyPairId the public/private key pair ID.
         * @param {Mechanism} mechanism the key exchange mechanism.
         * @param {PublicKey} publicKey the public key.
         * @param {PrivateKey} privateKey the private key.
         */
        init: function init(keyPairId, mechanism, publicKey, privateKey) {
            init.base.call(this, KeyExchangeScheme.ASYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyPairId: { value: keyPairId, writable: false, configurable: false },
                mechanism: { value: mechanism, writable: false, configurable: false },
                publicKey: { value: publicKey, writable: false, configurable: false },
                privateKey: { value: privateKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_KEY_PAIR_ID, this.keyPairId);
                mo.put(KEY_MECHANISM, this.mechanism);
                mo.put(KEY_PUBLIC_KEY, this.publicKey.getEncoded());
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (that === this) return true;
            if (!(that instanceof RequestData)) return false;
            // Private keys are optional but must be considered.
            var privateKeysEqual =
                this.privateKey === that.privateKey ||
                (this.privateKey && that.privateKey &&
                    Arrays.equal(this.privateKey.getEncoded(), that.privateKey.getEncoded()));
            return equals.base.call(this, that) &&
                this.keyPairId == that.keyPairId &&
                this.mechanism == that.mechanism &&
                Arrays.equal(this.publicKey.getEncoded(), that.publicKey.getEncoded()) &&
                privateKeysEqual;
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            var encodedPublicKey = this.publicKey.getEncoded();
            var encodedPrivateKey = this.privateKey && this.privateKey.getEncoded();

            var key = uniqueKey.base.call(this) + ':' + this.keyPairId + ':' + this.mechanism + ':' + Arrays.hashCode(encodedPublicKey);
            if (encodedPrivateKey)
                key += ':' + Arrays.hashCode(encodedPrivateKey);
            return key;
        }
    });

    /**
     * Create a new asymmetric key wrapped key request data instance from
     * the provided MSL object. The private key will be unknown.
     *
     * @param {MslObject} keyRequestMo the MSL object.
     * @param {{result: function(RequestData), error: function(Error)}}
     *        callback the callback will receive the request data or any
     *        thrown exceptions.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if the encoded key is invalid or the
     *         specified mechanism is not supported.
     * @throws MslKeyExchangeException if the specified mechanism is not
     *         recognized.
     */
    var RequestData$parse = function RequestData$parse(keyRequestMo, callback) {
        AsyncExecutor(callback, function() {
            var keyPairId, mechanism, encodedKey;
            try {
                // Pull key request data.
                keyPairId = keyRequestMo.getString(KEY_KEY_PAIR_ID);
                mechanism = keyRequestMo.getString(KEY_MECHANISM);
                encodedKey = keyRequestMo.getBytes(KEY_PUBLIC_KEY);

                // Verify mechanism.
                if (!Mechanism[mechanism])
                    throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM, mechanism);
            } catch (e) {
                if (e instanceof MslEncoderException)
                    throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyRequestMo);
                throw e;
            }

            // Reconstruct public key.
            try {
                switch (mechanism) {
                    case Mechanism.RSA:
                    case Mechanism.JWE_RSA:
                    case Mechanism.JWEJS_RSA:
                    case Mechanism.JWK_RSA:
                    {
                        PublicKey.import(encodedKey, WebCryptoAlgorithm.RSA_OAEP, WebCryptoUsage.WRAP, KeyFormat.SPKI, {
                            result: function(publicKey) {
                                constructRequestData(keyPairId, mechanism, publicKey);
                            },
                            error: callback.error,
                        });
                        break;
                    }
                    case Mechanism.JWK_RSAES:
                    {
                        PublicKey.import(encodedKey, WebCryptoAlgorithm.RSAES, WebCryptoUsage.WRAP, KeyFormat.SPKI, {
                            result: function(publicKey) {
                                constructRequestData(keyPairId, mechanism, publicKey);
                            },
                            error: callback.error,
                        });
                        break;
                    }
                    /* Does not currently work.
                    case Mechanism.ECC:
                     */
                    default:
                        throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism);
                }
            } catch (e) {
                if (!(e instanceof MslException))
                    throw new MslCryptoException(MslError.INVALID_PUBLIC_KEY, "keydata " + keyRequestMo, e);
                throw e;
            }
        });

        function constructRequestData(keyPairId, mechanism, publicKey) {
            // Return the request data. There is no private key.
            var privateKey = null;
            callback.result(new RequestData(keyPairId, mechanism, publicKey, privateKey));
        }
    };

    /**
     * <p>Asymmetric key wrapped key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keypairid", "encryptionkey", "hmackey" ],
     *   "keypairid" : "string",
     *   "encryptionkey" : "binary",
     *   "hmackey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keypairid} identifies the key pair for wrapping and unwrapping the session keys</li>
     * <li>{@code encryptionkey} the wrapped session encryption key</li>
     * <li>{@code hmackey} the wrapped session HMAC key</li>
     * </ul></p>
     */
    var ResponseData = KeyResponseData.extend({
        /**
         * Create a new asymmetric key wrapped key response data instance with
         * the provided master token, specified key pair ID, and public
         * key-encrypted encryption and HMAC keys.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {string} keyPairId the public/private key pair ID.
         * @param {Uint8Array} encryptionKey the public key-encrypted encryption key.
         * @param {Uint8Array} hmacKey the public key-encrypted HMAC key.
         */
        init: function init(masterToken, keyPairId, encryptionKey, hmacKey) {
            init.base.call(this, masterToken, KeyExchangeScheme.ASYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyPairId: { value: keyPairId, writable: false, configurable: false },
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_KEY_PAIR_ID, this.keyPairId);
                mo.put(KEY_ENCRYPTION_KEY, this.encryptionKey);
                mo.put(KEY_HMAC_KEY, this.hmacKey);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof ResponseData)) return false;
            return equals.base.call(this, that) &&
                this.keyPairId == that.keyPairId &&
                Arrays.equal(this.encryptionKey, that.encryptionKey) &&
                Arrays.equal(this.hmacKey, that.hmacKey);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.keyPairId +
                ':' + Arrays.hashCode(this.encryptionKey) +
                ':' + Arrays.hashCode(this.hmacKey);
        },
    });

    /**
     * Create a new asymmetric key wrapped key response data instance with
     * the provided master token from the provided MSL object.
     *
     * @param {MasterToken} masterToken the master token.
     * @param {MslObject} keyDataMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if an encoded key is invalid.
     */
    var ResponseData$parse = function ResponseData$parse(masterToken, keyDataMo) {
        var keyPairId, encryptionKey, hmacKey;
        try {
            // Pull key response data.
            keyPairId = keyDataMo.getString(KEY_KEY_PAIR_ID);
            encryptionKey = keyDataMo.getBytes(KEY_ENCRYPTION_KEY);
            hmacKey = keyDataMo.getBytes(KEY_HMAC_KEY);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo);
            throw e;
        }

        // Return the response data.
        return new ResponseData(masterToken, keyPairId, encryptionKey, hmacKey);
    };

    /**
     * Create the crypto context identified by the key ID, mechanism, and
     * provided keys.
     *
     * @param {MslContext} ctx MSL context.
     * @param {string} keyPairId the key pair ID.
     * @param {Mechanism} mechanism the key mechanism.
     * @param {PrivateKey} privateKey the private key. May be null.
     * @param {PublicKey} publicKey the public key. May be null.
     * @return {ICryptoContext} the crypto context.
     * @throws MslCryptoException if the key mechanism is unsupported.
     */
    function createCryptoContext(ctx, keyPairId, mechanism, privateKey, publicKey) {
        switch (mechanism) {
            case Mechanism.JWE_RSA:
            case Mechanism.JWEJS_RSA:
                return new JsonWebEncryptionCryptoContext(ctx, JsonWebEncryptionCryptoContext.Algorithm.RSA_OAEP, JsonWebEncryptionCryptoContext.Encryption.A128GCM, privateKey, publicKey);
            case Mechanism.RSA:
            case Mechanism.JWK_RSA:
                return new RsaCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaCryptoContext.Mode.WRAP_UNWRAP_OAEP);
            case Mechanism.JWK_RSAES:
                return new RsaCryptoContext(ctx, keyPairId, privateKey, publicKey, RsaCryptoContext.Mode.WRAP_UNWRAP_PKCS1);
            default:
                throw new MslCryptoException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism);
        }
    }

    var AsymmetricWrappedExchange = module.exports = KeyExchangeFactory.extend({
        /**
         * Create a new asymmetric wrapped key exchange factory.
         * 
         * @param {AuthenticationUtils} authutils authentication utilities.
         */
        init: function init(authutils) {
            init.base.call(this, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            
            // The properties.
            var props = {
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
            AsyncExecutor(callback, function() {
                return ResponseData$parse(masterToken, keyDataMo);
            });
        },

        /** @inheritDoc */
        generateResponse: function generateResponse(ctx, format, keyRequestData, entityToken, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + keyRequestData + " was not created by this factory.");
                
                var masterToken, entityAuthData, identity;
                if (entityToken instanceof MasterToken) {
                    // If the master token was not issued by the local entity then we
                    // should not be generating a key response for it.
                    masterToken = entityToken;
                    if (!masterToken.isVerified())
                        throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, entityToken);
                    identity = masterToken.identity;
                    
                    // Verify the scheme is permitted.
                    if (!this.authutils.isSchemePermitted(identity, this.scheme))
                        throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ": " + this.scheme.name).setMasterToken(entityToken);
                } else {
                    entityAuthData = entityToken;
                    identity = entityAuthData.getIdentity();
                    
                    // Verify the scheme is permitted.
                    if (!this.authutils.isSchemePermitted(identity, this.scheme))
                        throw new MslKeyExchangeException(MslError.KEYX_INCORRECT_DATA, "Authentication scheme for entity not permitted " + identity + ": " + this.scheme.name).setEntityAuthenticationData(entityToken);
                }

                // Create random AES-128 encryption and SHA-256 HMAC keys.
                this.generateSessionKeys(ctx, {
                    result: function(sessionKeys) {
                        var encryptionKey = sessionKeys.encryptionKey;
                        var hmacKey = sessionKeys.hmacKey;
                        wrapKeys(masterToken, entityAuthData, encryptionKey, hmacKey);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException) {
                                e.setMasterToken(masterToken);
                                e.setEntityAuthenticationData(entityAuthData);
                            }
                            throw e;
                        }, self);
                    }
                });
            }, self);

            function wrapKeys(masterToken, entityAuthData, encryptionKey, hmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Wrap session keys with public key.
                    var encoder = ctx.getMslEncoderFactory();
                    var keyPairId = request.keyPairId;
                    var mechanism = request.mechanism;
                    var publicKey = request.publicKey;
                    var wrapCryptoContext = createCryptoContext(ctx, keyPairId, mechanism, null, publicKey);
                    wrapCryptoContext.wrap(encryptionKey, encoder, format, {
                        result: function(wrappedEncryptionKey) {
                            AsyncExecutor(callback, function() {
                                wrapCryptoContext.wrap(hmacKey, encoder, format, {
                                    result: function(wrappedHmacKey) {
                                        createMasterToken(masterToken, entityAuthData, encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey);
                                    },
                                    error: function(e) {
                                        AsyncExecutor(callback, function() {
                                            if (e instanceof MslException) {
                                                e.setMasterToken(masterToken);
                                                e.setEntityAuthenticationData(entityAuthData);
                                            }
                                            throw e;
                                        }, self);
                                    }
                                });
                            }, self);
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException)
                                    if (e instanceof MslException) {
                                        e.setMasterToken(masterToken);
                                        e.setEntityAuthenticationData(entityAuthData);
                                    }
                                throw e;
                            }, self);
                        }
                    });
                }, self);
            }

            function createMasterToken(masterToken, entityAuthData, encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Create the master token.
                    var tokenFactory = ctx.getTokenFactory();
                    if (entityToken instanceof MasterToken) {
                        tokenFactory.renewMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyPairId, wrappedEncryptionKey, wrappedHmacKey);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext, callback);
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException) {
                                        e.setMasterToken(masterToken);
                                        e.setEntityAuthenticationData(entityAuthData);
                                    }
                                    throw e;
                                }, self);
                            }
                        });
                    } else {
                        tokenFactory.createMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyPairId, wrappedEncryptionKey, wrappedHmacKey);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext, callback);
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException) {
                                        e.setMasterToken(masterToken);
                                        e.setEntityAuthenticationData(entityAuthData);
                                    }
                                    throw e;
                                }, self);
                            }
                        });
                    }
                }, self);
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
                var requestKeyPairId = request.keyPairId;
                var responseKeyPairId = response.keyPairId;
                if (requestKeyPairId != responseKeyPairId)
                    throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyPairId + "; response " + responseKeyPairId).setMasterToken(masterToken);

                // Unwrap session keys with identified key.
                var encoder = ctx.getMslEncoderFactory();
                var privateKey = request.privateKey;
                if (!privateKey)
                    throw new MslKeyExchangeException(MslError.KEYX_PRIVATE_KEY_MISSING, "request Asymmetric private key").setMasterToken(masterToken);
                var mechanism = request.mechanism;
                var unwrapCryptoContext = createCryptoContext(ctx, requestKeyPairId, mechanism, privateKey, null);
                unwrapCryptoContext.unwrap(response.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                    result: function(encryptionKey) {
                        unwrapCryptoContext.unwrap(response.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, encoder, {
                            result: function(hmacKey) {
                                ctx.getEntityAuthenticationData(null, {
                                    result: function(entityAuthData) {
                                        AsyncExecutor(callback, function() {
                                            // Create crypto context.
                                            var identity = entityAuthData.getIdentity();
                                            var responseMasterToken = response.masterToken;
                                            return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
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
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setMasterToken(masterToken);
                                    throw e;
                                }, self);
                            }
                        });
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
    module.exports.Mechanism = Mechanism;
    module.exports.RequestData = RequestData;
    module.exports.RequestData.parse = RequestData$parse;
    module.exports.ResponseData = ResponseData;
    module.exports.ResponseData.parse = ResponseData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('AsymmetricWrappedExchange'));
