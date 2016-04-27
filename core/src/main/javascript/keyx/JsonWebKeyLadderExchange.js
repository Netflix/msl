/**
 * Copyright (c) 2013-2015 Netflix, Inc.  All rights reserved.
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
 * <p>JSON Web Key ladder key exchange.</p>
 *
 * <p>The key ladder consists of a symmetric wrapping key used to protect the
 * session keys. The wrapping key is only permitted to wrap and unwrap data. It
 * cannot be used for encrypt/decrypt or sign/verify operations.</p>
 *
 * <p>The wrapping key is protected by wrapping it with a known common key
 * (e.g. preshared keys), a provided public key (e.g. client-generated RSA key
 * pair), or the previously used wrapping key. The previous wrapping key must
 * be provided by the requesting entity in the form found in the response
 * data.</p>
 *
 * <p>The wrapping key is always an AES-128 key for AES key wrap/unwrap.</p>
 *
 * <p>This key exchange scheme does not provide perfect forward secrecy and
 * should only be used if necessary to satisfy other security requirements.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var JsonWebKeyLadderExchange;
var JsonWebKeyLadderExchange$Mechanism;
var JsonWebKeyLadderExchange$RequestData;
var JsonWebKeyLadderExchange$RequestData$parse;
var JsonWebKeyLadderExchange$ResponseData;
var JsonWebKeyLadderExchange$ResponseData$parse;
var JsonWebKeyLadderExchange$AesKwJwkCryptoContext;

(function() {
    "use strict";

    /**
     * Wrapping key wrap mechanism.
     * @enum {string}
     */
    var Mechanism = JsonWebKeyLadderExchange$Mechanism = {
        /** Wrapping key wrapped by PSK (AES-128 key wrap). */
        PSK: "PSK",
        /** Wrapping key wrapped by previous wrapping key (AES-128 key wrap). */
        WRAP: "WRAP",
    };

    /**
     * JSON key wrap key wrapping mechanism.
     * @const
     * @type {string}
     */
    var KEY_MECHANISM = "mechanism";
    /**
     * JSON key wrap data.
     * @const
     * @type {string}
     */
    var KEY_WRAPDATA = "wrapdata";
    /**
     * JSON key wrapping key.
     * @const
     * @type {string}
     */
    var KEY_WRAP_KEY = "wrapkey";
    /**
     * JSON key encrypted encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * JSON key encrypted HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";

    /**
     * <p>JSON Web Key ladder key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "mechanism" ],
     *   "mechanism" : "enum(PSK|MGK|WRAP)",
     *   "wrapdata" : "base64",
     * }} where:
     * <ul>
     * <li>{@code mechanism} identifies the mechanism for wrapping and unwrapping the wrapping key</li>
     * <li>{@code wrapdata} the Base64-encoded wrapping data for the previous wrapping key</li>
     * </ul></p>
     */
    var RequestData = JsonWebKeyLadderExchange$RequestData = KeyRequestData.extend({
        /**
         * <p>Create a new JSON Web Key ladder key request data instance
         * with the specified mechanism and wrapping key data.</p>
         *
         * <p>Arguments not applicable to the specified mechanism are
         * ignored.</p>
         *
         * @param {Mechanism} mechanism the wrap key wrapping mechanism.
         * @param {?Uint8Array} wrapdata the wrap data for reconstructing the previous
         *        wrapping key. May be null if the mechanism does not use the
         *        previous wrapping key.
         * @throws MslInternalException if the mechanism requires wrap data and
         *         the required argument is null.
         */
        init: function init(mechanism, wrapdata) {
            init.base.call(this, KeyExchangeScheme.JWK_LADDER);

            switch (mechanism) {
                case Mechanism.WRAP:
                    if (!wrapdata)
                        throw new MslInternalException("Previous wrapping key based key exchange requires the previous wrapping key data and ID.");
                    break;
                default:
                    wrapdata = null;
                    break;
            }

            // The properties.
            var props = {
                mechanism: { value: mechanism, writable: false, configurable: false },
                wrapdata: { value: wrapdata, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata() {
            var keydata = {};
            keydata[KEY_MECHANISM] = this.mechanism;
            if (this.wrapdata) keydata[KEY_WRAPDATA] = base64$encode(this.wrapdata);
            return keydata;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (that === this) return true;
            if (!(that instanceof JsonWebKeyLadderExchange$RequestData)) return false;
            return equals.base.call(this, that) &&
                this.mechanism == that.mechanism &&
                Arrays$equal(this.wrapdata, that.wrapdata);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            var key = uniqueKey.base.call(this) + ':' + this.mechanism;
            if (this.wrapdata)
                key += ':' + Arrays$hashCode(this.wrapdata);
            return key;
        },
    });

    /**
     * Create a new JSON Web Key ladder key request data instance
     * from the provided JSON object.
     *
     * @param {object} keyRequestJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslCryptoException the wrapped key data cannot be verified
     *         or decrypted, or the specified mechanism is not supported.
     * @throws MslKeyExchangeException if the specified mechanism is not
     *         recognized.
     */
    var RequestData$parse = JsonWebKeyLadderExchange$RequestData$parse = function RequestData$parse(keyRequestJO) {
        // Pull key request data.
        var mechanism = keyRequestJO[KEY_MECHANISM];
        var wrapdataB64 = keyRequestJO[KEY_WRAPDATA];

        // Verify key request data.
        if (!mechanism ||
            (mechanism == Mechanism.WRAP && typeof wrapdataB64 !== 'string'))
        {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + JSON.stringify(keyRequestJO));
        }

        // Verify mechanism.
        if (!Mechanism[mechanism])
            throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_MECHANISM, mechanism);

        // Create the request data.
        var wrapdata;
        switch (mechanism) {
            case Mechanism.WRAP:
                try {
                    wrapdata = base64$decode(wrapdataB64);
                } catch (e) {
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, "keydata " + keyRequestJO.toString());
                }
                if (wrapdata == null || wrapdata.length == 0)
                    throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, "keydata " + keyRequestJO.toString());
                break;
            default:
                wrapdata = null;
                break;
        }
        return new RequestData(mechanism, wrapdata);
    };

    /**
     * <p>JSON Web Key ladder key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "wrapkey", "wrapdata", "encryptionkey", "hmackey" ],
     *   "wrapkey" : "base64",
     *   "wrapdata" : "base64",
     *   "encryptionkey" : "base64",
     *   "hmackey" : "base64",
     * }} where:
     * <ul>
     * <li>{@code wrapkey} the Base64-encoded new wrapping key in JWE format, wrapped by the wrapping key</li>
     * <li>{@code wrapdata} the Base64-encoded wrapping key data for use in subsequent key request data</li>
     * <li>{@code encryptionkey} the Base64-encoded session encryption key in JWE format, wrapped with the new wrapping key</li>
     * <li>{@code hmackey} the Base64-encoded session HMAC key in JWE format, wrapped with the new wrapping key</li>
     * </ul></p>
     */
    var ResponseData = JsonWebKeyLadderExchange$ResponseData = KeyResponseData.extend({
        /**
         * Create a new JSON Web Key ladder key response data instance
         * with the provided master token and wrapped keys.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {Uint8Array} wrapKey the wrapped wrap key.
         * @param {Uint8Array} wrapdata the wrap data for reconstructing the wrap key.
         * @param {Uint8Array} encryptionKey the wrap key wrapped encryption key.
         * @param {Uint8Array} hmacKey the wrap key wrapped HMAC key.
         */
        init: function init(masterToken, wrapKey, wrapdata, encryptionKey, hmacKey) {
            init.base.call(this, masterToken, KeyExchangeScheme.JWK_LADDER);

            // The properties.
            var props = {
                wrapKey: { value: wrapKey, writable: false, configurable: false },
                wrapdata: { value: wrapdata, writable: false, configurable: false },
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata() {
            var keydata = {};
            keydata[KEY_WRAP_KEY] = base64$encode(this.wrapKey);
            keydata[KEY_WRAPDATA] = base64$encode(this.wrapdata);
            keydata[KEY_ENCRYPTION_KEY] = base64$encode(this.encryptionKey);
            keydata[KEY_HMAC_KEY] = base64$encode(this.hmacKey);
            return keydata;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof JsonWebKeyLadderExchange$ResponseData)) return false;
            return equals.base.call(this, that) &&
                Arrays$equal(this.wrapKey, that.wrapKey) &&
                Arrays$equal(this.wrapdata, that.wrapdata) &&
                Arrays$equal(this.encryptionKey, that.encryptionKey) &&
                Arrays$equal(this.hmacKey, that.hmacKey);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            var key = uniqueKey.base.call(this) +
                ':' + Arrays$hashCode(this.wrapKey) +
                ':' + Arrays$hashCode(this.wrapdata) +
                ':' + Arrays$hashCode(this.encryptionKey) +
                ':' + Arrays$hashCode(this.hmacKey);
            return key;
        }
    });

    /**
     * Create a new JSON Web Key ladder key response data instance
     * with the provided master token from the provided JSON object.
     *
     * @param {MasterToken} masterToken the master token.
     * @param {object} keyDataJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslKeyExchangeException if the mechanism is not recognized.
     */
    var ResponseData$parse = JsonWebKeyLadderExchange$ResponseData$parse = function JsonWebKeyLadderExchange$ResponseData$parse(masterToken, keyDataJO) {
        // Pull key response data.
        var wrapKeyB64 = keyDataJO[KEY_WRAP_KEY];
        var wrapdataB64 = keyDataJO[KEY_WRAPDATA];
        var encryptionKeyB64 = keyDataJO[KEY_ENCRYPTION_KEY];
        var hmacKeyB64 = keyDataJO[KEY_HMAC_KEY];

        // Verify key response data.
        if (typeof wrapKeyB64 !== 'string' ||
            typeof wrapdataB64 !== 'string' ||
            typeof encryptionKeyB64 !== 'string' ||
            typeof hmacKeyB64 !== 'string')
        {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "keydata " + JSON.stringify(keyDataJO));
        }

        // Decode keys.
        var wrapKey, wrapdata, encryptionKey, hmacKey;
        try {
            wrapKey = base64$decode(wrapKeyB64);
            wrapdata = base64$decode(wrapdataB64);
        } catch (e) {
            throw new MslCryptoException(MslError.INVALID_SYMMETRIC_KEY, "keydata " + JSON.stringify(keyDataJO), e);
        }
        try {
            encryptionKey = base64$decode(encryptionKeyB64);
        } catch (e) {
            throw new MslCryptoException(MslError.INVALID_ENCRYPTION_KEY, "keydata " + JSON.stringify(keyDataJO), e);
        }
        try {
            hmacKey = base64$decode(hmacKeyB64);
        } catch (e) {
            throw new MslCryptoException(MslError.INVALID_HMAC_KEY, "keydata " + JSON.stringify(keyDataJO), e);
        }

        // Return the response data.
        return new ResponseData(masterToken, wrapKey, wrapdata, encryptionKey, hmacKey);
    };
    
    /**
     * AES key wrap JSON web key crypto context.
     */
    var AesKwJwkCryptoContext = JsonWebKeyLadderExchange$AesKwJwkCryptoContext = ICryptoContext.extend({
        /**
         * Create an AES key wrap JSON web key crypto context with the provided
         * key.
         * 
         * @param {CipherKey} wrapKey AES secret key.
         */
        init: function(wrapKey) {
            // Extract actual wrapping key.
            if (wrapKey)
                wrapKey = wrapKey.rawKey;
            
            // Define properties.
            var props = {
                _wrapKey: { value: wrapKey, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /** @inheritDoc */
        encrypt: function encrypt(data, callback) {
            callback.error(new MslCryptoException(MslError.ENCRYPT_NOT_SUPPORTED));
        },

        /** @inheritDoc */
        decrypt: function decrypt(data, callback) {
            callback.error(new MslCryptoException(MslError.DECRYPT_NOT_SUPPORTED));
        },
        
        /** @inheritDoc */
        wrap: function wrap(key, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    callback.result(new Uint8Array(result));
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.WRAP_ERROR));
                };
                mslCrypto['wrapKey']('jwk', key.rawKey, this._wrapKey, WebCryptoAlgorithm.A128KW)
                    .then(oncomplete, onerror);
            }, this);
        },
        
        /** @inheritDoc */
        unwrap: function unwrap(data, algo, usages, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    constructKey(result);
                };
                var onerror = function(e) {
                    callback.error(new MslCryptoException(MslError.UNWRAP_ERROR));
                };
                mslCrypto['unwrapKey']('jwk', data, this._wrapKey, WebCryptoAlgorithm.A128KW, algo, false, usages)
                    .then(oncomplete, onerror);
            }, this);

            function constructKey(rawKey) {
                AsyncExecutor(callback, function() {
                    switch (rawKey["type"]) {
                        case "secret":
                            CipherKey$create(rawKey, callback);
                            break;
                        case "public":
                            PublicKey$create(rawKey, callback);
                            break;
                        case "private":
                            PrivateKey$create(rawKey, callback);
                            break;
                        default:
                            throw new MslCryptoException(MslError.UNSUPPORTED_KEY, "type: " + rawKey["type"]);
                    }
                });
            }
        },

        /** @inheritDoc */
        sign: function sign(data, callback) {
            callback.error(new MslCryptoException(MslError.SIGN_NOT_SUPPORTED));
        },

        /** @inheritDoc */
        verify: function verify(data, signature, callback) {
            callback.error(new MslCryptoException(MslError.VERIFY_NOT_SUPPORTED));
        },
    });

    /**
     * Create the crypto context identified by the mechanism.
     *
     * @param {MslContext} ctx MSL context.
     * @param {Mechanism} mechanism the wrap key wrapping mechanism.
     * @param {Uint8Array} wrapdata the wrap key previous wrapping key data. May be null.
     * @param {string} identity the entity identity.
     * @param {result: function(ICryptoContext), error: function(Error)}
     *        callback the callback that will receive the crypto context or any
     *        thrown exceptions.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslKeyExchangeException if the mechanism is unsupported.
     * @throws MslEntityAuthException if there is a problem with the entity
     *         identity.
     */
    function createCryptoContext(ctx, mechanism, wrapdata, identity, callback) {
        AsyncExecutor(callback, function() {
            switch (mechanism) {
                // FIXME: For PSK/MGK we need some way to get an ICryptoContext
                // that might run remotely. In other words, some other CryptoContext. Maybe
                // the WrapCryptoContextRepository can be used for that.
                case Mechanism.PSK:
                {
                    var authdata = new PresharedAuthenticationData(identity);
                    var factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                    if (!factory)
                        throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism);
                    var cryptoContext = factory.getCryptoContext(ctx, authdata);
                    // FIXME: Get a handle to KPW.
                    var kpw = undefined;
                    return new AesKwJwkCryptoContext(kpw);
                }
                case Mechanism.WRAP:
                {
                    var cryptoContext = ctx.getMslCryptoContext();
                    cryptoContext.unwrap(wrapdata, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                        result: function(wrapKey) {
                            AsyncExecutor(callback, function() {
                                return new AesKwJwkCryptoContext(wrapKey);
                            });
                        },
                        error: callback.error,
                    });
                    return;
                }
                default:
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism);
            }
        });
    }

    JsonWebKeyLadderExchange = KeyExchangeFactory.extend({
        /**
         * Create a new JSON Web Key ladder key exchange factory.
         *
         * @param {WrapCryptoContextRepository} repository the wrapping key crypto context repository.
         * @param {AuthenticationUtils} authutils authentication utilities.
         */
        init: function init(repository, authutils) {
            init.base.call(this, KeyExchangeScheme.JWK_LADDER);

            // The properties.
            var props = {
                repository: { value: repository, writable: false, enumerable: false, configurable: false },
                authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        createRequestData: function createRequestData(ctx, keyRequestJO, callback) {
            AsyncExecutor(callback, function() {
                return RequestData$parse(keyRequestJO);
            });
        },

        /** @inheritDoc */
        createResponseData: function createResponseData(ctx, masterToken, keyDataJO) {
            return ResponseData$parse(masterToken, keyDataJO);
        },

        /** @inheritDoc */
        generateResponse: function generateResponse(ctx, keyRequestData, entityToken, callback) {
            var self = this;

            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + JSON.stringify(keyRequestData) + " was not created by this factory.");

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

                // Create random AES-128 wrapping key.
                var wrapBytes = new Uint8Array(16);
                ctx.getRandom().nextBytes(wrapBytes);
                CipherKey$import(wrapBytes, WebCryptoAlgorithm.A128KW, WebCryptoUsage.WRAP_UNWRAP, {
                    result: function(wrapKey) {
                        AsyncExecutor(callback, function() {
                            var mslCryptoContext = ctx.getMslCryptoContext();
                            mslCryptoContext.wrap(wrapKey, {
                                result: function(wrapdata) {
                                    createSessionKeys(masterToken, entityAuthData, identity, wrapKey, wrapdata);
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
                            throw new MslCryptoException(MslError.WRAP_KEY_CREATION_FAILURE, null, e).setMasterToken(entityToken);
                        }, self);
                    }
                });
            }, self);

            function createSessionKeys(masterToken, entityAuthData, identity, wrapKey, wrapdata) {
                self.generateSessionKeys(ctx, {
                    result: function(sessionKeys) {
                        AsyncExecutor(callback, function() {
                            var encryptionKey = sessionKeys.encryptionKey;
                            var hmacKey = sessionKeys.hmacKey;
                            wrapWrappingKey(masterToken, entityAuthData, identity, wrapKey, wrapdata, encryptionKey, hmacKey);
                        }, self);
                    },
                    error: function(e) {
                        AsyncExecutor(callback, function() {
                            if (e instanceof MslException) {
                                e.setMasterToken(masterToken);
                                e.setEntityAuthenticationData(entityAuthData);
                            }
                            throw e;
                        });
                    }
                });
            }

            function wrapWrappingKey(masterToken, entityAuthData, identity, wrapKey, wrapdata, encryptionKey, hmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Grab the request data.
                    var mechanism = request.mechanism;
                    var prevWrapdata = request.wrapdata;

                    // Wrap wrapping key using specified wrapping key.
                    createCryptoContext(ctx, mechanism, prevWrapdata, identity, {
                        result: function (wrapKeyCryptoContext) {
                            wrapKeyCryptoContext.wrap(wrapKey, {
                                result: function(wrappedWrapJwk) {
                                    wrapSessionKeys(wrapKey, wrapdata, encryptionKey, hmacKey, wrappedWrapJwk);
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException) {
                                            e.setMasterToken(masterToken);
                                            e.setEntityAuthenticationData(entityAuthData);
                                        }
                                        throw e;
                                    });
                                }
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException) {
                                    e.setMasterToken(masterToken);
                                    e.setEntityAuthenticationData(entityAuthData);
                                }
                                throw e;
                            });
                        }
                    });
                }, self);
            }

            function wrapSessionKeys(masterToken, entityAuthData, wrapKey, wrapdata, encryptionKey, hmacKey, wrappedWrapJwk) {
                AsyncExecutor(callback, function() {
                    var wrapCryptoContext = new AesKwJwkCryptoContext(wrapKey);
                    wrapCryptoContext.wrap(encryptionKey, {
                        result: function(wrappedEncryptionJwk) {
                            wrapCryptoContext.wrap(hmacKey, {
                                result: function(wrappedHmacJwk) {
                                    createMasterToken(wrapdata, wrappedWrapJwk, encryptionKey, wrappedEncryptionJwk, hmacKey, wrappedHmacJwk);
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException) {
                                            e.setMasterToken(masterToken);
                                            e.setEntityAuthenticationData(entityAuthData);
                                        }
                                        throw e;
                                    });
                                }
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException) {
                                    e.setMasterToken(masterToken);
                                    e.setEntityAuthenticationData(entityAuthData);
                                }
                                throw e;
                            });
                        }
                    });
                }, self);
            }

            function createMasterToken(wrapdata, wrappedWrapJwk, encryptionKey, wrappedEncryptionJwk, hmacKey, wrappedHmacJwk) {
                AsyncExecutor(callback, function() {
                    // Create the master token.
                    var tokenFactory = ctx.getTokenFactory();
                    if (entityToken instanceof MasterToken) {
                        tokenFactory.renewMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create session crypto context.
                                    var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, wrappedWrapJwk, wrapdata, wrappedEncryptionJwk, wrappedHmacJwk);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext, callback);
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setMasterToken(entityToken);
                                    throw e;
                                });
                            }
                        });
                    } else {
                        tokenFactory.createMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create session crypto context.
                                    var cryptoContext = new SessionCryptoContext(ctx, masterToken);

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, wrappedWrapJwk, wrapdata, wrappedEncryptionJwk, wrappedHmacJwk);
                                    return new KeyExchangeFactory.KeyExchangeData(keyResponseData, cryptoContext, callback);
                                }, self);
                            },
                            error: function(e) {
                                AsyncExecutor(callback, function() {
                                    if (e instanceof MslException)
                                        e.setEntityAuthenticationData(entityToken);
                                    throw e;
                                });
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
                    throw new MslInternalException("Key request data " + JSON.stringify(keyRequestData) + " was not created by this factory.");
                var request = keyRequestData;
                if (!(keyResponseData instanceof ResponseData))
                    throw new MslInternalException("Key response data " + JSON.stringify(keyResponseData) + " was not created by this factory.");
                var response = keyResponseData;

                // Unwrap new wrapping key.
                var mechanism = request.mechanism;
                var requestWrapdata = request.wrapdata;
                ctx.getEntityAuthenticationData(null, {
                    result: function(entityAuthData) {
                        AsyncExecutor(callback, function() {
                            var identity = entityAuthData.getIdentity();
                            var wrapKeyCryptoContext;
                            switch (mechanism) {
                                case Mechanism.PSK:
                                {
                                    var authdata = new PresharedAuthenticationData(identity);
                                    var factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                                    if (!factory)
                                        throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism).setEntityAuthenticationData(entityAuthData);
                                    var cryptoContext = factory.getCryptoContext(ctx, authdata);
                                    // FIXME: Get a handle to KPW.
                                    var kpw = undefined;
                                    wrapKeyCryptoContext = new AesKwJwkCryptoContext(kpw);
                                    break;
                                }
                                case Mechanism.WRAP:
                                {
                                    wrapKeyCryptoContext = this.repository.getCryptoContext(requestWrapdata);
                                    if (!wrapKeyCryptoContext)
                                        throw new MslKeyExchangeException(MslError.KEYX_WRAPPING_KEY_MISSING, base64$encode(requestWrapdata)).setEntityAuthenticationData(entityAuthData);
                                    break;
                                }
                                default:
                                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_MECHANISM, mechanism).setEntityAuthenticationData(entityAuthData);
                            }

                            // Unwrap wrapping key.
                            wrapKeyCryptoContext.unwrap(response.wrapKey, WebCryptoAlgorithm.A128KW, WebCryptoAlgorithm.WRAP_UNWRAP, {
                                result: function(wrapKey) {
                                    unwrapSessionKeys(entityAuthData, response, requestWrapdata, identity, wrapKey);
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException)
                                            e.setEntityAuthenticationData(entityAuthData);
                                        throw e;
                                    });
                                }
                            });
                        }, self);
                    },
                    error: callback.error
                });
            }, self);

            function unwrapSessionKeys(entityAuthData, response, requestWrapdata, identity, wrapKey) {
                AsyncExecutor(callback, function() {
                    var unwrapCryptoContext = new AesKwJwkCryptoContext(wrapKey);
                    unwrapCryptoContext.unwrap(response.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoAlgorithm.ENCRYPT_DECRYPT, {
                        result: function(encryptionKey) {
                            unwrapCryptoContext.unwrap(response.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoAlgorithm.SIGN_VERIFY, {
                                result: function(hmacKey) {
                                    AsyncExecutor(callback, function() {
                                        // Deliver wrap data to wrap key repository.
                                        var wrapdata = response.wrapdata;
                                        this.repository.addCryptoContext(wrapdata, unwrapCryptoContext);
                                        this.repository.removeCryptoContext(requestWrapdata);

                                        // Create crypto context.
                                        var responseMasterToken = response.masterToken;
                                        return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
                                    }, self);
                                },
                                error: function(e) {
                                    AsyncExecutor(callback, function() {
                                        if (e instanceof MslException)
                                            e.setEntityAuthenticationData(entityAuthData);
                                        throw e;
                                    });
                                }
                            });
                        },
                        error: function(e) {
                            AsyncExecutor(callback, function() {
                                if (e instanceof MslException)
                                    e.setEntityAuthenticationData(entityAuthData);
                                throw e;
                            });
                        }
                    });
                }, self);
            }
        }
    });
})();
