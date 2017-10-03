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
 * <p>Symmetric key wrapped key exchange.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
(function(require, module) {
	"use strict";
	
	var KeyRequestData = require('../keyx/KeyRequestData.js');
	var KeyExchangeScheme = require('../keyx/KeyExchangeScheme.js');
	var KeyExchangeFactory = require('../keyx/KeyExchangeFactory.js');
	var AsyncExecutor = require('../util/AsyncExecutor.js');
	var MslKeyExchangeException = require('../MslKeyExchangeException.js');
	var MslError = require('../MslError.js');
	var MslEncoderException = require('../io/MslEncoderException.js');
	var MslEncodingException = require('../MslEncodingException.js');
	var KeyResponseData = require('../keyx/KeyResponseData.js');
	var Arrays = require('../util/Arrays.js');
	var MasterToken = require('../tokens/MasterToken.js');
	var MslMasterTokenException = require('../MslMasterTokenException.js');
	var SessionCryptoContext = require('../crypto/SessionCryptoContext.js');
	var PresharedAuthenticationData = require('../entityauth/PresharedAuthenticationData.js');
	var EntityAuthenticationScheme = require('../entityauth/EntityAuthenticationScheme.js');
	var MslInternalException = require('../MslInternalException.js');
	var MslException = require('../MslException.js');
	var WebCryptoAlgorithm = require('../crypto/WebCryptoAlgorithm.js');
	var WebCryptoUsage = require('../crypto/WebCryptoUsage.js');
	
    /**
     * Key ID.
     * @enum {string}
     */
    var KeyId = {
        PSK: "PSK",
        SESSION: "SESSION",
    };

    /**
     * Key symmetric key ID.
     * @const
     * @type {string}
     */
    var KEY_KEY_ID = "keyid";
    /**
     * Key wrapped encryption key.
     * @const
     * @type {string}
     */
    var KEY_ENCRYPTION_KEY = "encryptionkey";
    /**
     * Key wrapped HMAC key.
     * @const
     * @type {string}
     */
    var KEY_HMAC_KEY = "hmackey";

    /**
     * <p>Symmetric key wrapped key request data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid" ],
     *   "keyid" : "string"
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that should be used to wrap the session keys</li>
     * </ul></p>
     */
    var RequestData = KeyRequestData.extend({
        /**
         * Create a new symmetric key wrapped key request data instance with
         * the specified key ID.
         *
         * @param {KeyId} keyId symmetric key identifier.
         */
        init: function init(keyId) {
            init.base.call(this, KeyExchangeScheme.SYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyId: { value: keyId, writable: false, configurable: false }
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_KEY_ID, this.keyId);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof RequestData)) return false;
            return equals.base.call(this, that) && this.keyId == that.keyId;
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.keyId;
        },
    });

    /**
     * Create a new symmetric key wrapped key request data instance from
     * the provided MSL object.
     *
     * @param {MslObject} keyDataMo the MSL object.
     * @return {RequestData} the request data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslKeyExchangeException if the key ID is not recognized.
     */
    var RequestData$parse = function RequestData$parse(keyDataMo) {
        try {
            var keyId = keyDataMo.getString(KEY_KEY_ID);
            if (!KeyId[keyId])
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyId);
            return new RequestData(keyId);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
            throw e;
        }
    };

    /**
     * <p>Symmetric key wrapped key response data.</p>
     *
     * <p>
     * {@code {
     *   "#mandatory" : [ "keyid", "encryptionkey", "hmackey" ],
     *   "keyid" : "string",
     *   "encryptionkey" : "binary",
     *   "hmackey" : "binary"
     * }} where:
     * <ul>
     * <li>{@code keyid} identifies the key that was used to wrap the session keys</li>
     * <li>{@code encryptionkey} the wrapped session encryption key</li>
     * <li>{@code hmackey} the wrapped session HMAC key</li>
     * </ul></p>
     */
    var ResponseData = KeyResponseData.extend({
        /**
         * Create a new symmetric key wrapped key response data instance with
         * the provided master token, specified key ID and wrapped encryption
         * and HMAC keys.
         *
         * @param {MasterToken} masterToken the master token.
         * @param {KeyId} keyId the wrapping key ID.
         * @param {Uint8Array} encryptionKey the wrapped encryption key.
         * @param {Uint8Array} hmacKey the wrapped HMAC key.
         */
        init: function init(masterToken, keyId, encryptionKey, hmacKey) {
            init.base.call(this, masterToken, KeyExchangeScheme.SYMMETRIC_WRAPPED);

            // The properties.
            var props = {
                keyId: { value: keyId, writable: false, configurable: false },
                encryptionKey: { value: encryptionKey, writable: false, configurable: false },
                hmacKey: { value: hmacKey, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        getKeydata: function getKeydata(encoder, format, callback) {
            AsyncExecutor(callback, function() {
                var mo = encoder.createObject();
                mo.put(KEY_KEY_ID, this.keyId);
                mo.put(KEY_ENCRYPTION_KEY, this.encryptionKey);
                mo.put(KEY_HMAC_KEY, this.hmacKey);
                return mo;
            }, this);
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof ResponseData)) return false;
            return equals.base.call(this, that) && this.keyId == that.keyId &&
                Arrays.equal(this.encryptionKey, that.encryptionKey) &&
                Arrays.equal(this.hmacKey, that.hmacKey);
        },

        /** @inheritDoc */
        uniqueKey: function uniqueKey() {
            return uniqueKey.base.call(this) + ':' + this.keyId +
                ':' + Arrays.hashCode(this.encryptionKey) +
                ':' + Arrays.hashCode(this.hmacKey);
        },
    });

    /**
     * Create a new symmetric key wrapped key response data instance with
     * the provided master token from the provided MSL object.
     *
     * @param {MasterToken} masterToken the master token.
     * @param {MslObject} keyDataMo the MSL object.
     * @return {ResponseData} the response data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if an encoded key is invalid.
     * @throws MslKeyExchangeException if the key ID is not recognized.
     */
    var ResponseData$parse = function ResponseData$parse(masterToken, keyDataMo) {
        try {
            var keyId = keyDataMo.getString(KEY_KEY_ID);
            if (!KeyId[keyId])
                throw new MslKeyExchangeException(MslError.UNIDENTIFIED_KEYX_KEY_ID, keyId);
            var encryptionKey = keyDataMo.getBytes(KEY_ENCRYPTION_KEY);
            var hmacKey = keyDataMo.getBytes(KEY_HMAC_KEY);
            return new ResponseData(masterToken, keyId, encryptionKey, hmacKey);
        } catch (e) {
            if (e instanceof MslEncoderException)
                throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "keydata " + keyDataMo, e);
            throw e;
        }
    };

    /**
     * Create the crypto context identified by the key ID.
     *
     * @param {MslContext} ctx MSL context.
     * @param {KeyId} keyId the key ID.
     * @param {?MasterToken} the existing master token, which may be null.
     * @param {?string} the entity identity.
     * @param {{result: function(ICryptoContext}, error: function(Error)}}
     *        callback the callback that will receive the crypto context or any
     *        thrown exceptions.
     * @throws MslCryptoException if the crypto context cannot be created.
     * @throws MslMasterTokenException if the master token is not trusted.
     * @throws MslKeyExchangeException if the key ID is unsupported or a
     *         master token is required.
     * @throws MslEntityAuthException if there is an problem with the master
     *         token identity.
     */
    function createCryptoContext(ctx, keyId, masterToken, identity, callback) {
        AsyncExecutor(callback, function() {
            switch (keyId) {
            case KeyId.SESSION:
            {
                // If the master token is null session wrapped is unsupported.
                if (!masterToken)
                    throw new MslKeyExchangeException(MslError.KEYX_MASTER_TOKEN_MISSING, keyId);

                // Use a stored master token crypto context if we have one.
                var cachedCryptoContext = ctx.getMslStore().getCryptoContext(masterToken);
                if (cachedCryptoContext)
                    return cachedCryptoContext;

                // If there was no stored crypto context try making one from
                // the master token. We can only do this if we can open up the
                // master token.
                if (!masterToken.isDecrypted())
                    throw new MslMasterTokenException(MslError.MASTERTOKEN_UNTRUSTED, masterToken);
                var cryptoContext = new SessionCryptoContext(ctx, masterToken);
                return cryptoContext;
            }
            case KeyId.PSK:
            {
                var authdata = new PresharedAuthenticationData(identity);
                var factory = ctx.getEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
                if (!factory)
                    throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId);
                return factory.getCryptoContext(ctx, authdata);
            }
            default:
                throw new MslKeyExchangeException(MslError.UNSUPPORTED_KEYX_KEY_ID, keyId);
            }
        });
    }

    var SymmetricWrappedExchange = module.exports = KeyExchangeFactory.extend({
        /**
         * Create a new symmetric wrapped key exchange factory.
         * 
         * @param {AuthenticationUtils} authutils authentication utilities.
         */
        init: function init(authutils) {
            init.base.call(this, KeyExchangeScheme.SYMMETRIC_WRAPPED);
            
            // The properties.
            var props = {
                authutils: { value: authutils, writable: false, enumerable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },

        /** @inheritDoc */
        createRequestData: function createRequestData(ctx, keyRequestMo, callback) {
            AsyncExecutor(callback, function() {
                return RequestData$parse(keyRequestMo);
            });
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
                    result: function(sessionkeys) {
                        var encryptionKey = sessionkeys.encryptionKey;
                        var hmacKey = sessionkeys.hmacKey;
                        wrapKeys(masterToken, entityAuthData, identity, encryptionKey, hmacKey);
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

            function wrapKeys(masterToken, entityAuthData, identity, encryptionKey, hmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Wrap session keys with identified key.
                    var keyId = request.keyId;
                    var encoder = ctx.getMslEncoderFactory();
                    createCryptoContext(ctx, keyId, masterToken, identity, {
                        result: function(wrapCryptoContext) {
                            wrapCryptoContext.wrap(encryptionKey, encoder, format, {
                                result: function(wrappedEncryptionKey) {
                                    wrapCryptoContext.wrap(hmacKey, encoder, format, {
                                        result: function(wrappedHmacKey) {
                                            createMasterToken(encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey);
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
            }

            function createMasterToken(encryptionKey, wrappedEncryptionKey, hmacKey, wrappedHmacKey) {
                AsyncExecutor(callback, function() {
                    var request = keyRequestData;

                    // Create the master token.
                    var tokenFactory = ctx.getTokenFactory();
                    if (entityToken instanceof MasterToken) {
                        tokenFactory.renewMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext;
                                    try {
                                        cryptoContext = new SessionCryptoContext(ctx, masterToken);
                                    } catch (e) {
                                        if (e instanceof MslMasterTokenException)
                                            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
                                        if (e instanceof MslException)
                                            e.setMasterToken(entityToken);
                                        throw e;
                                    }

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyId, wrappedEncryptionKey, wrappedHmacKey);
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
                        tokenFactory.createMasterToken(ctx, entityToken, encryptionKey, hmacKey, null, {
                            result: function(masterToken) {
                                AsyncExecutor(callback, function() {
                                    // Create crypto context.
                                    var cryptoContext;
                                    try {
                                        cryptoContext = new SessionCryptoContext(ctx, masterToken);
                                    } catch (e) {
                                        if (e instanceof MslMasterTokenException)
                                            throw new MslInternalException("Master token constructed by token factory is not trusted.", e);
                                        throw e;
                                    }

                                    // Return the key exchange data.
                                    var keyResponseData = new ResponseData(masterToken, request.keyId, wrappedEncryptionKey, wrappedHmacKey);
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
            }
        },

        /** @inheritDoc */
        getCryptoContext: function getCryptoContext(ctx, keyRequestData, keyResponseData, masterToken, callback) {
            var self = this;
            var entityAuthData;

            AsyncExecutor(callback, function() {
                if (!(keyRequestData instanceof RequestData))
                    throw new MslInternalException("Key request data " + keyRequestData + " was not created by this factory.");
                var request = keyRequestData;
                if (!(keyResponseData instanceof ResponseData))
                    throw new MslInternalException("Key response data " + keyResponseData + " was not created by this factory.");
                var response = keyResponseData;

                // Verify response matches request.
                var requestKeyId = request.keyId;
                var responseKeyId = response.keyId;
                if (requestKeyId != responseKeyId)
                    throw new MslKeyExchangeException(MslError.KEYX_RESPONSE_REQUEST_MISMATCH, "request " + requestKeyId + "; response " + responseKeyId).setMasterToken(masterToken);

                // Unwrap session keys with identified key.
                ctx.getEntityAuthenticationData(null, {
                    result: function(ead) {
                        AsyncExecutor(callback, function() {
                            entityAuthData = ead;
                            var identity = entityAuthData.getIdentity();
                            var encoder = ctx.getMslEncoderFactory();
                            createCryptoContext(ctx, responseKeyId, masterToken, identity, {
                                result: function(unwrapCryptoContext) {
                                    unwrapCryptoContext.unwrap(response.encryptionKey, WebCryptoAlgorithm.AES_CBC, WebCryptoUsage.ENCRYPT_DECRYPT, encoder, {
                                        result: function(encryptionKey) {
                                            unwrapCryptoContext.unwrap(response.hmacKey, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, encoder, {
                                                result: function(hmacKey) {
                                                    // Create crypto context.
                                                    ctx.getEntityAuthenticationData(null, {
                                                        result: function(entityAuthData) {
                                                            AsyncExecutor(callback, function() {
                                                                var identity = entityAuthData.getIdentity();
                                                                var responseMasterToken = response.masterToken;
                                                                return new SessionCryptoContext(ctx, responseMasterToken, identity, encryptionKey, hmacKey);
                                                            }, self);
                                                        },
                                                        error: handleError,
                                                    });
                                                },
                                                error: handleError,
                                            });
                                        },
                                        error: handleError,
                                    });
                                },
                                error: handleError,
                            });
                        }, self);
                    },
                    error: handleError,
                });
            }, self);
            
            function handleError(e) {
                AsyncExecutor(callback, function() {
                    if (e instanceof MslException) {
                        e.setMasterToken(masterToken);
                        e.setEntityAuthenticationData(entityAuthData);
                    }
                    throw e;
                }, self);
            }
        },
    });
    
    // Exports.
    module.exports.KeyId = KeyId;
    module.exports.RequestData = RequestData;
    module.exports.RequestData.parse = RequestData$parse;
    module.exports.ResponseData = ResponseData;
    module.exports.ResponseData.parse = ResponseData$parse;
})(require, (typeof module !== 'undefined') ? module : mkmodule('SymmetricWrappedExchange'));
